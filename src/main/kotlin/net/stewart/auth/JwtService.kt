package net.stewart.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import org.jdbi.v3.core.Handle
import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource

/**
 * Result of a JWT access + refresh token pair creation.
 */
data class TokenPair(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Int // seconds
)

sealed class RefreshResult {
    data class Success(val tokenPair: TokenPair) : RefreshResult()
    data object InvalidToken : RefreshResult()
    data object FamilyRevoked : RefreshResult()
}

/**
 * JWT authentication service with refresh token rotation and family-based revocation.
 *
 * Uses HMAC-SHA256 with an auto-generated signing key stored in a `config` table.
 * Supports dual-key validation for seamless key rotation.
 *
 * Refresh tokens rotate on every use. A rotated token presented again within a short
 * grace window (to tolerate client retries and racing requests) yields the *same*
 * successor that was already issued — never a new one — provided that successor has
 * not itself been used or revoked. Any other reuse revokes the whole token family.
 *
 * @param dataSource JDBC DataSource
 * @param userRepository User lookup
 * @param issuer JWT issuer claim (default: "auth-toolkit")
 * @param audience JWT audience claim (default: "api")
 * @param accessTokenSeconds Access token lifetime (default: 900 = 15 minutes)
 * @param refreshTokenDays Refresh token lifetime (default: 30 days)
 * @param configTableName Table for signing key storage (default: "auth_config")
 * @param maxRefreshTokensPerUser Cap on active refresh tokens per user (default: 10)
 * @param clock Time source (injectable for tests)
 */
class JwtService(
    private val dataSource: DataSource,
    private val userRepository: UserRepository,
    private val issuer: String = "auth-toolkit",
    private val audience: String = "api",
    private val accessTokenSeconds: Int = 900,
    private val refreshTokenDays: Long = 30L,
    private val configTableName: String = "auth_config",
    private val maxRefreshTokensPerUser: Int = 10,
    private val clock: Clock = Clock.systemDefaultZone(),
) {
    private val log = LoggerFactory.getLogger(JwtService::class.java)
    private val jdbi = Jdbi.create(dataSource)
    private val gracePeriod: Duration = Duration.ofSeconds(60)

    /** Creates a new access + refresh token pair. */
    fun createTokenPair(user: AuthUser, deviceName: String): TokenPair {
        val accessToken = createAccessToken(user)
        val refreshToken = SessionService.generateSecureToken()
        enforceTokenCap(user.id)
        jdbi.useHandle<Exception> { handle ->
            insertRefreshToken(handle, user.id, refreshToken, deviceName, SessionService.generateSecureToken())
        }
        return TokenPair(accessToken, refreshToken, accessTokenSeconds)
    }

    /** Validates a JWT access token. Returns the authenticated user or null. */
    fun validateAccessToken(token: String): AuthUser? {
        val decoded = verifyToken(token) ?: return null
        if (decoded.getClaim("type").asString() != "access") return null
        val userId = decoded.subject?.toLongOrNull() ?: return null
        return userRepository.findById(userId)
    }

    private data class TokenLookup(
        val id: Long, val userId: Long, val familyId: String, val deviceName: String,
        val expiresAt: LocalDateTime, val revoked: Boolean,
        val replacedByHash: String?, val replacedAt: LocalDateTime?
    )

    /**
     * Refreshes a token pair with rotation and family-based theft detection.
     *
     * The successor refresh token is derived deterministically from the presented token
     * (HMAC under the signing key), so a retry within the grace window can return the
     * exact successor that was already issued without storing raw tokens.
     */
    fun refresh(rawRefreshToken: String): RefreshResult {
        val tokenHash = hashToken(rawRefreshToken)
        var rt = lookup(tokenHash) ?: return RefreshResult.InvalidToken
        val now = LocalDateTime.now(clock)
        if (rt.revoked || rt.expiresAt.isBefore(now)) return RefreshResult.InvalidToken
        val user = userRepository.findById(rt.userId) ?: return RefreshResult.InvalidToken

        val successor = deriveSuccessor(rawRefreshToken)
        val successorHash = hashToken(successor)

        if (rt.replacedAt == null) {
            enforceTokenCap(user.id)
            val claimed = jdbi.inTransaction<Boolean, Exception> { handle ->
                // Conditional claim: only one concurrent caller can rotate this token.
                val updated = handle.createUpdate(
                    """UPDATE refresh_token SET replaced_by_hash = :newHash, replaced_at = :now
                       WHERE id = :id AND replaced_at IS NULL AND revoked = FALSE"""
                ).bind("newHash", successorHash).bind("now", now).bind("id", rt.id).execute()
                if (updated == 1) {
                    insertRefreshToken(handle, user.id, successor, rt.deviceName, rt.familyId)
                }
                updated == 1
            }
            if (claimed) {
                return RefreshResult.Success(TokenPair(createAccessToken(user), successor, accessTokenSeconds))
            }
            // Lost a race with a concurrent refresh; fall through to the reuse path.
            rt = lookup(tokenHash) ?: return RefreshResult.InvalidToken
            if (rt.revoked) return RefreshResult.InvalidToken
        }

        val replacedAt = rt.replacedAt ?: return RefreshResult.InvalidToken
        val withinGrace = !Duration.between(replacedAt, now).minus(gracePeriod).isPositive
        if (withinGrace && rt.replacedByHash == successorHash && successorStillFresh(successorHash)) {
            return RefreshResult.Success(TokenPair(createAccessToken(user), successor, accessTokenSeconds))
        }

        revokeFamily(rt.familyId)
        log.warn("AUDIT: Refresh token reuse — family {} revoked for user_id={}", rt.familyId, rt.userId)
        return RefreshResult.FamilyRevoked
    }

    /** Revokes a single refresh token. */
    fun revoke(rawRefreshToken: String): Boolean {
        val hash = hashToken(rawRefreshToken)
        return jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("UPDATE refresh_token SET revoked = TRUE WHERE token_hash = :hash AND revoked = FALSE")
                .bind("hash", hash).execute()
        } > 0
    }

    /** Revokes all refresh tokens for a user. */
    fun revokeAllForUser(userId: Long) {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("UPDATE refresh_token SET revoked = TRUE WHERE user_id = :uid AND revoked = FALSE")
                .bind("uid", userId).execute()
        }
    }

    /** Delete expired refresh tokens. Call periodically. */
    fun cleanupExpired() {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM refresh_token WHERE expires_at < :now")
                .bind("now", LocalDateTime.now(clock)).execute()
        }
    }

    /** Returns the raw HMAC signing key bytes. Used by [WebAuthnService] for challenge HMAC. */
    fun signingKeyBytes(): ByteArray = hexToBytes(getOrCreateSigningKey())

    /** SHA-256 fingerprint of the signing key (for TOFU verification). */
    fun signingKeyFingerprint(): String {
        val key = getOrCreateSigningKey()
        return MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    // --- Internal ---

    private fun lookup(tokenHash: String): TokenLookup? =
        jdbi.withHandle<TokenLookup?, Exception> { handle ->
            handle.createQuery(
                """SELECT id, user_id, family_id, device_name, expires_at, revoked,
                          replaced_by_hash, replaced_at
                   FROM refresh_token WHERE token_hash = :hash"""
            ).bind("hash", tokenHash)
                .map { rs, _ ->
                    TokenLookup(
                        rs.getLong("id"), rs.getLong("user_id"), rs.getString("family_id"),
                        rs.getString("device_name"), rs.getTimestamp("expires_at").toLocalDateTime(),
                        rs.getBoolean("revoked"), rs.getString("replaced_by_hash"),
                        rs.getTimestamp("replaced_at")?.toLocalDateTime()
                    )
                }.firstOrNull()
        }

    /**
     * True if the successor has not been revoked or rotated onward. A successor that is
     * not visible yet belongs to a concurrent rotation still committing, which is fine.
     */
    private fun successorStillFresh(successorHash: String): Boolean {
        val s = lookup(successorHash) ?: return true
        return !s.revoked && s.replacedAt == null
    }

    /** Deterministic successor for a refresh token: HMAC-SHA256(signing key, token), hex. */
    private fun deriveSuccessor(rawRefreshToken: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingKeyBytes(), "HmacSHA256"))
        return mac.doFinal("refresh-successor:$rawRefreshToken".toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun createAccessToken(user: AuthUser): String {
        val now = clock.instant()
        return JWT.create()
            .withIssuer(issuer).withAudience(audience)
            .withSubject(user.id.toString())
            .withClaim("type", "access")
            .withIssuedAt(now).withExpiresAt(now.plusSeconds(accessTokenSeconds.toLong()))
            .sign(currentAlgorithm())
    }

    private fun insertRefreshToken(handle: Handle, userId: Long, rawToken: String, deviceName: String, familyId: String) {
        val now = LocalDateTime.now(clock)
        handle.createUpdate(
            """INSERT INTO refresh_token (user_id, token_hash, family_id, device_name, created_at, expires_at, revoked)
               VALUES (:uid, :hash, :fam, :dev, :now, :exp, FALSE)"""
        ).bind("uid", userId).bind("hash", hashToken(rawToken))
            .bind("fam", familyId)
            .bind("dev", deviceName.take(255))
            .bind("now", now).bind("exp", now.plusDays(refreshTokenDays)).execute()
    }

    private fun enforceTokenCap(userId: Long) {
        val ids = jdbi.withHandle<List<Long>, Exception> { handle ->
            handle.createQuery(
                """SELECT id FROM refresh_token WHERE user_id = :uid AND revoked = FALSE AND expires_at > :now
                   ORDER BY created_at DESC"""
            ).bind("uid", userId).bind("now", LocalDateTime.now(clock)).mapTo(Long::class.java).list()
        }
        if (ids.size >= maxRefreshTokensPerUser) {
            val toRevoke = ids.drop(maxRefreshTokensPerUser - 1)
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate("UPDATE refresh_token SET revoked = TRUE WHERE id IN (<ids>)")
                    .bindList("ids", toRevoke).execute()
            }
        }
    }

    private fun revokeFamily(familyId: String) {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("UPDATE refresh_token SET revoked = TRUE WHERE family_id = :fid AND revoked = FALSE")
                .bind("fid", familyId).execute()
        }
    }

    private fun currentAlgorithm(): Algorithm = Algorithm.HMAC256(hexToBytes(getOrCreateSigningKey()))

    private fun previousAlgorithm(): Algorithm? {
        val prev = getConfig("signing_key_previous") ?: return null
        return Algorithm.HMAC256(hexToBytes(prev))
    }

    private fun verifierFor(algorithm: Algorithm): com.auth0.jwt.interfaces.JWTVerifier =
        (JWT.require(algorithm).withIssuer(issuer).withAudience(audience) as JWTVerifier.BaseVerification)
            .build(clock)

    private fun verifyToken(token: String): DecodedJWT? {
        try { return verifierFor(currentAlgorithm()).verify(token) }
        catch (_: JWTVerificationException) { }
        val prev = previousAlgorithm() ?: return null
        return try { verifierFor(prev).verify(token) }
        catch (_: JWTVerificationException) { null }
    }

    private fun getOrCreateSigningKey(): String {
        val existing = getConfig("signing_key")
        if (existing != null) return existing
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("INSERT INTO $configTableName (config_key, config_val) VALUES (:key, :val)")
                .bind("key", "signing_key").bind("val", key).execute()
        }
        log.info("Generated new JWT signing key")
        return key
    }

    private fun getConfig(key: String): String? =
        jdbi.withHandle<String?, Exception> { handle ->
            handle.createQuery("SELECT config_val FROM $configTableName WHERE config_key = :key")
                .bind("key", key).mapTo(String::class.java).firstOrNull()
        }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun hashToken(token: String): String =
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray()).joinToString("") { "%02x".format(it) }
}
