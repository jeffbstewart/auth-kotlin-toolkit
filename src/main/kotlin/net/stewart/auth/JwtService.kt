package net.stewart.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.util.UUID
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
 * @param dataSource JDBC DataSource
 * @param userRepository User lookup
 * @param issuer JWT issuer claim (default: "auth-toolkit")
 * @param audience JWT audience claim (default: "api")
 * @param accessTokenSeconds Access token lifetime (default: 900 = 15 minutes)
 * @param refreshTokenDays Refresh token lifetime (default: 30 days)
 * @param configTableName Table for signing key storage (default: "auth_config")
 * @param maxRefreshTokensPerUser Cap on active refresh tokens per user (default: 10)
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
) {
    private val log = LoggerFactory.getLogger(JwtService::class.java)
    private val jdbi = Jdbi.create(dataSource)
    private val gracePeriodSeconds = 60L

    /** Creates a new access + refresh token pair. */
    fun createTokenPair(user: AuthUser, deviceName: String): TokenPair {
        val accessToken = createAccessToken(user)
        val refreshToken = createRefreshToken(user, deviceName)
        return TokenPair(accessToken, refreshToken, accessTokenSeconds)
    }

    /** Validates a JWT access token. Returns the authenticated user or null. */
    fun validateAccessToken(token: String): AuthUser? {
        val decoded = verifyToken(token) ?: return null
        if (decoded.getClaim("type").asString() != "access") return null
        val userId = decoded.subject?.toLongOrNull() ?: return null
        return userRepository.findById(userId)
    }

    /** Refreshes a token pair with rotation and family-based theft detection. */
    fun refresh(rawRefreshToken: String): RefreshResult {
        val tokenHash = hashToken(rawRefreshToken)
        val now = LocalDateTime.now()

        data class TokenLookup(
            val id: Long, val userId: Long, val familyId: String, val deviceName: String,
            val expiresAt: LocalDateTime, val revoked: Boolean,
            val replacedByHash: String?, val replacedAt: LocalDateTime?
        )

        val rt = jdbi.withHandle<TokenLookup?, Exception> { handle ->
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
        } ?: return RefreshResult.InvalidToken

        if (rt.revoked || rt.expiresAt.isBefore(now)) return RefreshResult.InvalidToken

        if (rt.replacedAt != null) {
            val secondsSince = Duration.between(rt.replacedAt, now).seconds
            if (secondsSince <= gracePeriodSeconds) {
                val user = userRepository.findById(rt.userId) ?: return RefreshResult.InvalidToken
                return RefreshResult.Success(TokenPair(
                    createAccessToken(user), createRefreshToken(user, rt.deviceName, rt.familyId), accessTokenSeconds))
            }
            revokeFamily(rt.familyId)
            log.warn("AUDIT: Refresh token reuse — family {} revoked for user_id={}", rt.familyId, rt.userId)
            return RefreshResult.FamilyRevoked
        }

        val user = userRepository.findById(rt.userId) ?: return RefreshResult.InvalidToken
        val newRefresh = createRefreshToken(user, rt.deviceName, rt.familyId)

        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate(
                "UPDATE refresh_token SET replaced_by_hash = :newHash, replaced_at = :now WHERE id = :id"
            ).bind("newHash", hashToken(newRefresh)).bind("now", now).bind("id", rt.id).execute()
        }

        return RefreshResult.Success(TokenPair(createAccessToken(user), newRefresh, accessTokenSeconds))
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
                .bind("now", LocalDateTime.now()).execute()
        }
    }

    /** SHA-256 fingerprint of the signing key (for TOFU verification). */
    fun signingKeyFingerprint(): String {
        val key = getOrCreateSigningKey()
        return MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    // --- Internal ---

    private fun createAccessToken(user: AuthUser): String {
        val now = Instant.now()
        return JWT.create()
            .withIssuer(issuer).withAudience(audience)
            .withSubject(user.id.toString())
            .withClaim("type", "access")
            .withIssuedAt(now).withExpiresAt(now.plusSeconds(accessTokenSeconds.toLong()))
            .sign(currentAlgorithm())
    }

    private fun createRefreshToken(user: AuthUser, deviceName: String, familyId: String? = null): String {
        val token = UUID.randomUUID().toString()
        val now = LocalDateTime.now()
        enforceTokenCap(user.id)

        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate(
                """INSERT INTO refresh_token (user_id, token_hash, family_id, device_name, created_at, expires_at, revoked)
                   VALUES (:uid, :hash, :fam, :dev, :now, :exp, FALSE)"""
            ).bind("uid", user.id).bind("hash", hashToken(token))
                .bind("fam", familyId ?: UUID.randomUUID().toString())
                .bind("dev", deviceName.take(255))
                .bind("now", now).bind("exp", now.plusDays(refreshTokenDays)).execute()
        }
        return token
    }

    private fun enforceTokenCap(userId: Long) {
        val ids = jdbi.withHandle<List<Long>, Exception> { handle ->
            handle.createQuery(
                """SELECT id FROM refresh_token WHERE user_id = :uid AND revoked = FALSE AND expires_at > :now
                   ORDER BY created_at DESC"""
            ).bind("uid", userId).bind("now", LocalDateTime.now()).mapTo(Long::class.java).list()
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

    private fun verifyToken(token: String): DecodedJWT? {
        try { return JWT.require(currentAlgorithm()).withIssuer(issuer).withAudience(audience).build().verify(token) }
        catch (_: JWTVerificationException) { }
        val prev = previousAlgorithm() ?: return null
        return try { JWT.require(prev).withIssuer(issuer).withAudience(audience).build().verify(token) }
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
