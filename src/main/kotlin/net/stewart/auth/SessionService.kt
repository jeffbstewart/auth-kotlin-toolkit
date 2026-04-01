package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap
import javax.sql.DataSource

/**
 * Cookie-based session management with SHA-256 token hashing and in-memory caching.
 *
 * Sessions are stored in a `session_token` table. Raw tokens are never persisted —
 * only SHA-256 hashes. An in-memory cache (configurable TTL) eliminates redundant
 * database lookups for high-frequency requests (image loading, API polling).
 *
 * @param dataSource JDBC DataSource for session token persistence
 * @param userRepository Repository for looking up users by ID
 * @param cookieName The session cookie name (default: "auth_session")
 * @param sessionDays Session lifetime in days (default: 30)
 * @param maxSessionsPerUser Maximum concurrent sessions per user (default: 10)
 * @param cacheTtlSeconds Token cache TTL in seconds (default: 60)
 */
class SessionService(
    private val dataSource: DataSource,
    private val userRepository: UserRepository,
    val cookieName: String = "auth_session",
    val sessionDays: Long = 30L,
    private val maxSessionsPerUser: Int = 10,
    private val cacheTtlSeconds: Long = 60L,
) {
    private val log = LoggerFactory.getLogger(SessionService::class.java)
    private val jdbi = Jdbi.create(dataSource)

    private data class CachedAuth(
        val user: AuthUser,
        val tokenId: Long,
        val cachedAt: Instant,
        val lastUsedUpdatedAt: Instant,
    )

    private val tokenCache = ConcurrentHashMap<String, CachedAuth>()

    /**
     * Creates a new session for the user. Returns the raw token string.
     * The caller is responsible for setting the cookie.
     */
    fun createSession(user: AuthUser, userAgent: String): String {
        // Cap sessions per user
        val existingTokenIds = jdbi.withHandle<List<Long>, Exception> { handle ->
            handle.createQuery("SELECT id FROM session_token WHERE user_id = :uid ORDER BY expires_at DESC")
                .bind("uid", user.id).mapTo(Long::class.java).list()
        }
        if (existingTokenIds.size >= maxSessionsPerUser) {
            val toRemove = existingTokenIds.drop(maxSessionsPerUser - 1)
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate("DELETE FROM session_token WHERE id IN (<ids>)")
                    .bindList("ids", toRemove).execute()
            }
            log.info("AUDIT: Session created user='{}' (trimmed {} oldest)", user.username, toRemove.size)
        } else {
            log.info("AUDIT: Session created user='{}'", user.username)
        }

        val token = generateSecureToken()
        val tokenHash = hashToken(token)
        val now = LocalDateTime.now()
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate(
                """INSERT INTO session_token (user_id, token_hash, user_agent, expires_at, last_used_at, created_at)
                   VALUES (:uid, :hash, :ua, :exp, :now, :now)"""
            ).bind("uid", user.id).bind("hash", tokenHash).bind("ua", userAgent)
                .bind("exp", now.plusDays(sessionDays)).bind("now", now).execute()
        }
        return token
    }

    /** Validates a raw cookie token and returns the authenticated user, or null. */
    fun validateToken(token: String): AuthUser? {
        val hash = hashToken(token)
        val now = Instant.now()

        // Check cache
        val cached = tokenCache[hash]
        if (cached != null && now.epochSecond - cached.cachedAt.epochSecond < cacheTtlSeconds) {
            // Reject locked users even from cache
            if (cached.user.isLocked) {
                tokenCache.remove(hash)
                return null
            }
            // Throttle last_used_at updates (every 5 minutes)
            if (now.epochSecond - cached.lastUsedUpdatedAt.epochSecond >= 300L) {
                try {
                    jdbi.withHandle<Int, Exception> { handle ->
                        handle.createUpdate("UPDATE session_token SET last_used_at = :now WHERE id = :id")
                            .bind("now", LocalDateTime.now()).bind("id", cached.tokenId).execute()
                    }
                    tokenCache[hash] = cached.copy(lastUsedUpdatedAt = now)
                } catch (_: Exception) { }
            }
            return cached.user
        }

        // Cache miss — validate against DB
        data class TokenLookup(val id: Long, val userId: Long)
        val lookup = jdbi.withHandle<TokenLookup?, Exception> { handle ->
            handle.createQuery(
                "SELECT id, user_id FROM session_token WHERE token_hash = :hash AND expires_at > :now LIMIT 1"
            ).bind("hash", hash).bind("now", LocalDateTime.now())
                .map { rs, _ -> TokenLookup(rs.getLong("id"), rs.getLong("user_id")) }.firstOrNull()
        } ?: return null

        val user = userRepository.findById(lookup.userId) ?: return null

        tokenCache[hash] = CachedAuth(user, lookup.id, now, now)

        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("UPDATE session_token SET last_used_at = :now WHERE id = :id")
                .bind("now", LocalDateTime.now()).bind("id", lookup.id).execute()
        }
        return user
    }

    /** Revokes a session by raw cookie token. Returns the user who was logged out. */
    fun revokeByToken(cookieToken: String): AuthUser? {
        val hash = hashToken(cookieToken)
        tokenCache.remove(hash)
        val userId = jdbi.withHandle<Long?, Exception> { handle ->
            handle.createQuery("SELECT user_id FROM session_token WHERE token_hash = :hash LIMIT 1")
                .bind("hash", hash).mapTo(Long::class.java).firstOrNull()
        }
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM session_token WHERE token_hash = :hash")
                .bind("hash", hash).execute()
        }
        return userId?.let { userRepository.findById(it) }
    }

    /** Revokes all sessions for a user. Call on password change. */
    fun revokeAllForUser(userId: Long) {
        tokenCache.entries.removeIf { it.value.user.id == userId }
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM session_token WHERE user_id = :uid")
                .bind("uid", userId).execute()
        }
    }

    /** Revokes all sessions for a user except the current one. */
    fun revokeAllExceptCurrent(userId: Long, currentTokenHash: String?) {
        tokenCache.entries.removeIf { it.value.user.id == userId && it.key != currentTokenHash }
        jdbi.withHandle<Int, Exception> { handle ->
            if (currentTokenHash != null) {
                handle.createUpdate("DELETE FROM session_token WHERE user_id = :uid AND token_hash != :hash")
                    .bind("uid", userId).bind("hash", currentTokenHash).execute()
            } else {
                handle.createUpdate("DELETE FROM session_token WHERE user_id = :uid")
                    .bind("uid", userId).execute()
            }
        }
    }

    /** Delete expired session tokens. Call periodically. */
    fun cleanupExpired() {
        val deleted = jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM session_token WHERE expires_at < :now")
                .bind("now", LocalDateTime.now()).execute()
        }
        if (deleted > 0) log.info("Cleaned up {} expired session tokens", deleted)
    }

    /** Builds a Set-Cookie header value for the session cookie. Secure flag defaults to true. */
    fun buildCookieHeader(token: String, secure: Boolean = true): String {
        val maxAge = (sessionDays * 24 * 60 * 60).toInt()
        return buildString {
            append("$cookieName=$token; Path=/; Max-Age=$maxAge; HttpOnly; SameSite=Lax")
            if (secure) append("; Secure")
        }
    }

    /** Builds a Set-Cookie header that expires (clears) the session cookie. */
    fun buildExpireCookieHeader(): String =
        "$cookieName=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"

    /** Evict a specific token from the cache. */
    fun evictFromCache(tokenHash: String) { tokenCache.remove(tokenHash) }

    /** Clear entire token cache. */
    fun clearCache() { tokenCache.clear() }

    companion object {
        private val secureRandom = SecureRandom()

        /** Generates a 256-bit cryptographically random token (hex-encoded). */
        fun generateSecureToken(): String {
            val bytes = ByteArray(32)
            secureRandom.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }

        fun hashToken(token: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest(token.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }
}
