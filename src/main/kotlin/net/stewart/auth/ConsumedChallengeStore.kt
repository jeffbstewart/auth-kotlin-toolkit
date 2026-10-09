package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import java.security.MessageDigest
import java.sql.SQLIntegrityConstraintViolationException
import java.time.Clock
import java.time.Instant
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap
import javax.sql.DataSource

/**
 * Remembers WebAuthn challenges that have already been presented for verification,
 * so each signed challenge can be used at most once. Entries only need to be kept
 * until the challenge itself expires; after that the TTL check rejects it anyway.
 */
interface ConsumedChallengeStore {
    /**
     * Atomically records [challengeId] as consumed until [expiresAt].
     *
     * @return true if this call consumed it; false if it had already been consumed.
     */
    fun markConsumed(challengeId: String, expiresAt: Instant): Boolean
}

/**
 * Process-local [ConsumedChallengeStore]. Expired entries are purged opportunistically
 * as new challenges are consumed, so memory stays bounded by the challenge rate × TTL.
 */
class InMemoryConsumedChallengeStore(
    private val clock: Clock = Clock.systemDefaultZone(),
) : ConsumedChallengeStore {
    private val consumed = ConcurrentHashMap<String, Instant>()

    override fun markConsumed(challengeId: String, expiresAt: Instant): Boolean {
        purgeExpired()
        return consumed.putIfAbsent(challengeId, expiresAt) == null
    }

    /** Drops entries whose challenge has expired. */
    fun purgeExpired() {
        val now = clock.instant()
        consumed.entries.removeIf { it.value.isBefore(now) }
    }

    /** Number of entries currently held (for monitoring and tests). */
    fun size(): Int = consumed.size
}

/**
 * Database-backed [ConsumedChallengeStore] for deployments where several server
 * processes share one database. Requires the `webauthn_consumed_challenge` table
 * from `db/auth/V003__webauthn_consumed_challenge.sql`. Expired rows are purged
 * opportunistically on each insert; [purgeExpired] can also be called periodically.
 */
class JdbcConsumedChallengeStore(
    dataSource: DataSource,
    private val clock: Clock = Clock.systemDefaultZone(),
) : ConsumedChallengeStore {
    private val jdbi = Jdbi.create(dataSource)

    override fun markConsumed(challengeId: String, expiresAt: Instant): Boolean {
        purgeExpired()
        return try {
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    "INSERT INTO webauthn_consumed_challenge (challenge_hash, expires_at) VALUES (:h, :exp)"
                ).bind("h", sha256Hex(challengeId))
                    .bind("exp", LocalDateTime.ofInstant(expiresAt, clock.zone))
                    .execute()
            } == 1
        } catch (e: Exception) {
            if (isDuplicateKey(e)) false else throw e
        }
    }

    /** Deletes rows for challenges that have expired. */
    fun purgeExpired() {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM webauthn_consumed_challenge WHERE expires_at < :now")
                .bind("now", LocalDateTime.now(clock)).execute()
        }
    }

    private fun isDuplicateKey(e: Throwable): Boolean {
        var cause: Throwable? = e
        while (cause != null) {
            if (cause is SQLIntegrityConstraintViolationException) return true
            // SQLState class 23 = integrity constraint violation (portable across drivers).
            if (cause is java.sql.SQLException && cause.sqlState?.startsWith("23") == true) return true
            cause = cause.cause
        }
        return false
    }

    private fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}
