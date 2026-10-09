package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime
import java.util.concurrent.locks.ReentrantLock
import javax.sql.DataSource
import kotlin.concurrent.withLock

/**
 * Result of a login attempt.
 */
sealed class LoginResult {
    data class Success(val user: AuthUser) : LoginResult()
    data object Failed : LoginResult()
    data class RateLimited(val retryAfterSeconds: Long) : LoginResult()
}

/**
 * Login authentication with rate limiting, exponential backoff, and temporary lockout.
 *
 * Attempts are tracked in a `login_attempt` table. Each attempt is checked against the
 * limits and *reserved* (recorded as a failure) atomically before the password is
 * verified, then flipped to a success if it matches — so concurrent attempts cannot
 * slip past a limit while their BCrypt verifications are in flight.
 *
 * - **Backoff:** after [rateLimitThreshold] failures within [rateLimitWindowMinutes]
 *   from one IP, or against one username, further attempts from that IP / for that
 *   username wait with exponential backoff. The two are tracked independently.
 * - **Lockout:** after [lockoutThreshold] failures against one username within
 *   [lockoutWindow] (counting only failures since that username's last successful
 *   login), the username is refused for [lockoutDuration] after its most recent
 *   failure. Lockout is temporary and based on per-username failures only; failures
 *   from an IP never lock accounts, and the persistent account lock
 *   ([AuthUser.isLocked], set via [UserRepository.lockUser]) is left for
 *   administrators.
 * - **Daily cap:** an IP with [dailyFailureCap] failures in 24 hours is refused.
 *
 * The atomic check-and-reserve is enforced within one process. Multiple processes
 * sharing a database are still limited, but can each admit one attempt concurrently.
 *
 * @param clock Time source (injectable for tests)
 */
class LoginService(
    private val dataSource: DataSource,
    private val userRepository: UserRepository,
    private val rateLimitWindowMinutes: Long = 15L,
    private val rateLimitThreshold: Int = 5,
    private val baseCooldownSeconds: Long = 30L,
    private val maxCooldownSeconds: Long = 900L,
    private val lockoutThreshold: Int = 20,
    private val dailyFailureCap: Int = 100,
    private val lockoutWindow: Duration = Duration.ofHours(24),
    private val lockoutDuration: Duration = Duration.ofMinutes(30),
    private val clock: Clock = Clock.systemDefaultZone(),
) {
    private val log = LoggerFactory.getLogger(LoginService::class.java)
    private val jdbi = Jdbi.create(dataSource)
    private val lockStripes = Array(LOCK_STRIPES) { ReentrantLock() }

    /**
     * Attempts to authenticate a user by username and password.
     * Enforces rate limiting and records the attempt.
     *
     * @param ip The client's real IP address. **Must be resolved from trusted proxy headers only.**
     *   Never pass a raw `X-Forwarded-For` value from an untrusted source — an attacker could
     *   rotate IPs to bypass per-IP rate limiting.
     */
    fun login(username: String, password: String, ip: String): LoginResult {
        val attemptId = withAttemptLocks(ip, username) {
            checkRateLimit(ip, username)?.let { return it }
            reserveAttempt(username, ip)
        }

        val user = userRepository.findByUsername(username)

        // Reject locked accounts (still run BCrypt to equalize timing)
        if (user?.isLocked == true) {
            PasswordService.dummyVerify()
            log.info("AUDIT: Login rejected — account '{}' is locked", maskUsername(username))
            return LoginResult.Failed
        }

        // Equalize timing whether user exists or not (prevents account enumeration)
        val matched = if (user != null) {
            PasswordService.verify(password, user.passwordHash)
        } else {
            PasswordService.dummyVerify()
            false
        }

        return if (user != null && matched) {
            markSuccess(attemptId)
            log.info("AUDIT: Login success user='{}' ip='{}'", username, ip)
            LoginResult.Success(user)
        } else {
            log.info("AUDIT: Login failed user='{}' ip='{}'", maskUsername(username), ip)
            LoginResult.Failed
        }
    }

    /** Delete login attempts older than 30 days. Call periodically. */
    fun cleanupOldAttempts() {
        val deleted = jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM login_attempt WHERE attempted_at < :cutoff")
                .bind("cutoff", LocalDateTime.now(clock).minusDays(30)).execute()
        }
        if (deleted > 0) log.info("Cleaned up {} old login attempts", deleted)
    }

    /** Holds the lock stripes for both the IP and the (case-folded) username, in a fixed order. */
    private inline fun <T> withAttemptLocks(ip: String, username: String, block: () -> T): T {
        val a = Math.floorMod(("ip:$ip").hashCode(), LOCK_STRIPES)
        val b = Math.floorMod(("user:" + username.lowercase()).hashCode(), LOCK_STRIPES)
        val first = lockStripes[minOf(a, b)]
        val second = lockStripes[maxOf(a, b)]
        return first.withLock { second.withLock(block) }
    }

    /** Records the attempt as a failure up front; returns its row id. */
    private fun reserveAttempt(username: String, ip: String): Long =
        jdbi.withHandle<Long, Exception> { handle ->
            handle.createUpdate(
                """INSERT INTO login_attempt (username, ip_address, attempted_at, success)
                   VALUES (:user, :ip, :at, FALSE)"""
            ).bind("user", username).bind("ip", ip).bind("at", LocalDateTime.now(clock))
                .executeAndReturnGeneratedKeys("id").mapTo(Long::class.java).one()
        }

    private fun markSuccess(attemptId: Long) {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("UPDATE login_attempt SET success = TRUE WHERE id = :id")
                .bind("id", attemptId).execute()
        }
    }

    private fun checkRateLimit(ip: String, username: String): LoginResult.RateLimited? {
        val now = LocalDateTime.now(clock)
        val lastSuccess = lastUserAttempt(username, success = true, since = null)

        // Temporary per-username lockout (failures since the last successful login only).
        val lockoutSince = maxOf(now.minus(lockoutWindow), lastSuccess ?: LocalDateTime.MIN)
        val lockoutFailures = countUserFailures(username, lockoutSince)
        if (lockoutFailures >= lockoutThreshold) {
            val lastFailure = lastUserAttempt(username, success = false, since = lockoutSince)
            val remaining = secondsUntil(now, lastFailure?.plus(lockoutDuration))
            if (remaining > 0) {
                log.warn("AUDIT: Account '{}' temporarily locked out after {} failed attempts ({}s remaining)",
                    maskUsername(username), lockoutFailures, remaining)
                return LoginResult.RateLimited(remaining)
            }
        }

        // Exponential backoff, tracked independently per IP and per username.
        val windowStart = now.minusMinutes(rateLimitWindowMinutes)
        val userWindowStart = maxOf(windowStart, lastSuccess ?: LocalDateTime.MIN)
        val ipWait = backoffSeconds(
            now, countIpFailures(ip, windowStart), lastIpFailure(ip, windowStart))
        val userWait = backoffSeconds(
            now, countUserFailures(username, userWindowStart),
            lastUserAttempt(username, success = false, since = userWindowStart))
        val wait = maxOf(ipWait, userWait)
        if (wait > 0) {
            log.info("AUDIT: Rate-limited ip='{}' user='{}' ({}s)", ip, maskUsername(username), wait)
            return LoginResult.RateLimited(wait)
        }

        // Daily cap per IP.
        if (countIpFailures(ip, now.minusHours(24)) >= dailyFailureCap) {
            log.info("AUDIT: Daily rate limit hit ip='{}'", ip)
            return LoginResult.RateLimited(maxCooldownSeconds)
        }
        return null
    }

    private fun backoffSeconds(now: LocalDateTime, failures: Int, lastFailure: LocalDateTime?): Long {
        if (failures < rateLimitThreshold || lastFailure == null) return 0
        val exponent = failures - rateLimitThreshold
        val cooldown = minOf(baseCooldownSeconds * (1L shl minOf(exponent, 10)), maxCooldownSeconds)
        return secondsUntil(now, lastFailure.plusSeconds(cooldown))
    }

    private fun secondsUntil(now: LocalDateTime, until: LocalDateTime?): Long {
        if (until == null) return 0
        val d = Duration.between(now, until)
        return if (d.isNegative || d.isZero) 0L else d.seconds + 1
    }

    private fun countIpFailures(ip: String, since: LocalDateTime): Int =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery(
                "SELECT COUNT(*) FROM login_attempt WHERE ip_address = :ip AND success = FALSE AND attempted_at > :since"
            ).bind("ip", ip).bind("since", since).mapTo(Int::class.java).one()
        }

    private fun lastIpFailure(ip: String, since: LocalDateTime): LocalDateTime? =
        jdbi.withHandle<LocalDateTime?, Exception> { handle ->
            handle.createQuery(
                "SELECT MAX(attempted_at) FROM login_attempt WHERE ip_address = :ip AND success = FALSE AND attempted_at > :since"
            ).bind("ip", ip).bind("since", since).mapTo(LocalDateTime::class.java).firstOrNull()
        }

    private fun countUserFailures(username: String, since: LocalDateTime): Int =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery(
                """SELECT COUNT(*) FROM login_attempt
                   WHERE LOWER(username) = LOWER(:user) AND success = FALSE AND attempted_at > :since"""
            ).bind("user", username).bind("since", since).mapTo(Int::class.java).one()
        }

    private fun lastUserAttempt(username: String, success: Boolean, since: LocalDateTime?): LocalDateTime? =
        jdbi.withHandle<LocalDateTime?, Exception> { handle ->
            handle.createQuery(
                """SELECT MAX(attempted_at) FROM login_attempt
                   WHERE LOWER(username) = LOWER(:user) AND success = :ok AND attempted_at > :since"""
            ).bind("user", username).bind("ok", success).bind("since", since ?: LocalDateTime.of(1970, 1, 1, 0, 0))
                .mapTo(LocalDateTime::class.java).firstOrNull()
        }

    private companion object {
        const val LOCK_STRIPES = 64
    }
}

/** Masks a username for audit logs (preserves first 2 and last 2 characters). */
fun maskUsername(raw: String): String {
    if (raw.length <= 3) return "***"
    val truncated = if (raw.length > 30) raw.substring(0, 27) + "..." else raw
    return truncated.substring(0, 2) + "*".repeat(truncated.length - 4) + truncated.substring(truncated.length - 2)
}
