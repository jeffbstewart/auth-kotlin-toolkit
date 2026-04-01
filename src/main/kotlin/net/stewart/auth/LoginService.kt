package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.LocalDateTime
import javax.sql.DataSource

/**
 * Result of a login attempt.
 */
sealed class LoginResult {
    data class Success(val user: AuthUser) : LoginResult()
    data object Failed : LoginResult()
    data class RateLimited(val retryAfterSeconds: Long) : LoginResult()
}

/**
 * Login authentication with rate limiting, exponential backoff, and account lockout.
 *
 * Rate limiting is tracked per-IP and per-username in a `login_attempt` table.
 * After [rateLimitThreshold] failures in [rateLimitWindowMinutes], requests are
 * delayed with exponential backoff. After [lockoutThreshold] failures, the account
 * is locked (requires admin intervention).
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
) {
    private val log = LoggerFactory.getLogger(LoginService::class.java)
    private val jdbi = Jdbi.create(dataSource)

    /**
     * Attempts to authenticate a user by username and password.
     * Enforces rate limiting and records the attempt.
     */
    fun login(username: String, password: String, ip: String): LoginResult {
        val rateLimitResult = checkRateLimit(ip, username)
        if (rateLimitResult != null) return rateLimitResult

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

        // Record the attempt
        recordAttempt(username, ip, matched)

        return if (user != null && matched) {
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
                .bind("cutoff", LocalDateTime.now().minusDays(30)).execute()
        }
        if (deleted > 0) log.info("Cleaned up {} old login attempts", deleted)
    }

    private fun recordAttempt(username: String, ip: String, success: Boolean) {
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate(
                """INSERT INTO login_attempt (username, ip_address, attempted_at, success)
                   VALUES (:user, :ip, :at, :ok)"""
            ).bind("user", username).bind("ip", ip)
                .bind("at", LocalDateTime.now()).bind("ok", success).execute()
        }
    }

    private fun checkRateLimit(ip: String, username: String): LoginResult.RateLimited? {
        val windowStart = LocalDateTime.now().minusMinutes(rateLimitWindowMinutes)

        val ipFailures = countFailures("ip_address", ip, windowStart)
        val userFailures = countFailuresCI("username", username, windowStart)
        val maxFailures = maxOf(ipFailures, userFailures)

        // Daily cap
        if (maxFailures < rateLimitThreshold) {
            val dayStart = LocalDateTime.now().minusHours(24)
            val dailyMax = maxOf(
                countFailures("ip_address", ip, dayStart),
                countFailuresCI("username", username, dayStart)
            )
            if (dailyMax >= dailyFailureCap) {
                log.info("AUDIT: Daily rate limit hit ip='{}' user='{}'", ip, maskUsername(username))
                return LoginResult.RateLimited(maxCooldownSeconds)
            }
            return null
        }

        // Permanent lockout
        if (maxFailures >= lockoutThreshold) {
            userRepository.findByUsername(username)?.let { user ->
                if (!user.isLocked) {
                    userRepository.lockUser(user.id)
                    log.warn("AUDIT: Account '{}' locked after {} failed attempts", maskUsername(username), maxFailures)
                }
            }
            return LoginResult.RateLimited(maxCooldownSeconds)
        }

        // Exponential backoff
        val exponent = maxFailures - rateLimitThreshold
        val cooldown = minOf(baseCooldownSeconds * (1L shl minOf(exponent, 10)), maxCooldownSeconds)

        val lastAttempt = jdbi.withHandle<LocalDateTime?, Exception> { handle ->
            handle.createQuery(
                """SELECT MAX(attempted_at) FROM login_attempt
                   WHERE (ip_address = :ip OR LOWER(username) = LOWER(:user))
                     AND success = FALSE AND attempted_at > :window"""
            ).bind("ip", ip).bind("user", username).bind("window", windowStart)
                .mapTo(LocalDateTime::class.java).firstOrNull()
        } ?: return null

        val retryAfter = Duration.between(LocalDateTime.now(), lastAttempt.plusSeconds(cooldown))
        val secondsRemaining = if (retryAfter.isNegative) 0L else retryAfter.seconds + 1
        if (secondsRemaining > 0) {
            log.info("AUDIT: Rate-limited ip='{}' user='{}' ({}s cooldown)", ip, maskUsername(username), cooldown)
            return LoginResult.RateLimited(secondsRemaining)
        }
        return null
    }

    private fun countFailures(column: String, value: String, since: LocalDateTime): Int =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery(
                "SELECT COUNT(*) FROM login_attempt WHERE $column = :val AND success = FALSE AND attempted_at > :since"
            ).bind("val", value).bind("since", since).mapTo(Int::class.java).one()
        }

    private fun countFailuresCI(column: String, value: String, since: LocalDateTime): Int =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery(
                "SELECT COUNT(*) FROM login_attempt WHERE LOWER($column) = LOWER(:val) AND success = FALSE AND attempted_at > :since"
            ).bind("val", value).bind("since", since).mapTo(Int::class.java).one()
        }
}

/** Masks a username for audit logs (preserves first 2 and last 2 characters). */
fun maskUsername(raw: String): String {
    if (raw.length <= 3) return "***"
    val truncated = if (raw.length > 30) raw.substring(0, 27) + "..." else raw
    return truncated.substring(0, 2) + "*".repeat(truncated.length - 4) + truncated.substring(truncated.length - 2)
}
