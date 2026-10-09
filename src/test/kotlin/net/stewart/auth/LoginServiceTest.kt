package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import java.time.Duration
import java.time.LocalDateTime
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class LoginServiceTest {

    private class Fixture(
        rateLimitThreshold: Int = 5,
        lockoutThreshold: Int = 20,
        lockoutDuration: Duration = Duration.ofMinutes(30),
    ) : AutoCloseable {
        val ds = createAuthTestDb()
        val clock = MutableClock()
        val repo = TestUserRepository().also {
            it.users[1] = TestUser(1, "victim", PasswordService.hash("correct-horse"))
            it.users[2] = TestUser(2, "other", PasswordService.hash("battery-staple"))
        }
        val login = LoginService(
            ds, repo,
            rateLimitThreshold = rateLimitThreshold,
            lockoutThreshold = lockoutThreshold,
            lockoutDuration = lockoutDuration,
            clock = clock,
        )

        /** Inserts historical failed attempts directly, as if they happened [ago] before now. */
        fun seedFailures(username: String, ip: String, count: Int, ago: Duration = Duration.ofMinutes(1)) {
            val at = LocalDateTime.now(clock).minus(ago)
            Jdbi.create(ds).useHandle<Exception> { h ->
                repeat(count) {
                    h.createUpdate(
                        "INSERT INTO login_attempt (username, ip_address, attempted_at, success) VALUES (:u, :ip, :at, FALSE)"
                    ).bind("u", username).bind("ip", ip).bind("at", at).execute()
                }
            }
        }

        override fun close() = ds.close()
    }

    @Test
    fun `parallel wrong-password attempts cannot exceed the threshold`(): Unit = Fixture(rateLimitThreshold = 3).use { f ->
        val threads = 24
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val futures = pool.invokeAll((1..threads).map { i ->
                Callable {
                    // Distinct IPs so only the per-username limit is in play.
                    f.login.login("victim", "wrong-password", "10.0.0.$i")
                }
            })
            val results = futures.map { it.get() }
            assertEquals(3, results.count { it is LoginResult.Failed },
                "only rateLimitThreshold attempts may reach password verification")
            assertEquals(threads - 3, results.count { it is LoginResult.RateLimited })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `parallel attempts from one IP across usernames cannot exceed the threshold`(): Unit =
        Fixture(rateLimitThreshold = 3).use { f ->
            val threads = 24
            val pool = Executors.newFixedThreadPool(threads)
            try {
                val results = pool.invokeAll((1..threads).map { i ->
                    Callable { f.login.login("user$i", "wrong-password", "10.9.9.9") }
                }).map { it.get() }
                assertEquals(3, results.count { it is LoginResult.Failed })
            } finally {
                pool.shutdownNow()
            }
        }

    @Test
    fun `failures from one IP never lock other users' accounts`(): Unit = Fixture(lockoutThreshold = 20).use { f ->
        // The attacking IP has racked up many failures against assorted usernames.
        (1..40).forEach { f.seedFailures("someone$it", "203.0.113.7", 1) }

        // The attacking IP is throttled...
        assertIs<LoginResult.RateLimited>(f.login.login("victim", "guess", "203.0.113.7"))

        // ...but the victim's account is neither locked nor throttled for the victim.
        assertFalse(f.repo.users.getValue(1).isLocked)
        assertIs<LoginResult.Success>(f.login.login("victim", "correct-horse", "198.51.100.1"))
    }

    @Test
    fun `username lockout is temporary and never locks the account permanently`(): Unit =
        Fixture(lockoutThreshold = 20, lockoutDuration = Duration.ofMinutes(30)).use { f ->
            f.seedFailures("victim", "198.51.100.50", 20, ago = Duration.ofMinutes(20))

            // Locked out, even with the correct password from a clean IP.
            val limited = assertIs<LoginResult.RateLimited>(f.login.login("victim", "correct-horse", "198.51.100.1"))
            assertTrue(limited.retryAfterSeconds in 1..(10 * 60 + 1), "remaining lockout: ${limited.retryAfterSeconds}")
            assertFalse(f.repo.users.getValue(1).isLocked, "lockout must not set the persistent lock flag")

            // Other accounts are unaffected.
            assertIs<LoginResult.Success>(f.login.login("other", "battery-staple", "198.51.100.1"))

            f.clock.advance(Duration.ofMinutes(11))
            assertIs<LoginResult.Success>(f.login.login("victim", "correct-horse", "198.51.100.1"))
        }

    @Test
    fun `successful login resets the username failure count`(): Unit = Fixture(lockoutThreshold = 20).use { f ->
        f.seedFailures("victim", "198.51.100.50", 4, ago = Duration.ofHours(2))
        assertIs<LoginResult.Success>(f.login.login("victim", "correct-horse", "198.51.100.1"))
        f.clock.advance(Duration.ofHours(1))
        f.seedFailures("victim", "198.51.100.50", 16, ago = Duration.ofMinutes(20))
        // 20 failures in the lockout window, but only 16 since the last success.
        assertIs<LoginResult.Success>(f.login.login("victim", "correct-horse", "198.51.100.1"))
    }

    @Test
    fun `backoff applies after the rate-limit threshold`(): Unit = Fixture(rateLimitThreshold = 3).use { f ->
        repeat(3) { assertIs<LoginResult.Failed>(f.login.login("victim", "wrong", "198.51.100.1")) }
        assertIs<LoginResult.RateLimited>(f.login.login("victim", "correct-horse", "198.51.100.1"))
        f.clock.advance(Duration.ofSeconds(31))
        assertIs<LoginResult.Success>(f.login.login("victim", "correct-horse", "198.51.100.1"))
    }

    @Test
    fun `administratively locked accounts stay rejected`(): Unit = Fixture().use { f ->
        f.repo.lockUser(1)
        assertIs<LoginResult.Failed>(f.login.login("victim", "correct-horse", "198.51.100.1"))
    }
}
