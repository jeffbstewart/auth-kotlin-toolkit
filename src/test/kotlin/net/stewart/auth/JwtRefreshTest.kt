package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class JwtRefreshTest {

    private class Fixture : AutoCloseable {
        val ds = createAuthTestDb()
        val clock = MutableClock()
        val repo = TestUserRepository().also {
            it.users[1] = TestUser(1, "carol", PasswordService.hash("password1"))
        }
        val jwt = JwtService(ds, repo, clock = clock)
        val user get() = repo.users.getValue(1)

        fun activeTokenCount(): Int = Jdbi.create(ds).withHandle<Int, Exception> { h ->
            h.createQuery("SELECT COUNT(*) FROM refresh_token WHERE revoked = FALSE")
                .mapTo(Int::class.java).one()
        }

        override fun close() = ds.close()
    }

    @Test
    fun `refresh rotates the token`(): Unit = Fixture().use { f ->
        val pair = f.jwt.createTokenPair(f.user, "phone")
        val result = assertIs<RefreshResult.Success>(f.jwt.refresh(pair.refreshToken))
        assertNotEquals(pair.refreshToken, result.tokenPair.refreshToken)
        assertNotNull(f.jwt.validateAccessToken(result.tokenPair.accessToken))
        assertIs<RefreshResult.Success>(f.jwt.refresh(result.tokenPair.refreshToken))
    }

    @Test
    fun `reuse within grace window returns the already-issued successor`(): Unit = Fixture().use { f ->
        val pair = f.jwt.createTokenPair(f.user, "phone")
        val first = assertIs<RefreshResult.Success>(f.jwt.refresh(pair.refreshToken))
        val tokensAfterRotation = f.activeTokenCount()

        f.clock.advance(Duration.ofSeconds(30))
        val retry = assertIs<RefreshResult.Success>(f.jwt.refresh(pair.refreshToken))

        assertEquals(first.tokenPair.refreshToken, retry.tokenPair.refreshToken,
            "a retried refresh must not mint a new refresh token")
        assertEquals(tokensAfterRotation, f.activeTokenCount(),
            "no additional refresh token may be created in the family")
        assertNotNull(f.jwt.validateAccessToken(retry.tokenPair.accessToken))
    }

    @Test
    fun `reuse after grace window revokes the whole family`(): Unit = Fixture().use { f ->
        val pair = f.jwt.createTokenPair(f.user, "phone")
        val first = assertIs<RefreshResult.Success>(f.jwt.refresh(pair.refreshToken))

        f.clock.advance(Duration.ofSeconds(61))
        assertEquals(RefreshResult.FamilyRevoked, f.jwt.refresh(pair.refreshToken))
        assertEquals(RefreshResult.InvalidToken, f.jwt.refresh(first.tokenPair.refreshToken))
    }

    @Test
    fun `reuse within grace window after the successor was rotated revokes the family`(): Unit = Fixture().use { f ->
        val pair = f.jwt.createTokenPair(f.user, "phone")
        val first = assertIs<RefreshResult.Success>(f.jwt.refresh(pair.refreshToken))
        val second = assertIs<RefreshResult.Success>(f.jwt.refresh(first.tokenPair.refreshToken))

        f.clock.advance(Duration.ofSeconds(10))
        assertEquals(RefreshResult.FamilyRevoked, f.jwt.refresh(pair.refreshToken))
        assertEquals(RefreshResult.InvalidToken, f.jwt.refresh(second.tokenPair.refreshToken))
    }

    @Test
    fun `concurrent refreshes of one token converge on a single successor`(): Unit = Fixture().use { f ->
        val pair = f.jwt.createTokenPair(f.user, "phone")
        val pool = Executors.newFixedThreadPool(8)
        try {
            val results = pool.invokeAll((1..8).map { Callable { f.jwt.refresh(pair.refreshToken) } })
                .map { it.get() }
            val successors = results.map { assertIs<RefreshResult.Success>(it).tokenPair.refreshToken }.toSet()
            assertEquals(1, successors.size, "every racing refresh must get the same successor")
            assertEquals(1, f.activeTokenCount() - 1, "exactly one successor row besides the original")
        } finally {
            pool.shutdownNow()
        }
    }
}
