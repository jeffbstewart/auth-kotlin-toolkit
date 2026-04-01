package net.stewart.auth

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.File
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Simple in-memory AuthUser for testing. */
data class TestUser(
    override val id: Long,
    override val username: String,
    override val passwordHash: String,
    override val isLocked: Boolean = false,
    override val mustChangePassword: Boolean = false,
) : AuthUser

/** In-memory user repository for testing. */
class TestUserRepository : UserRepository {
    val users = mutableMapOf<Long, TestUser>()

    override fun findById(id: Long): AuthUser? = users[id]
    override fun findByUsername(username: String): AuthUser? =
        users.values.firstOrNull { it.username.equals(username, ignoreCase = true) }
    override fun hasUsers(): Boolean = users.isNotEmpty()
    override fun lockUser(id: Long) {
        users[id]?.let { users[id] = it.copy(isLocked = true) }
    }
}

class AuthTest {

    private fun createTestDb(): Pair<DataSource, File> {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "auth-test-${System.nanoTime()}")
        tempDir.mkdirs()
        val ds = HikariDataSource(HikariConfig().apply {
            jdbcUrl = "jdbc:h2:mem:test-${System.nanoTime()};DB_CLOSE_DELAY=-1"
            username = "sa"
            password = ""
            maximumPoolSize = 5
        })
        // Run auth schema from SQL resource
        ds.connection.use { conn ->
            val sql = AuthTest::class.java.getResourceAsStream("/db/auth/V001__auth_tables.sql")!!
                .bufferedReader().readText()
            conn.createStatement().execute(sql)
        }
        return ds to tempDir
    }

    @Test
    fun `password hashing and verification`() {
        val hash = PasswordService.hash("mypassword")
        assertTrue(PasswordService.verify("mypassword", hash))
        assertTrue(!PasswordService.verify("wrong", hash))
    }

    @Test
    fun `password validation`() {
        assertTrue(PasswordService.validate("short", "user").isNotEmpty())
        assertTrue(PasswordService.validate("validpassword", "user").isEmpty())
        assertTrue(PasswordService.validate("user", "user").isNotEmpty()) // matches username
    }

    @Test
    fun `session create and validate`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "alice", PasswordService.hash("pass123"))
            repo.users[1] = user

            val sessions = SessionService(ds, repo)
            val token = sessions.createSession(user, "TestBrowser/1.0")
            assertNotNull(token)

            val validated = sessions.validateToken(token)
            assertNotNull(validated)
            assertEquals("alice", validated.username)

            // Revoke
            sessions.revokeByToken(token)
            assertNull(sessions.validateToken(token))
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `login with rate limiting`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "bob", PasswordService.hash("correct"))
            repo.users[1] = user

            val login = LoginService(ds, repo, rateLimitThreshold = 3)

            // Successful login
            val result = login.login("bob", "correct", "127.0.0.1")
            assertTrue(result is LoginResult.Success)

            // Failed logins
            login.login("bob", "wrong", "127.0.0.1")
            login.login("bob", "wrong", "127.0.0.1")
            login.login("bob", "wrong", "127.0.0.1")

            // Should now be rate limited
            val limited = login.login("bob", "correct", "127.0.0.1")
            assertTrue(limited is LoginResult.RateLimited)
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `JWT create and validate`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "carol", PasswordService.hash("pass"))
            repo.users[1] = user

            val jwt = JwtService(ds, repo)
            val pair = jwt.createTokenPair(user, "TestDevice")
            assertNotNull(pair.accessToken)
            assertNotNull(pair.refreshToken)

            val validated = jwt.validateAccessToken(pair.accessToken)
            assertNotNull(validated)
            assertEquals("carol", validated.username)
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }
}
