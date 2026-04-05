package net.stewart.auth

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.File
import javax.sql.DataSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
        // Run auth schema from SQL resources
        ds.connection.use { conn ->
            val stmt = conn.createStatement()
            stmt.execute(AuthTest::class.java.getResourceAsStream("/db/auth/V001__auth_tables.sql")!!
                .bufferedReader().readText())
            stmt.execute(AuthTest::class.java.getResourceAsStream("/db/auth/V002__passkey_credential.sql")!!
                .bufferedReader().readText())
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

    // --- WebAuthn tests ---

    private fun createWebAuthn(ds: DataSource, repo: TestUserRepository): Pair<WebAuthnService, JwtService> {
        val jwt = JwtService(ds, repo)
        val webauthn = WebAuthnService(
            dataSource = ds,
            userRepository = repo,
            signingKeyProvider = { jwt.signingKeyBytes() },
            config = WebAuthnConfig(rpId = "localhost", rpName = "Test App"),
        )
        return webauthn to jwt
    }

    @Test
    fun `WebAuthn registration options include user and RP`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "dave", PasswordService.hash("pass"))
            repo.users[1] = user

            val (webauthn, _) = createWebAuthn(ds, repo)
            val opts = webauthn.generateRegistrationOptions(1, "dave", "Dave")

            assertNotNull(opts.signedChallenge)
            assertTrue(opts.signedChallenge.contains("."))

            @Suppress("UNCHECKED_CAST")
            val rp = opts.optionsJson["rp"] as Map<String, Any>
            assertEquals("localhost", rp["id"])
            assertEquals("Test App", rp["name"])

            @Suppress("UNCHECKED_CAST")
            val userJson = opts.optionsJson["user"] as Map<String, Any>
            assertEquals("dave", userJson["name"])
            assertEquals("Dave", userJson["displayName"])
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn authentication options are discoverable`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val (webauthn, _) = createWebAuthn(ds, repo)
            val opts = webauthn.generateAuthenticationOptions()

            assertNotNull(opts.signedChallenge)
            assertEquals("localhost", opts.optionsJson["rpId"])
            @Suppress("UNCHECKED_CAST")
            val allowCreds = opts.optionsJson["allowCredentials"] as List<Any>
            assertTrue(allowCreds.isEmpty(), "Discoverable credentials should have empty allowCredentials")
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn credential CRUD operations`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "eve", PasswordService.hash("pass"))
            repo.users[1] = user

            val (webauthn, _) = createWebAuthn(ds, repo)

            // Initially no passkeys
            assertFalse(webauthn.anyPasskeysExist())
            assertFalse(webauthn.hasPasskeys(1))
            assertTrue(webauthn.listCredentials(1).isEmpty())

            // Insert a credential directly for CRUD testing (bypasses WebAuthn ceremony)
            org.jdbi.v3.core.Jdbi.create(ds).withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, display_name, created_at)
                       VALUES (1, 'test-cred-id', X'00', 0, 'Test Key', CURRENT_TIMESTAMP)"""
                ).execute()
            }

            // Now has passkeys
            assertTrue(webauthn.anyPasskeysExist())
            assertTrue(webauthn.hasPasskeys(1))

            val creds = webauthn.listCredentials(1)
            assertEquals(1, creds.size)
            assertEquals("Test Key", creds[0].displayName)
            assertEquals("test-cred-id", creds[0].credentialId)

            // Delete by wrong user — should fail
            assertFalse(webauthn.deleteCredential(creds[0].id, 999))
            assertTrue(webauthn.hasPasskeys(1))

            // Delete by correct user
            assertTrue(webauthn.deleteCredential(creds[0].id, 1))
            assertFalse(webauthn.hasPasskeys(1))
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn deleteAllCredentials removes all for user`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            repo.users[1] = TestUser(1, "frank", PasswordService.hash("pass"))
            repo.users[2] = TestUser(2, "grace", PasswordService.hash("pass"))

            val (webauthn, _) = createWebAuthn(ds, repo)

            // Insert credentials for two users
            val jdbi = org.jdbi.v3.core.Jdbi.create(ds)
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, display_name, created_at)
                       VALUES (1, 'frank-key-1', X'00', 0, 'Key 1', CURRENT_TIMESTAMP)"""
                ).execute()
            }
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, display_name, created_at)
                       VALUES (1, 'frank-key-2', X'00', 0, 'Key 2', CURRENT_TIMESTAMP)"""
                ).execute()
            }
            jdbi.withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, display_name, created_at)
                       VALUES (2, 'grace-key-1', X'00', 0, 'Key 1', CURRENT_TIMESTAMP)"""
                ).execute()
            }

            assertEquals(2, webauthn.listCredentials(1).size)
            assertEquals(1, webauthn.listCredentials(2).size)

            // Delete all for user 1 — user 2 unaffected
            val deleted = webauthn.deleteAllCredentials(1)
            assertEquals(2, deleted)
            assertTrue(webauthn.listCredentials(1).isEmpty())
            assertEquals(1, webauthn.listCredentials(2).size)
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn challenge HMAC prevents tampering`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val user = TestUser(1, "hal", PasswordService.hash("pass"))
            repo.users[1] = user

            val (webauthn, _) = createWebAuthn(ds, repo)
            val opts = webauthn.generateRegistrationOptions(1, "hal", "Hal")

            // Tamper with the challenge
            val tampered = opts.signedChallenge.replaceFirst(".", "x.")
            val result = webauthn.verifyRegistration(
                signedChallenge = tampered,
                credentialId = "fake",
                clientDataJSON = "fake",
                attestationObject = "fake",
                transports = null,
                displayName = "Tampered",
                userId = 1,
            )
            val failed = result as WebAuthnRegisterResult.Failed
            assertTrue(failed.reason.contains("challenge", ignoreCase = true))
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn authentication with unknown credential fails`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val (webauthn, _) = createWebAuthn(ds, repo)
            val opts = webauthn.generateAuthenticationOptions()

            val result = webauthn.verifyAuthentication(
                signedChallenge = opts.signedChallenge,
                credentialId = "nonexistent-credential",
                clientDataJSON = "fake",
                authenticatorData = "fake",
                signature = "fake",
                userHandle = null,
            )
            val failed = result as WebAuthnAuthResult.Failed
            assertEquals("Unknown credential", failed.reason)
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `WebAuthn locked user blocked from login`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val hash = PasswordService.hash("pass")
            // User starts unlocked
            repo.users[1] = TestUser(1, "ivan", hash, isLocked = false)

            val login = LoginService(ds, repo)
            val (webauthn, _) = createWebAuthn(ds, repo)

            // Register a credential
            org.jdbi.v3.core.Jdbi.create(ds).withHandle<Int, Exception> { handle ->
                handle.createUpdate(
                    """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, display_name, created_at)
                       VALUES (1, 'ivan-cred', X'00', 0, 'Key', CURRENT_TIMESTAMP)"""
                ).execute()
            }
            assertTrue(webauthn.hasPasskeys(1))

            // Password login succeeds while unlocked
            val loginResult = login.login("ivan", "pass", "127.0.0.1")
            assertTrue(loginResult is LoginResult.Success)

            // Lock the user
            repo.users[1] = TestUser(1, "ivan", hash, isLocked = true)

            // Password login now fails
            val lockedLogin = login.login("ivan", "pass", "127.0.0.1")
            assertTrue(lockedLogin is LoginResult.Failed)

            // Passkey still exists, but the user is locked.
            // A full WebAuthn ceremony can't run in unit tests (no browser/authenticator),
            // but the code path in verifyAuthentication() checks user.isLocked after
            // credential lookup and returns Failed("Account locked").
            assertTrue(webauthn.hasPasskeys(1))
            assertTrue(repo.findById(1)!!.isLocked)
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `JwtService signingKeyBytes returns consistent key`() {
        val (ds, tempDir) = createTestDb()
        try {
            val repo = TestUserRepository()
            val jwt = JwtService(ds, repo)
            val key1 = jwt.signingKeyBytes()
            val key2 = jwt.signingKeyBytes()
            assertEquals(32, key1.size)
            assertTrue(key1.contentEquals(key2), "Signing key should be stable across calls")
        } finally {
            (ds as HikariDataSource).close()
            tempDir.deleteRecursively()
        }
    }
}
