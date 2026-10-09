package net.stewart.auth

import org.jdbi.v3.core.Jdbi
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WebAuthnChallengeReplayTest {

    private class Fixture(storeFactory: (Fixture) -> ConsumedChallengeStore? = { null }) : AutoCloseable {
        val ds = createAuthTestDb()
        val clock = MutableClock()
        val repo = TestUserRepository().also {
            it.users[1] = TestUser(1, "dave", PasswordService.hash("password1"))
        }
        val jwt = JwtService(ds, repo, clock = clock)
        val store = storeFactory(this)
        val webauthn = if (store == null) {
            WebAuthnService(ds, repo, { jwt.signingKeyBytes() }, WebAuthnConfig(rpId = "localhost"), clock = clock)
        } else {
            WebAuthnService(ds, repo, { jwt.signingKeyBytes() }, WebAuthnConfig(rpId = "localhost"),
                clock = clock, consumedChallengeStore = store)
        }

        fun authenticate(signedChallenge: String) = webauthn.verifyAuthentication(
            signedChallenge = signedChallenge,
            credentialId = "nonexistent-credential",
            clientDataJSON = "fake",
            authenticatorData = "fake",
            signature = "fake",
            userHandle = null,
        )

        override fun close() = ds.close()
    }

    @Test
    fun `authentication challenge cannot be used twice`(): Unit = Fixture().use { f ->
        val challenge = f.webauthn.generateAuthenticationOptions().signedChallenge

        val first = assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge))
        assertEquals("Unknown credential", first.reason, "first use passes the challenge check")

        val replay = assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge))
        assertTrue(replay.reason.contains("already used"), "replay must be rejected: ${replay.reason}")
    }

    @Test
    fun `registration challenge cannot be used twice`(): Unit = Fixture().use { f ->
        val challenge = f.webauthn.generateRegistrationOptions(1, "dave", "Dave").signedChallenge
        fun register() = f.webauthn.verifyRegistration(challenge, "cred", "e30", "AA", null, "Key", 1)

        val first = assertIs<WebAuthnRegisterResult.Failed>(register())
        assertFalse(first.reason.contains("challenge", ignoreCase = true), "first use passes: ${first.reason}")
        val replay = assertIs<WebAuthnRegisterResult.Failed>(register())
        assertTrue(replay.reason.contains("already used"), "replay must be rejected: ${replay.reason}")
    }

    @Test
    fun `fresh challenges remain usable`(): Unit = Fixture().use { f ->
        repeat(3) {
            val challenge = f.webauthn.generateAuthenticationOptions().signedChallenge
            assertEquals("Unknown credential", assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge)).reason)
        }
    }

    @Test
    fun `concurrent replays admit exactly one use`(): Unit = Fixture().use { f ->
        val challenge = f.webauthn.generateAuthenticationOptions().signedChallenge
        val pool = Executors.newFixedThreadPool(8)
        try {
            val reasons = pool.invokeAll((1..16).map { Callable { f.authenticate(challenge) } })
                .map { assertIs<WebAuthnAuthResult.Failed>(it.get()).reason }
            assertEquals(1, reasons.count { it == "Unknown credential" })
            assertEquals(15, reasons.count { it.contains("already used") })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `expired challenge is rejected as expired`(): Unit = Fixture().use { f ->
        val challenge = f.webauthn.generateAuthenticationOptions().signedChallenge
        f.clock.advance(Duration.ofSeconds(301))
        val result = assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge))
        assertTrue(result.reason.contains("expired"), result.reason)
    }

    @Test
    fun `in-memory store forgets entries once they expire`() {
        val clock = MutableClock()
        val store = InMemoryConsumedChallengeStore(clock)
        val expiry = clock.instant().plusSeconds(300)

        assertTrue(store.markConsumed("a", expiry))
        assertFalse(store.markConsumed("a", expiry))
        assertTrue(store.markConsumed("b", expiry))
        assertEquals(2, store.size())

        clock.advance(Duration.ofSeconds(301))
        store.purgeExpired()
        assertEquals(0, store.size())
    }

    @Test
    fun `in-memory store purges expired entries as new ones arrive`() {
        val clock = MutableClock()
        val store = InMemoryConsumedChallengeStore(clock)
        store.markConsumed("old", clock.instant().plusSeconds(300))
        clock.advance(Duration.ofSeconds(301))
        store.markConsumed("new", clock.instant().plusSeconds(300))
        assertEquals(1, store.size())
    }

    @Test
    fun `database store rejects replay and purges expired rows`() {
        Fixture({ JdbcConsumedChallengeStore(it.ds, it.clock) }).use { f ->
            val challenge = f.webauthn.generateAuthenticationOptions().signedChallenge
            assertEquals("Unknown credential", assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge)).reason)
            assertTrue(assertIs<WebAuthnAuthResult.Failed>(f.authenticate(challenge)).reason.contains("already used"))

            fun rows() = Jdbi.create(f.ds).withHandle<Int, Exception> { h ->
                h.createQuery("SELECT COUNT(*) FROM webauthn_consumed_challenge").mapTo(Int::class.java).one()
            }
            assertEquals(1, rows())

            f.clock.advance(Duration.ofSeconds(301))
            (f.store as JdbcConsumedChallengeStore).purgeExpired()
            assertEquals(0, rows())
        }
    }
}
