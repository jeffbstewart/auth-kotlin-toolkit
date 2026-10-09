package net.stewart.auth

import org.mindrot.jbcrypt.BCrypt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PasswordServiceTest {

    private fun violations(password: String) = PasswordService.validate(password, "someuser")

    @Test
    fun `72 ASCII bytes is accepted`() {
        assertTrue(violations("a".repeat(72)).isEmpty())
    }

    @Test
    fun `73 ASCII bytes is rejected`() {
        val v = violations("a".repeat(73))
        assertEquals(1, v.size)
        assertTrue(v.single().contains("72"), v.single())
    }

    @Test
    fun `limit counts UTF-8 bytes, not characters`() {
        // 36 two-byte characters = 72 bytes: accepted.
        assertTrue(violations("é".repeat(36)).isEmpty())
        // 25 three-byte characters = 75 bytes, only 25 characters: rejected.
        assertTrue(violations("€".repeat(25)).isNotEmpty())
    }

    @Test
    fun `hash refuses input bcrypt would silently truncate`() {
        PasswordService.hash("a".repeat(72))
        assertFailsWith<IllegalArgumentException> { PasswordService.hash("a".repeat(73)) }
    }

    @Test
    fun `existing hashes of over-long passwords still verify`() {
        // A hash created before the cap existed (directly via BCrypt) keeps working.
        val long = "x".repeat(100)
        val legacyHash = BCrypt.hashpw(long, BCrypt.gensalt(4))
        assertTrue(PasswordService.verify(long, legacyHash))
    }

    @Test
    fun `max length constant matches the byte cap`() {
        assertEquals(72, PasswordService.MAX_PASSWORD_BYTES)
        assertTrue(PasswordService.MAX_PASSWORD_LENGTH <= PasswordService.MAX_PASSWORD_BYTES)
    }
}
