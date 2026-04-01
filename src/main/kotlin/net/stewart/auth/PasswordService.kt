package net.stewart.auth

import org.mindrot.jbcrypt.BCrypt

/**
 * BCrypt password hashing with timing-safe verification and policy validation.
 */
object PasswordService {

    const val MAX_PASSWORD_LENGTH = 128
    const val MIN_PASSWORD_LENGTH = 8

    // Pre-computed hash for dummy BCrypt verification (timing equalization)
    private val DUMMY_HASH = BCrypt.hashpw("dummy", BCrypt.gensalt(12))

    /** Hash a plaintext password with BCrypt (cost factor 12). */
    fun hash(plaintext: String): String =
        BCrypt.hashpw(plaintext, BCrypt.gensalt(12))

    /** Verify a plaintext password against a BCrypt hash. */
    fun verify(plaintext: String, hash: String): Boolean =
        BCrypt.checkpw(plaintext, hash)

    /**
     * Performs a dummy BCrypt verification to equalize timing when the user
     * does not exist. Prevents account enumeration via timing analysis.
     */
    fun dummyVerify() {
        BCrypt.checkpw("dummy", DUMMY_HASH)
    }

    /**
     * Validates a password against policy rules. Returns a list of violation messages
     * (empty if the password is acceptable).
     */
    fun validate(password: String, username: String, currentHash: String? = null): List<String> {
        val violations = mutableListOf<String>()
        if (password.length < MIN_PASSWORD_LENGTH) {
            violations.add("Must be at least $MIN_PASSWORD_LENGTH characters")
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            violations.add("Must be at most $MAX_PASSWORD_LENGTH characters")
        }
        if (password.equals(username, ignoreCase = true)) {
            violations.add("Password cannot be the same as your username")
        }
        if (currentHash != null && verify(password, currentHash)) {
            violations.add("New password must be different from current password")
        }
        return violations
    }
}
