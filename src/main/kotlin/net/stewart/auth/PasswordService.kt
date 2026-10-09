package net.stewart.auth

import org.mindrot.jbcrypt.BCrypt

/**
 * BCrypt password hashing with timing-safe verification and policy validation.
 */
object PasswordService {

    /**
     * BCrypt only consumes the first 72 bytes of its input; anything beyond is
     * silently ignored. Passwords are capped here so that every byte a user
     * types is part of the hash.
     */
    const val MAX_PASSWORD_BYTES = 72

    /**
     * Maximum length in characters. Equal to [MAX_PASSWORD_BYTES] because a
     * character is at least one UTF-8 byte; non-ASCII passwords hit the byte
     * cap sooner, which [validate] reports.
     */
    const val MAX_PASSWORD_LENGTH = MAX_PASSWORD_BYTES
    const val MIN_PASSWORD_LENGTH = 8

    // Pre-computed hash for dummy BCrypt verification (timing equalization)
    private val DUMMY_HASH = BCrypt.hashpw("dummy", BCrypt.gensalt(12))

    /**
     * Hash a plaintext password with BCrypt (cost factor 12).
     *
     * @throws IllegalArgumentException if the password exceeds [MAX_PASSWORD_BYTES]
     *   when UTF-8 encoded (BCrypt would otherwise silently truncate it).
     *   Call [validate] first to get a user-facing message.
     */
    fun hash(plaintext: String): String {
        require(utf8Length(plaintext) <= MAX_PASSWORD_BYTES) {
            "Password exceeds $MAX_PASSWORD_BYTES bytes when UTF-8 encoded"
        }
        return BCrypt.hashpw(plaintext, BCrypt.gensalt(12))
    }

    /**
     * Verify a plaintext password against a BCrypt hash. Not length-capped, so
     * hashes created before the cap existed continue to verify.
     */
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
        if (utf8Length(password) > MAX_PASSWORD_BYTES) {
            violations.add("Must be at most $MAX_PASSWORD_BYTES bytes (fewer characters if using non-ASCII characters)")
        }
        if (password.equals(username, ignoreCase = true)) {
            violations.add("Password cannot be the same as your username")
        }
        if (currentHash != null && verify(password, currentHash)) {
            violations.add("New password must be different from current password")
        }
        return violations
    }

    private fun utf8Length(s: String): Int = s.toByteArray(Charsets.UTF_8).size
}
