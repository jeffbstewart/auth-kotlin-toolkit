@file:Suppress("DEPRECATION") // AuthenticatorImpl is deprecated but is the only Authenticator impl in webauthn4j

package net.stewart.auth

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.authenticator.AuthenticatorImpl
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.*
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.verifier.exception.VerificationException
import org.jdbi.v3.core.Jdbi
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.time.Instant
import java.time.LocalDateTime
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource

/**
 * Configuration for WebAuthn relying party.
 *
 * @param rpId The relying party identifier — the domain users access the site from (e.g., "mm.example.com")
 * @param rpOrigin The full origin URL including protocol and port if non-standard (e.g., "https://mm.example.com:8443").
 *                 If null, defaults to "https://{rpId}" (standard port 443) or "http://localhost:4200" for localhost.
 * @param rpName Display name shown in browser passkey prompts (default: "Application")
 */
data class WebAuthnConfig(
    val rpId: String,
    val rpOrigin: String? = null,
    val rpName: String = "Application",
)

/**
 * A stored passkey credential returned from registration and credential queries.
 */
data class PasskeyCredentialRecord(
    val id: Long,
    val userId: Long,
    val credentialId: String,
    val displayName: String,
    val createdAt: LocalDateTime?,
    val lastUsedAt: LocalDateTime?,
)

/** Result of WebAuthn registration. */
sealed class WebAuthnRegisterResult {
    data class Success(val credential: PasskeyCredentialRecord) : WebAuthnRegisterResult()
    data class Failed(val reason: String) : WebAuthnRegisterResult()
}

/** Result of WebAuthn authentication. */
sealed class WebAuthnAuthResult {
    data class Success(val user: AuthUser) : WebAuthnAuthResult()
    data class Failed(val reason: String) : WebAuthnAuthResult()
}

/**
 * Registration options returned to the client for the WebAuthn registration ceremony.
 * The client passes `optionsJson` to `navigator.credentials.create()` and returns the
 * signed challenge alongside the credential response for verification.
 */
data class RegistrationOptionsResponse(
    val signedChallenge: String,
    val optionsJson: Map<String, Any?>,
)

/**
 * Authentication options returned to the client for the WebAuthn authentication ceremony.
 * The client passes `optionsJson` to `navigator.credentials.get()` and returns the
 * signed challenge alongside the credential response for verification.
 */
data class AuthenticationOptionsResponse(
    val signedChallenge: String,
    val optionsJson: Map<String, Any?>,
)

/**
 * WebAuthn/passkey service for registration and authentication ceremonies.
 *
 * Challenges are stateless: a random challenge + metadata is HMAC-signed with the
 * signing key and returned to the client as an opaque token. On verification, the
 * server validates the HMAC and checks the 5-minute TTL.
 *
 * Framework-agnostic: takes config as a data class, uses JDBI for database access.
 * Consumers are responsible for wiring this into their HTTP framework.
 *
 * @param dataSource JDBC DataSource for passkey credential storage
 * @param userRepository User lookup for authentication verification
 * @param signingKeyProvider Returns the raw HMAC signing key bytes (typically from [JwtService])
 * @param config Relying party configuration (domain, origin, display name)
 * @param challengeTtlSeconds How long a challenge is valid (default: 300 = 5 minutes)
 */
class WebAuthnService(
    private val dataSource: DataSource,
    private val userRepository: UserRepository,
    private val signingKeyProvider: () -> ByteArray,
    private val config: WebAuthnConfig,
    private val challengeTtlSeconds: Int = 300,
) {
    private val log = LoggerFactory.getLogger(WebAuthnService::class.java)
    private val jdbi = Jdbi.create(dataSource)
    private val random = SecureRandom()
    private val objectConverter = ObjectConverter()
    private val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
    private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

    // --- Registration ---

    /**
     * Generates WebAuthn registration options for a user.
     *
     * @param userId The user's ID (bound into the signed challenge)
     * @param username The user's login name (included in the WebAuthn options)
     * @param userDisplayName A human-readable name for the user
     * @return Options to pass to the client's `navigator.credentials.create()`
     */
    fun generateRegistrationOptions(userId: Long, username: String, userDisplayName: String): RegistrationOptionsResponse {
        val challenge = randomChallenge()
        val signedChallenge = signChallenge(challenge, userId = userId, purpose = "register")

        val existing = findCredentialsByUserId(userId)
        val excludeCredentials = existing.map { cred ->
            mapOf(
                "type" to "public-key",
                "id" to cred.credentialId,
            )
        }

        val options = mapOf(
            "rp" to mapOf("name" to config.rpName, "id" to config.rpId),
            "user" to mapOf(
                "id" to base64UrlEncode(userId.toString().toByteArray()),
                "name" to username,
                "displayName" to userDisplayName,
            ),
            "challenge" to base64UrlEncode(challenge),
            "pubKeyCredParams" to listOf(
                mapOf("alg" to -7, "type" to "public-key"),   // ES256
                mapOf("alg" to -257, "type" to "public-key"), // RS256
            ),
            "timeout" to 300000,
            "attestation" to "none",
            "authenticatorSelection" to mapOf(
                "residentKey" to "preferred",
                "requireResidentKey" to false,
                "userVerification" to "preferred",
            ),
            "excludeCredentials" to excludeCredentials,
        )

        return RegistrationOptionsResponse(signedChallenge, options)
    }

    /**
     * Verifies a registration response and stores the new credential.
     *
     * @param signedChallenge The opaque challenge token from [generateRegistrationOptions]
     * @param credentialId Base64URL-encoded credential ID from the authenticator response
     * @param clientDataJSON Base64URL-encoded clientDataJSON from `credential.response`
     * @param attestationObject Base64URL-encoded attestationObject from `credential.response`
     * @param transports Comma-separated transport hints (e.g., "internal,hybrid"), or null
     * @param displayName User-chosen name for this passkey
     * @param userId The authenticated user's ID (must match the challenge)
     */
    fun verifyRegistration(
        signedChallenge: String,
        credentialId: String,
        clientDataJSON: String,
        attestationObject: String,
        transports: String?,
        displayName: String,
        userId: Long,
    ): WebAuthnRegisterResult {
        val challengeData: ChallengePayload
        try {
            challengeData = verifyAndDecodeChallenge(signedChallenge, purpose = "register")
        } catch (e: IllegalArgumentException) {
            return WebAuthnRegisterResult.Failed("Invalid challenge: ${e.message}")
        }

        if (challengeData.userId != userId) {
            return WebAuthnRegisterResult.Failed("Challenge user mismatch")
        }

        val challengeBytes = base64UrlDecode(challengeData.challenge)

        val registrationRequest = RegistrationRequest(
            base64UrlDecode(attestationObject),
            base64UrlDecode(clientDataJSON),
        )

        val origin = determineOrigin()
        val serverProperty = ServerProperty(origin, config.rpId, DefaultChallenge(challengeBytes), null)
        val registrationParameters = RegistrationParameters(serverProperty, null, false, true)

        val registrationData = try {
            webAuthnManager.verify(registrationRequest, registrationParameters)
        } catch (e: VerificationException) {
            log.warn("WebAuthn registration verification failed: {}", e.message)
            return WebAuthnRegisterResult.Failed("Verification failed")
        } catch (e: Exception) {
            log.warn("WebAuthn registration parse failed: {}", e.message)
            return WebAuthnRegisterResult.Failed("Invalid response")
        }

        val attestedData = registrationData.attestationObject?.authenticatorData?.attestedCredentialData
            ?: return WebAuthnRegisterResult.Failed("No attested credential data")

        val publicKeyBytes = attestedCredentialDataConverter.convert(attestedData)
        val signCount = registrationData.attestationObject!!.authenticatorData.signCount
        val safeName = displayName.take(255).ifBlank { "Passkey" }
        val now = LocalDateTime.now()

        val id = jdbi.withHandle<Long, Exception> { handle ->
            handle.createUpdate(
                """INSERT INTO passkey_credential (user_id, credential_id, public_key, sign_count, transports, display_name, created_at)
                   VALUES (:uid, :cid, :pk, :sc, :tr, :dn, :now)"""
            )
                .bind("uid", userId)
                .bind("cid", credentialId)
                .bind("pk", publicKeyBytes)
                .bind("sc", signCount)
                .bind("tr", transports?.takeIf { it.isNotBlank() })
                .bind("dn", safeName)
                .bind("now", now)
                .executeAndReturnGeneratedKeys("id")
                .mapTo(Long::class.java)
                .one()
        }

        log.info("AUDIT: Passkey registered for user_id={} credentialId={}...{}",
            userId, credentialId.take(8), credentialId.takeLast(4))

        return WebAuthnRegisterResult.Success(PasskeyCredentialRecord(
            id = id, userId = userId, credentialId = credentialId,
            displayName = safeName, createdAt = now, lastUsedAt = null,
        ))
    }

    // --- Authentication ---

    /**
     * Generates WebAuthn authentication options.
     * Uses discoverable credentials (empty allowCredentials) to avoid username enumeration.
     */
    fun generateAuthenticationOptions(): AuthenticationOptionsResponse {
        val challenge = randomChallenge()
        val signedChallenge = signChallenge(challenge, userId = null, purpose = "authenticate")

        val options = mapOf(
            "challenge" to base64UrlEncode(challenge),
            "timeout" to 300000,
            "rpId" to config.rpId,
            "userVerification" to "preferred",
            "allowCredentials" to emptyList<Any>(),
        )

        return AuthenticationOptionsResponse(signedChallenge, options)
    }

    /**
     * Verifies an authentication response and returns the authenticated user.
     *
     * @param signedChallenge The opaque challenge token from [generateAuthenticationOptions]
     * @param credentialId Base64URL-encoded credential ID from the authenticator
     * @param clientDataJSON Base64URL-encoded clientDataJSON from `credential.response`
     * @param authenticatorData Base64URL-encoded authenticatorData from `credential.response`
     * @param signature Base64URL-encoded signature from `credential.response`
     * @param userHandle Base64URL-encoded user handle from `credential.response`, or null
     */
    fun verifyAuthentication(
        signedChallenge: String,
        credentialId: String,
        clientDataJSON: String,
        authenticatorData: String,
        signature: String,
        userHandle: String?,
    ): WebAuthnAuthResult {
        val challengeData: ChallengePayload
        try {
            challengeData = verifyAndDecodeChallenge(signedChallenge, purpose = "authenticate")
        } catch (e: IllegalArgumentException) {
            return WebAuthnAuthResult.Failed("Invalid challenge: ${e.message}")
        }

        val challengeBytes = base64UrlDecode(challengeData.challenge)

        // Look up the credential via indexed query
        data class StoredCredential(
            val id: Long, val userId: Long, val publicKey: ByteArray, val signCount: Long
        )

        val stored = jdbi.withHandle<StoredCredential?, Exception> { handle ->
            handle.createQuery(
                "SELECT id, user_id, public_key, sign_count FROM passkey_credential WHERE credential_id = :cid"
            ).bind("cid", credentialId)
                .map { rs, _ ->
                    StoredCredential(
                        rs.getLong("id"), rs.getLong("user_id"),
                        rs.getBytes("public_key"), rs.getLong("sign_count"),
                    )
                }.firstOrNull()
        } ?: return WebAuthnAuthResult.Failed("Unknown credential")

        val attestedCredentialData = attestedCredentialDataConverter.convert(stored.publicKey)
        val authenticator = AuthenticatorImpl(attestedCredentialData, null, stored.signCount)

        val authenticationRequest = AuthenticationRequest(
            base64UrlDecode(credentialId),
            base64UrlDecode(userHandle ?: ""),
            base64UrlDecode(authenticatorData),
            base64UrlDecode(clientDataJSON),
            null,
            base64UrlDecode(signature),
        )

        val origin = determineOrigin()
        val serverProperty = ServerProperty(origin, config.rpId, DefaultChallenge(challengeBytes), null)
        val authenticationParameters = AuthenticationParameters(serverProperty, authenticator, null, true)

        val authenticationResultData = try {
            webAuthnManager.verify(authenticationRequest, authenticationParameters)
        } catch (e: VerificationException) {
            log.warn("WebAuthn authentication verification failed for credential {}...{}: {}",
                credentialId.take(8), credentialId.takeLast(4), e.message)
            return WebAuthnAuthResult.Failed("Verification failed")
        } catch (e: Exception) {
            log.warn("WebAuthn authentication parse failed for credential {}...{}: {}",
                credentialId.take(8), credentialId.takeLast(4), e.message)
            return WebAuthnAuthResult.Failed("Invalid response")
        }

        // Update sign count and last used
        val newSignCount = authenticationResultData.authenticatorData!!.signCount
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate(
                "UPDATE passkey_credential SET sign_count = :sc, last_used_at = :now WHERE id = :id"
            ).bind("sc", newSignCount).bind("now", LocalDateTime.now()).bind("id", stored.id).execute()
        }

        val user = userRepository.findById(stored.userId)
            ?: return WebAuthnAuthResult.Failed("User not found")

        if (user.isLocked) {
            log.warn("AUDIT: Passkey authentication blocked — user '{}' is locked", user.username)
            return WebAuthnAuthResult.Failed("Account locked")
        }

        log.info("AUDIT: Passkey authentication succeeded for user '{}' (credential {}...{})",
            user.username, credentialId.take(8), credentialId.takeLast(4))
        return WebAuthnAuthResult.Success(user)
    }

    // --- Credential Management ---

    /** List all passkey credentials for a user. */
    fun listCredentials(userId: Long): List<PasskeyCredentialRecord> =
        jdbi.withHandle<List<PasskeyCredentialRecord>, Exception> { handle ->
            handle.createQuery(
                "SELECT id, user_id, credential_id, display_name, created_at, last_used_at FROM passkey_credential WHERE user_id = :uid ORDER BY created_at"
            ).bind("uid", userId)
                .map { rs, _ ->
                    PasskeyCredentialRecord(
                        rs.getLong("id"), rs.getLong("user_id"), rs.getString("credential_id"),
                        rs.getString("display_name"),
                        rs.getTimestamp("created_at")?.toLocalDateTime(),
                        rs.getTimestamp("last_used_at")?.toLocalDateTime(),
                    )
                }.list()
        }

    /** Delete a single credential by ID, only if owned by the specified user. Returns true if deleted. */
    fun deleteCredential(credentialId: Long, userId: Long): Boolean {
        val deleted = jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM passkey_credential WHERE id = :id AND user_id = :uid")
                .bind("id", credentialId).bind("uid", userId).execute()
        }
        if (deleted > 0) log.info("AUDIT: Passkey deleted id={} for user_id={}", credentialId, userId)
        return deleted > 0
    }

    /** Delete all credentials for a user. Returns the count deleted. */
    fun deleteAllCredentials(userId: Long): Int {
        val deleted = jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM passkey_credential WHERE user_id = :uid")
                .bind("uid", userId).execute()
        }
        if (deleted > 0) log.info("AUDIT: All {} passkeys deleted for user_id={}", deleted, userId)
        return deleted
    }

    /** Delete a single credential by ID (admin — no ownership check). Returns true if deleted. */
    fun adminDeleteCredential(credentialId: Long): Boolean {
        val deleted = jdbi.withHandle<Int, Exception> { handle ->
            handle.createUpdate("DELETE FROM passkey_credential WHERE id = :id")
                .bind("id", credentialId).execute()
        }
        if (deleted > 0) log.info("AUDIT: Admin deleted passkey id={}", credentialId)
        return deleted > 0
    }

    /** Check if any passkeys exist in the database. */
    fun anyPasskeysExist(): Boolean =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery("SELECT COUNT(*) FROM passkey_credential")
                .mapTo(Int::class.java).one()
        } > 0

    /** Check if a specific user has any passkeys. */
    fun hasPasskeys(userId: Long): Boolean =
        jdbi.withHandle<Int, Exception> { handle ->
            handle.createQuery("SELECT COUNT(*) FROM passkey_credential WHERE user_id = :uid")
                .bind("uid", userId).mapTo(Int::class.java).one()
        } > 0

    // --- Challenge HMAC ---

    private data class ChallengePayload(
        val challenge: String,
        val timestamp: Long,
        val purpose: String,
        val userId: Long?,
    )

    private fun signChallenge(challenge: ByteArray, userId: Long?, purpose: String): String {
        // Simple format: challenge|timestamp|purpose[|userId]
        val parts = mutableListOf(
            base64UrlEncode(challenge),
            Instant.now().epochSecond.toString(),
            purpose,
        )
        userId?.let { parts.add(it.toString()) }
        val payload = parts.joinToString("|")
        val payloadBytes = payload.toByteArray()
        val mac = hmacSha256(payloadBytes)
        return base64UrlEncode(payloadBytes) + "." + base64UrlEncode(mac)
    }

    private fun verifyAndDecodeChallenge(signedChallenge: String, purpose: String): ChallengePayload {
        val dotIndex = signedChallenge.indexOf('.')
        if (dotIndex < 0) throw IllegalArgumentException("Invalid challenge format")

        val payloadBytes = base64UrlDecode(signedChallenge.substring(0, dotIndex))
        val expectedMac = base64UrlDecode(signedChallenge.substring(dotIndex + 1))
        val actualMac = hmacSha256(payloadBytes)

        if (!constantTimeEquals(expectedMac, actualMac)) {
            throw IllegalArgumentException("Challenge signature invalid")
        }

        val payload = String(payloadBytes)
        val parts = payload.split("|")
        if (parts.size < 3) throw IllegalArgumentException("Invalid challenge payload")

        val timestamp = parts[1].toLongOrNull() ?: throw IllegalArgumentException("Invalid timestamp")
        val elapsed = Instant.now().epochSecond - timestamp
        if (elapsed < 0 || elapsed > challengeTtlSeconds) {
            throw IllegalArgumentException("Challenge expired")
        }

        if (parts[2] != purpose) {
            throw IllegalArgumentException("Challenge purpose mismatch")
        }

        return ChallengePayload(
            challenge = parts[0],
            timestamp = timestamp,
            purpose = parts[2],
            userId = parts.getOrNull(3)?.toLongOrNull(),
        )
    }

    private fun hmacSha256(data: ByteArray): ByteArray {
        val key = signingKeyProvider()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    // --- Origin ---

    private fun determineOrigin(): Origin {
        config.rpOrigin?.let { return Origin.create(it) }
        return if (config.rpId == "localhost") {
            Origin.create("http://localhost:4200")
        } else {
            Origin.create("https://${config.rpId}")
        }
    }

    // --- Helpers ---

    private fun randomChallenge(): ByteArray =
        ByteArray(32).also { random.nextBytes(it) }

    private fun findCredentialsByUserId(userId: Long): List<PasskeyCredentialRecord> =
        listCredentials(userId)

    private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val base64UrlDecoder = Base64.getUrlDecoder()

    private fun base64UrlEncode(bytes: ByteArray): String = base64UrlEncoder.encodeToString(bytes)
    private fun base64UrlDecode(str: String): ByteArray = base64UrlDecoder.decode(str)
}
