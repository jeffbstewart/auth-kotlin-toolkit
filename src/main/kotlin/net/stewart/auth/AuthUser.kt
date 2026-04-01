package net.stewart.auth

/**
 * Minimal user interface for the auth framework.
 * Consumers implement this on their own user entity/model.
 */
interface AuthUser {
    val id: Long
    val username: String
    val passwordHash: String
    val isLocked: Boolean
    val mustChangePassword: Boolean
}
