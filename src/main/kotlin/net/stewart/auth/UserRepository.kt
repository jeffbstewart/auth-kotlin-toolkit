package net.stewart.auth

/**
 * Interface for user persistence operations. Consumers implement this
 * to bridge the auth framework to their own data layer (ORM, JDBI, etc.).
 */
interface UserRepository {
    /** Find a user by ID. */
    fun findById(id: Long): AuthUser?

    /** Find a user by username (case-insensitive). */
    fun findByUsername(username: String): AuthUser?

    /** Returns true if any users exist. */
    fun hasUsers(): Boolean

    /** Lock a user account (set isLocked = true). */
    fun lockUser(id: Long)
}
