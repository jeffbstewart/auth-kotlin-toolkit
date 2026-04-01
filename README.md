# auth-kotlin-toolkit

A Kotlin authentication framework providing JWT tokens, cookie-based sessions, BCrypt password hashing, rate-limited login with exponential backoff, and account lockout. Designed for Kotlin web applications with no framework coupling — bring your own HTTP server and ORM.

## Features

- **Password hashing** — BCrypt with cost factor 12, timing-safe verification, dummy verify for account enumeration prevention
- **Cookie sessions** — SHA-256 hashed tokens, in-memory cache with configurable TTL, per-user session cap, automatic cleanup
- **Login with rate limiting** — per-IP and per-username failure tracking, exponential backoff (30s to 15min), daily failure cap, automatic account lockout
- **JWT authentication** — HMAC-SHA256 access tokens (15min default) with refresh token rotation, family-based theft detection, dual-key rotation support
- **No framework coupling** — works with Armeria, Ktor, Spring, or raw servlets. You implement `UserRepository` to bridge to your data layer.

## Quick Start

### 1. Add the dependency

**Composite build (recommended for development):**

```kotlin
// settings.gradle.kts
includeBuild("../auth-kotlin-toolkit")
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("net.stewart:auth-kotlin-toolkit:0.1.0")
}
```

**Or Maven Local:**

```bash
cd auth-kotlin-toolkit && ./gradlew publishToMavenLocal
```

### 2. Create the auth tables

Apply the migration in `src/main/resources/db/auth/V001__auth_tables.sql` to your database. If using Flyway, add `classpath:db/auth` to your migration locations.

### 3. Implement the user interface

```kotlin
import net.stewart.auth.AuthUser
import net.stewart.auth.UserRepository

// Your app's user entity implements AuthUser
data class AppUser(
    override val id: Long,
    override val username: String,
    override val passwordHash: String,
    override val isLocked: Boolean = false,
    override val mustChangePassword: Boolean = false,
    // ... your app-specific fields
) : AuthUser

// Bridge to your data layer
class AppUserRepository : UserRepository {
    override fun findById(id: Long): AuthUser? = /* your ORM/SQL */
    override fun findByUsername(username: String): AuthUser? = /* case-insensitive lookup */
    override fun hasUsers(): Boolean = /* count > 0 */
    override fun lockUser(id: Long) { /* set locked = true */ }
}
```

### 4. Wire up the services

```kotlin
val userRepo = AppUserRepository()
val dataSource = /* your HikariCP DataSource */

// Cookie-based sessions
val sessions = SessionService(
    dataSource = dataSource,
    userRepository = userRepo,
    cookieName = "my_session",   // default: "auth_session"
    sessionDays = 30L,           // default: 30
)

// Login with rate limiting
val login = LoginService(
    dataSource = dataSource,
    userRepository = userRepo,
)

// JWT (for mobile/API clients)
val jwt = JwtService(
    dataSource = dataSource,
    userRepository = userRepo,
    issuer = "myapp",
    audience = "myapp-api",
)
```

### 5. Use in your HTTP handlers

```kotlin
// Login endpoint
fun handleLogin(username: String, password: String, ip: String, userAgent: String): Response {
    return when (val result = login.login(username, password, ip)) {
        is LoginResult.Success -> {
            val token = sessions.createSession(result.user, userAgent)
            Response(200, headers = mapOf(
                "Set-Cookie" to sessions.buildCookieHeader(token, secure = true)
            ))
        }
        is LoginResult.RateLimited ->
            Response(429, body = """{"retry_after": ${result.retryAfterSeconds}}""")
        is LoginResult.Failed ->
            Response(401, body = """{"error": "Invalid credentials"}""")
    }
}

// Auth middleware (extract cookie → validate session)
fun authenticate(cookieToken: String?): AuthUser? {
    if (cookieToken == null) return null
    return sessions.validateToken(cookieToken)
}

// JWT login (for mobile)
fun handleJwtLogin(username: String, password: String, ip: String, deviceName: String): Response {
    return when (val result = login.login(username, password, ip)) {
        is LoginResult.Success -> {
            val pair = jwt.createTokenPair(result.user, deviceName)
            Response(200, body = """{"access_token":"${pair.accessToken}","expires_in":${pair.expiresIn}}""")
        }
        // ...
    }
}
```

## Configuration Reference

### SessionService

| Parameter | Default | Description |
|-----------|---------|-------------|
| `cookieName` | `"auth_session"` | Session cookie name |
| `sessionDays` | `30` | Session lifetime in days |
| `maxSessionsPerUser` | `10` | Max concurrent sessions |
| `cacheTtlSeconds` | `60` | Token cache TTL |

### LoginService

| Parameter | Default | Description |
|-----------|---------|-------------|
| `rateLimitWindowMinutes` | `15` | Sliding window for failure counts |
| `rateLimitThreshold` | `5` | Failures before backoff starts |
| `baseCooldownSeconds` | `30` | Initial backoff duration |
| `maxCooldownSeconds` | `900` | Maximum backoff (15 minutes) |
| `lockoutThreshold` | `20` | Failures before account lock |
| `dailyFailureCap` | `100` | Hard daily limit per IP/username |

### JwtService

| Parameter | Default | Description |
|-----------|---------|-------------|
| `issuer` | `"auth-toolkit"` | JWT issuer claim |
| `audience` | `"api"` | JWT audience claim |
| `accessTokenSeconds` | `900` | Access token lifetime (15 min) |
| `refreshTokenDays` | `30` | Refresh token lifetime |
| `configTableName` | `"auth_config"` | Table for signing key storage |
| `maxRefreshTokensPerUser` | `10` | Cap on active refresh tokens |

## Periodic Maintenance

Call these from a scheduled task (e.g., every 24 hours):

```kotlin
sessions.cleanupExpired()     // Delete expired session tokens
login.cleanupOldAttempts()    // Delete login attempts older than 30 days
jwt.cleanupExpired()          // Delete expired refresh tokens
```

## JWT Key Rotation

1. Copy current signing key to `signing_key_previous` in `auth_config` table
2. Delete the `signing_key` row (new key auto-generates on next use)
3. Restart the server
4. For 15 minutes, JWTs signed with either key are accepted
5. After access tokens expire, remove `signing_key_previous`

## Requirements

- JDK 21+
- Kotlin 2.x
- H2, PostgreSQL, or any JDBC-compatible database

## License

MIT
