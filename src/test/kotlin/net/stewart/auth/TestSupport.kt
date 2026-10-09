package net.stewart.auth

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId

/** A [Clock] whose time only moves when a test advances it. Thread-safe. */
class MutableClock(
    @Volatile private var now: Instant = Instant.parse("2026-01-15T12:00:00Z"),
    private val zone: ZoneId = ZoneId.of("UTC"),
) : Clock() {
    override fun getZone(): ZoneId = zone
    override fun withZone(zone: ZoneId): Clock = MutableClock(now, zone)
    override fun instant(): Instant = now

    fun advance(by: Duration) {
        now = now.plus(by)
    }
}

/** Fresh in-memory H2 database with every auth migration applied. Close it when done. */
fun createAuthTestDb(): HikariDataSource {
    val ds = HikariDataSource(HikariConfig().apply {
        jdbcUrl = "jdbc:h2:mem:test-${System.nanoTime()};DB_CLOSE_DELAY=-1"
        username = "sa"
        password = ""
        maximumPoolSize = 10
    })
    ds.connection.use { conn ->
        val stmt = conn.createStatement()
        for (migration in listOf(
            "V001__auth_tables.sql",
            "V002__passkey_credential.sql",
            "V003__webauthn_consumed_challenge.sql",
        )) {
            stmt.execute(TestUser::class.java.getResourceAsStream("/db/auth/$migration")!!
                .bufferedReader().readText())
        }
    }
    return ds
}
