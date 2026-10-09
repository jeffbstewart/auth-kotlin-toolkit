-- Single-use tracking for WebAuthn challenges (JdbcConsumedChallengeStore).
-- Rows only need to outlive the challenge TTL; expired rows are purged automatically.
-- Optional: only needed if WebAuthnService is configured with JdbcConsumedChallengeStore.
CREATE TABLE IF NOT EXISTS webauthn_consumed_challenge (
    challenge_hash  VARCHAR(64) PRIMARY KEY,
    expires_at      TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_consumed_challenge_exp ON webauthn_consumed_challenge(expires_at);
