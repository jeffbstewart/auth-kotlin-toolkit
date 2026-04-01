-- Test-only: the auth toolkit doesn't own the user table.
-- Consumers define their own user table and implement UserRepository.
CREATE TABLE IF NOT EXISTS test_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL
);
