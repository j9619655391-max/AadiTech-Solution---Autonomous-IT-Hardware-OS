-- Phase 1K.2: opt-in TOTP, hashed one-time recovery and pre-session MFA challenges.
CREATE TABLE IF NOT EXISTS auth_totp_credentials (
 user_id CHAR(36) NOT NULL PRIMARY KEY,
 secret_encrypted VARCHAR(512) NOT NULL,
 enabled_at DATETIME(3) NULL,
 enrollment_expires_at DATETIME(3) NULL,
 last_counter BIGINT NOT NULL DEFAULT -1,
 CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_totp_recovery_codes (
 user_id CHAR(36) NOT NULL,
 code_hash CHAR(64) NOT NULL,
 used_at DATETIME(3) NULL,
 PRIMARY KEY (user_id,code_hash),
 CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_mfa_challenges (
 token_hash CHAR(64) NOT NULL PRIMARY KEY,
 user_id CHAR(36) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
 INDEX idx_mfa_expiry (expires_at),
 CONSTRAINT fk_challenge_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
