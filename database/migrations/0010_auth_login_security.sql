-- Phase 1K: durable atomic login attempt buckets and short-lived session reauthentication.
CREATE TABLE IF NOT EXISTS auth_login_rate_buckets (
  key_hash CHAR(64) NOT NULL,
  window_bucket BIGINT UNSIGNED NOT NULL,
  attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (key_hash,window_bucket),
  INDEX idx_rate_bucket_expiry (window_bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_step_up_sessions (
  session_token_hash CHAR(64) NOT NULL PRIMARY KEY,
  step_up_token_hash CHAR(64) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_step_up_session FOREIGN KEY (session_token_hash) REFERENCES auth_sessions(token_hash) ON DELETE CASCADE,
  INDEX idx_step_up_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
