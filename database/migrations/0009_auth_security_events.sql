CREATE TABLE IF NOT EXISTS auth_security_events (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_user_id CHAR(36) NOT NULL,
 target_user_id CHAR(36) NOT NULL,
 event_type ENUM('REVIEWER_DISABLED','REVIEWER_ENABLED','SESSIONS_REVOKED','OWN_SESSIONS_REVOKED') NOT NULL,
 revoked_session_count INT UNSIGNED NOT NULL DEFAULT 0,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_security_events_target (target_user_id,created_at),
 INDEX idx_security_events_actor (actor_user_id,created_at),
 CONSTRAINT fk_security_actor FOREIGN KEY (actor_user_id) REFERENCES auth_users(id),
 CONSTRAINT fk_security_target FOREIGN KEY (target_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
