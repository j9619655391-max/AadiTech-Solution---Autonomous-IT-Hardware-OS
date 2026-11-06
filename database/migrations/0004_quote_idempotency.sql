-- Phase 1F: append-only idempotency mapping; legacy drafts remain intact.
CREATE TABLE IF NOT EXISTS sales_quote_create_requests (
  actor_id CHAR(36) NOT NULL,
  request_key CHAR(36) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  quote_id CHAR(36) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (actor_id, request_key),
  INDEX idx_quote_request_quote (quote_id),
  CONSTRAINT fk_quote_create_actor FOREIGN KEY (actor_id) REFERENCES auth_users(id),
  CONSTRAINT fk_quote_create_draft FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
