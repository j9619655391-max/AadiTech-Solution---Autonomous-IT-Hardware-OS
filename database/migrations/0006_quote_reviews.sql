-- Phase 1G: immutable internal owner review decisions; never triggers customer sending.
CREATE TABLE IF NOT EXISTS sales_quote_review_decisions (
  id CHAR(36) NOT NULL PRIMARY KEY,
  quote_id CHAR(36) NOT NULL,
  revision_number INT UNSIGNED NOT NULL,
  owner_user_id CHAR(36) NOT NULL,
  decision ENUM('APPROVED_INTERNAL','REJECTED_INTERNAL') NOT NULL,
  reason VARCHAR(1000) NOT NULL,
  override_requested BOOLEAN NOT NULL DEFAULT FALSE,
  gross_margin_bps INT NOT NULL,
  minimum_margin_bps INT NOT NULL,
  subtotal DECIMAL(18,2) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_review_quote_revision (quote_id,revision_number),
  INDEX idx_review_owner (owner_user_id,created_at),
  CONSTRAINT fk_review_quote FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id),
  CONSTRAINT fk_review_owner FOREIGN KEY (owner_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
