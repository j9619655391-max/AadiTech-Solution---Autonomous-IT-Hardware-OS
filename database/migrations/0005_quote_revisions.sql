-- Phase 1F.2: append-only internal draft revisions, no mutation of existing draft/items.
CREATE TABLE IF NOT EXISTS sales_quote_draft_revisions (
  id CHAR(36) NOT NULL PRIMARY KEY,
  quote_id CHAR(36) NOT NULL,
  revision_number INT UNSIGNED NOT NULL,
  actor_id CHAR(36) NOT NULL,
  reason VARCHAR(500) NOT NULL,
  subtotal DECIMAL(18,2) NOT NULL,
  tax_estimate DECIMAL(18,2) NOT NULL,
  total_estimate DECIMAL(18,2) NOT NULL,
  gross_margin_bps INT NOT NULL,
  review_status ENUM('DRAFT_OK','MARGIN_REVIEW_REQUIRED') NOT NULL,
  line_snapshot JSON NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_quote_revision (quote_id,revision_number),
  INDEX idx_quote_revision_actor (actor_id),
  CONSTRAINT fk_revision_quote FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id),
  CONSTRAINT fk_revision_actor FOREIGN KEY (actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
