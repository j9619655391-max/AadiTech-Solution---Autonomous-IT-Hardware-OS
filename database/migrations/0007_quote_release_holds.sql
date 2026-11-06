-- Phase 1H: fail-closed preparation, not authorization to send.
-- No worker or provider dispatch is permitted to consume these rows.
CREATE TABLE IF NOT EXISTS sales_quote_release_preparations (
 id CHAR(36) NOT NULL PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 revision_number INT UNSIGNED NOT NULL,
 internal_review_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 status ENUM('HELD') NOT NULL DEFAULT 'HELD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_release_quote_revision (quote_id,revision_number),
 UNIQUE KEY uq_release_internal_review (internal_review_id),
 INDEX idx_release_prepared_by (prepared_by,created_at),
 CONSTRAINT fk_release_quote FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id),
 CONSTRAINT fk_release_review FOREIGN KEY (internal_review_id) REFERENCES sales_quote_review_decisions(id),
 CONSTRAINT fk_release_actor FOREIGN KEY (prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sales_quote_outbox_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_preparation_id CHAR(36) NOT NULL,
 event_type ENUM('QUOTE_RELEASE_PREPARATION_HELD') NOT NULL,
 dispatch_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 payload_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_outbox_release (release_preparation_id),
 CONSTRAINT fk_outbox_release FOREIGN KEY (release_preparation_id) REFERENCES sales_quote_release_preparations(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
