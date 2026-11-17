-- Phase 1BM: quote-specific candidate witness checkpoint custody ONLY.
-- Local MySQL rows are NOT independently published, immutable WORM,
-- authenticated CA/revocation proof, anti-rollback proof or release authority.
CREATE TABLE IF NOT EXISTS quote_bm_candidate_checkpoint_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_sequence INT UNSIGNED NOT NULL DEFAULT 0,
 last_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_revision_number INT UNSIGNED NOT NULL DEFAULT 0,
 last_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 independent_publication_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_revocation_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 external_worm_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
  ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bm_quote FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bm_candidate_checkpoint_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 sequence_number INT UNSIGNED NOT NULL,
 candidate_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 candidate_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_publication_head_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'PINSET_CHANGE_QUARANTINED','SOURCE_MISMATCH_QUARANTINED',
  'PUBLICATION_MISMATCH_QUARANTINED','REVOCATION_CLAIM_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bm_candidate_attempt(quote_id,candidate_receipt_sha256,outcome),
 INDEX ix_bm_sequence(quote_id,sequence_number),
 CONSTRAINT fk_bm_attempt_stream FOREIGN KEY (quote_id)
  REFERENCES quote_bm_candidate_checkpoint_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
