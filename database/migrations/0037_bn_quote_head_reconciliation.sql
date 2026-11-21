-- Phase 1BN: local, untrusted candidate dual-witness reconciliation and DR rehearsal ledger.
-- NO independently published head, NO CRL/OCSP issuer, NO provider WORM,
-- NO externally witnessed restore, NO production release.
CREATE TABLE IF NOT EXISTS quote_bn_candidate_reconciliation_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_revision INT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_revocation_epoch INT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 independent_head_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 issuer_and_revocation_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 real_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bn_candidate_quote FOREIGN KEY (quote_id)
  REFERENCES quote_bm_candidate_checkpoint_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bn_candidate_reconciliation_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 revision_number INT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 claimed_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_revocation_epoch INT UNSIGNED NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED',
  'ROLLBACK_QUARANTINED','GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'PINSET_ROLLOVER_UNVERIFIED_QUARANTINED','REVOCATION_REGRESSION_QUARANTINED',
  'CLAIM_CONFLICT_QUARANTINED','LOCAL_CHECKPOINT_DRIFT_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bn_packet_outcome (quote_id,packet_sha256,outcome),
 KEY ix_bn_revision (quote_id,revision_number),
 CONSTRAINT fk_bn_candidate_attempt FOREIGN KEY (quote_id)
  REFERENCES quote_bn_candidate_reconciliation_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
