-- Phase 1BO internal candidate-only external authority onboarding DOSSIER.
-- This is NOT authenticated provider enrollment, external published WORM,
-- legal signatory verification, production CRL/OCSP or DR acceptance.
CREATE TABLE IF NOT EXISTS quote_bo_candidate_authority_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_version INT UNSIGNED NOT NULL DEFAULT 0,
 last_dossier_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bn_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bm_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_claimed_revocation_epoch INT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 provider_enrolled ENUM('NO') NOT NULL DEFAULT 'NO',
 out_of_band_head_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_revocation_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 encrypted_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 legal_signoffs_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bo_bn_stream FOREIGN KEY (quote_id)
  REFERENCES quote_bn_candidate_reconciliation_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bo_candidate_authority_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 dossier_version INT UNSIGNED NOT NULL,
 dossier_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 predecessor_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 bn_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 bm_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 quote_source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 candidate_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_revocation_epoch INT UNSIGNED NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'UPSTREAM_DRIFT_QUARANTINED','REVOCATION_REGRESSION_QUARANTINED',
  'EVIDENCE_CONFLICT_QUARANTINED','POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bo_candidate_outcome(quote_id,dossier_sha256,outcome),
 KEY ix_bo_candidate_quote_version(quote_id,dossier_version),
 CONSTRAINT fk_bo_candidate_stream FOREIGN KEY (quote_id)
  REFERENCES quote_bo_candidate_authority_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
