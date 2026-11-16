-- Phase 1BG: candidate-only CRL/OCSP, cloud WORM and encrypted DR
-- cross-source audit quorum. Neither externally authenticated nor trusted.
CREATE TABLE IF NOT EXISTS inv_bg_cross_source_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_publication_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_auditor_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_publisher_pin_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_crl_number BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_crl_this_update_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 independently_authenticated_issuer ENUM('NO') NOT NULL DEFAULT 'NO',
 trusted_live_crl_ocsp ENUM('NO') NOT NULL DEFAULT 'NO',
 independently_pinned_auditors ENUM('NO') NOT NULL DEFAULT 'NO',
 externally_enforced_object_lock ENUM('NO') NOT NULL DEFAULT 'NO',
 real_encrypted_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
  ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bg_review_publication FOREIGN KEY(log_ref)
  REFERENCES inv_bf_publication_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_bg_cross_source_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 review_revision BIGINT UNSIGNED NOT NULL,
 review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 publication_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 publisher_pin_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 auditor_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 crl_number BIGINT UNSIGNED NOT NULL,
 crl_this_update_ms BIGINT UNSIGNED NOT NULL,
 outcome ENUM(
  'RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'PUBLISHER_PIN_CHANGE_QUARANTINED','AUDITOR_PINSET_CHANGE_QUARANTINED',
  'CRL_REGRESSION_QUARANTINED','POST_INCIDENT_QUARANTINED'
 ) NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bg_review_attempt(log_ref,review_sha256,outcome),
 KEY ix_bg_revision(log_ref,review_revision),
 CONSTRAINT fk_bg_review_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bg_cross_source_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
