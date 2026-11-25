-- Phase 1BF: local candidate revocation publisher continuity only.
-- Not externally authenticated CRL/OCSP, independently signed WORM, actual
-- provider revocation, genuine encrypted DR or release authorization.
CREATE TABLE IF NOT EXISTS inv_bf_publication_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_publication_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_freeze_incident_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_publisher_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 independent_issuer_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 active_crl_ocsp_independently_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 revoked_key_externally_confirmed ENUM('NO') NOT NULL DEFAULT 'NO',
 object_lock_provider_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 encrypted_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
  ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bf_publication_freeze FOREIGN KEY(log_ref)
  REFERENCES inv_be_freeze_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_bf_publication_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 publication_sequence BIGINT UNSIGNED NOT NULL,
 publication_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_publication_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 freeze_incident_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 publisher_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED',
  'ROLLBACK_QUARANTINED','GAP_QUARANTINED',
  'PREDECESSOR_MISMATCH_QUARANTINED',
  'ISSUER_KEY_CHANGE_QUARANTINED',
  'UPSTREAM_FREEZE_CHANGED_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bf_publication_attempt(log_ref,publication_sha256,outcome),
 KEY ix_bf_publication_sequence(log_ref,publication_sequence),
 CONSTRAINT fk_bf_publication_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bf_publication_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
