-- Phase 1BR. Offline byte-level evidence, NOT provider-authorized enrollment.
-- NO live transport; NO CA policy path, signed CRL/OCSP, WORM or DR authority.
CREATE TABLE IF NOT EXISTS quote_br_candidate_byte_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_version INT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bq_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_root_cert_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_claimed_revocation_epoch INT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 provider_root_independently_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 live_provider_tls_attested ENUM('NO') NOT NULL DEFAULT 'NO',
 issuer_policy_and_chain_authorized ENUM('NO') NOT NULL DEFAULT 'NO',
 signed_crl_ocsp_authorized ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_worm_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 actual_dr_restore_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_br_bq_candidate FOREIGN KEY(quote_id)
  REFERENCES quote_bq_candidate_remote_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_br_candidate_byte_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 version_number INT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 predecessor_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 bq_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 root_cert_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_revocation_epoch INT UNSIGNED NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'BQ_REPLAY_QUARANTINED','ROOT_CHANGE_QUARANTINED',
  'REVOCATION_REGRESSION_QUARANTINED','UPSTREAM_DRIFT_QUARANTINED',
  'RAW_BYTES_CONFLICT_QUARANTINED','POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_br_packet_outcome(quote_id,packet_sha256,outcome),
 INDEX ix_br_quote_version(quote_id,version_number),
 CONSTRAINT fk_br_candidate_attempt FOREIGN KEY(quote_id)
  REFERENCES quote_br_candidate_byte_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
