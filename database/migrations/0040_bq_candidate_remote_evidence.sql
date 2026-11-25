-- Phase 1BQ: offline captured candidate remote evidence; no genuine online
-- retrieval, issuer authentication, enrolled registrar, cloud WORM or real DR.
CREATE TABLE IF NOT EXISTS quote_bq_candidate_remote_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_version INT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bp_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_registrar_pin_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_collector_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_endpoint_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_claimed_revocation_epoch INT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 authenticated_registrar_enrollment ENUM('NO') NOT NULL DEFAULT 'NO',
 remotely_retrieved_head_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 live_issuer_crl_ocsp_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_worm_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 actual_dr_recovery_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bq_bp_candidate FOREIGN KEY(quote_id)
  REFERENCES quote_bp_candidate_intake_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bq_candidate_remote_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 version_number INT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 predecessor_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 bp_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 registrar_pin_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 collector_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 endpoint_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 claimed_revocation_epoch INT UNSIGNED NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'CHALLENGE_REPLAY_QUARANTINED','REGISTRAR_OR_ENDPOINT_CHANGE_QUARANTINED',
  'REVOCATION_REGRESSION_QUARANTINED','UPSTREAM_DRIFT_QUARANTINED',
  'REMOTE_CLAIM_CONFLICT_QUARANTINED','POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bq_candidate_packet(quote_id,packet_sha256,outcome),
 INDEX ix_bq_quote_version(quote_id,version_number),
 CONSTRAINT fk_bq_remote_attempt FOREIGN KEY(quote_id)
  REFERENCES quote_bq_candidate_remote_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bq_candidate_remote_challenges (
 challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 issued_at DATETIME(3) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 status ENUM('ISSUED','CONSUMED') NOT NULL DEFAULT 'ISSUED',
 consumed_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 INDEX ix_bq_quote_challenge(quote_id,status),
 CONSTRAINT fk_bq_remote_challenge FOREIGN KEY(quote_id)
  REFERENCES quote_bq_candidate_remote_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
