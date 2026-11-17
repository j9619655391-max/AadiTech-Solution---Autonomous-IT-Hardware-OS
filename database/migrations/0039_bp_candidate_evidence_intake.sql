-- Phase 1BP local cryptographic CANDIDATE intake only.
-- Not an independent publisher, enrolled CA, issuer CRL/OCSP, verified WORM,
-- witnessed DR or production release. Ordinary MySQL is not WORM.
CREATE TABLE IF NOT EXISTS quote_bp_candidate_intake_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_version INT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bo_dossier_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bm_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bn_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_signer_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_revocation_epoch INT UNSIGNED NOT NULL DEFAULT 0,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 trusted_external_key_enrollment ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_head_retrieved ENUM('NO') NOT NULL DEFAULT 'NO',
 crl_ocsp_authority_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 real_worm_delete_denial_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 actual_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bp_bo_dossier FOREIGN KEY(quote_id)
  REFERENCES quote_bo_candidate_authority_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bp_candidate_intake_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 version_number INT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 predecessor_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 bo_dossier_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 bm_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 bn_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signer_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 revocation_epoch INT UNSIGNED NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'CHALLENGE_REPLAY_QUARANTINED','PINSET_CHANGE_QUARANTINED',
  'EPOCH_REGRESSION_QUARANTINED','UPSTREAM_DRIFT_QUARANTINED',
  'CROSS_SOURCE_CONFLICT_QUARANTINED','POST_INCIDENT_QUARANTINED')
  NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bp_packet_outcome(quote_id,packet_sha256,outcome),
 INDEX ix_bp_quote_challenge(quote_id,challenge_sha256),
 CONSTRAINT fk_bp_attempt_stream FOREIGN KEY(quote_id)
  REFERENCES quote_bp_candidate_intake_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Server-issued short-lived one-use nonce hash (no public HTTP issuer).
CREATE TABLE IF NOT EXISTS quote_bp_candidate_intake_challenges (
 challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 issued_at DATETIME(3) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 status ENUM('ISSUED','CONSUMED') NOT NULL DEFAULT 'ISSUED',
 consumed_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 INDEX ix_bp_challenge_quote(quote_id,status),
 CONSTRAINT fk_bp_challenge_stream FOREIGN KEY(quote_id)
  REFERENCES quote_bp_candidate_intake_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
