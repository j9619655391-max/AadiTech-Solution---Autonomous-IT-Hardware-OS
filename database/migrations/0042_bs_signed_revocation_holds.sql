-- Phase 1BS: signed CRL/OCSP OFFLINE candidate verification only.
-- Issuer keys are synthetic or caller configured; not CCA/RCAI/eMudhra trust.
-- Local MySQL is not WORM, and no live revocation endpoint is contacted.
CREATE TABLE IF NOT EXISTS quote_bs_candidate_revocation_streams (
 quote_id CHAR(36) NOT NULL PRIMARY KEY,
 last_version INT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_br_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_candidate_issuer_root_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_crl_number INT UNSIGNED NOT NULL DEFAULT 0,
 last_crl_until DATETIME(3) NULL,
 last_ocsp_until DATETIME(3) NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 authorized_real_issuer_enrolled ENUM('NO') NOT NULL DEFAULT 'NO',
 real_signed_crl_distribution_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 live_authorized_ocsp_responder_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_revocation_monotonicity_proven ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_bs_br_byte_head FOREIGN KEY(quote_id)
  REFERENCES quote_br_candidate_byte_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quote_bs_candidate_revocation_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 quote_id CHAR(36) NOT NULL,
 version_number INT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 predecessor_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 br_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 issuer_root_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 crl_number INT UNSIGNED NOT NULL,
 crl_until DATETIME(3) NULL,
 ocsp_until DATETIME(3) NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'BR_REPLAY_QUARANTINED','ROOT_CHANGE_QUARANTINED',
  'CRL_EPOCH_REGRESSION_QUARANTINED','STATUS_STALE_QUARANTINED',
  'UPSTREAM_DRIFT_QUARANTINED','SOURCE_REVOCATION_CONFLICT_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bs_packet_outcome(quote_id,packet_sha256,outcome),
 INDEX ix_bs_quote_version(quote_id,version_number),
 CONSTRAINT fk_bs_revocation_attempt FOREIGN KEY(quote_id)
  REFERENCES quote_bs_candidate_revocation_streams(quote_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
