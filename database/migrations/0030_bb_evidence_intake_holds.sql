-- Phase 1BB: synthetic digest-only evidence custody. These rows are NOT WORM,
-- legal trust, externally authenticated witness evidence or provider access.
-- Never persist bearer tokens, private keys, signed contracts or raw objects.
CREATE TABLE IF NOT EXISTS inv_bb_evidence_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 external_sources_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_key_custody_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_bb_evidence_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 sequence_number BIGINT UNSIGNED NOT NULL,
 batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 outcome ENUM('ACCEPTED_UNVERIFIED','FORK_QUARANTINED',
  'ROLLBACK_QUARANTINED','GAP_QUARANTINED',
  'PREDECESSOR_QUARANTINED','NONCE_REPLAY_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bb_log_batch_outcome(log_ref,batch_sha256,outcome),
 KEY ix_bb_log_seq(log_ref,sequence_number),
 CONSTRAINT fk_bb_attempt_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bb_evidence_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_bb_evidence_nonce_claims (
 challenge_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 KEY ix_bb_nonce_log_batch(log_ref,batch_sha256),
 CONSTRAINT fk_bb_nonce_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bb_evidence_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
