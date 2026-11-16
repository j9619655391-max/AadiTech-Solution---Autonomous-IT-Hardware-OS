-- Phase 1AX: additive, append-only-at-application-layer checkpoint observations.
-- Internal cryptographic evidence only; no externally authenticated witness.
-- No triggers/WORM storage: a privileged DBA can change rows. Release ALWAYS HOLD.
CREATE TABLE IF NOT EXISTS inv_ax_checkpoint_streams (
  log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  provider_code VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  requested_scope VARCHAR(160) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  last_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  last_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_claim_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  last_signer_pin_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
  release_decision ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_ax_checkpoint_observations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  checkpoint_sequence BIGINT UNSIGNED NOT NULL,
  receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  claim_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  prior_receipt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  outcome ENUM('ACCEPTED_UNTRUSTED','REPLAY_VARIANT','FORK','ROLLBACK','GAP','UNAUTHORIZED_KEY_CHANGE','QUARANTINED_OBSERVATION')
    NOT NULL,
  signed_checkpoint_json JSON NOT NULL,
  recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_ax_log_receipt(log_ref,receipt_sha256),
  KEY ix_ax_log_sequence(log_ref,checkpoint_sequence),
  CONSTRAINT fk_ax_observation_stream FOREIGN KEY(log_ref)
    REFERENCES inv_ax_checkpoint_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
