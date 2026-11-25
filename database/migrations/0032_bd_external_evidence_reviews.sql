-- Phase 1BD: internal digest-only independent-evidence REVIEW history.
-- Neither these tables nor applicant-supplied Ed25519 evidence constitute
-- external witness authority, real Object Lock, WORM, verified DR, or GO.
CREATE TABLE IF NOT EXISTS inv_bd_review_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_az_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bb_batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 independent_authority_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 object_lock_provider_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 encrypted_dr_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
   ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_bd_review_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 revision_number BIGINT UNSIGNED NOT NULL,
 review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 az_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 bb_batch_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 outcome ENUM('RECORDED_UNVERIFIED','FORK_QUARANTINED',
  'ROLLBACK_QUARANTINED','GAP_QUARANTINED',
  'PREDECESSOR_MISMATCH_QUARANTINED','UPSTREAM_CHANGED_QUARANTINED',
  'POST_INCIDENT_QUARANTINED') NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bd_review_attempt(log_ref,review_sha256,outcome),
 KEY ix_bd_review_revision(log_ref,revision_number),
 CONSTRAINT fk_bd_review_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bd_review_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
