-- Phase 1BE candidate witness revocation INCIDENT freeze only.
-- SQL does NOT verify independent legal/provider authority, trust, revocation
-- publishing, WORM enforcement or real encrypted restore. No unfreeze exists.
CREATE TABLE IF NOT EXISTS inv_be_freeze_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 state ENUM('HELD_UNVERIFIED','FROZEN_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 last_incident_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 frozen_witness_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 frozen_key_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_bd_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 independent_witness_authority_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 independently_published_revocation_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 provider_worm_denial_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 encrypted_dr_restore_witnessed ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
  ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_be_freeze_attempts (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 incident_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 bd_review_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 az_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 frozen_witness_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 frozen_key_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 outcome ENUM('FROZEN_UNVERIFIED','CONFLICT_QUARANTINED',
   'POST_INCIDENT_QUARANTINED') NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_be_freeze_attempt(log_ref,incident_sha256,outcome),
 KEY ix_be_freeze_evidence(log_ref,bd_review_sha256),
 CONSTRAINT fk_be_freeze_stream FOREIGN KEY(log_ref)
  REFERENCES inv_be_freeze_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
