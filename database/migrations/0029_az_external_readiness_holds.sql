-- Phase 1AZ: digest-only witness/archive/recovery readiness history.
-- Internal provenance only; tables are NOT WORM, external authorization or DR evidence.
CREATE TABLE IF NOT EXISTS inv_az_readiness_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 external_witnesses_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 immutable_storage_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 real_dr_restore_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_az_readiness_packets (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 revision BIGINT UNSIGNED NOT NULL,
 packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 internal_evidence_consistent BOOLEAN NOT NULL DEFAULT 0,
 outcome ENUM('RECORDED_UNTRUSTED','CONFLICT_QUARANTINED','ROLLBACK_QUARANTINED',
  'GAP_QUARANTINED','PREDECESSOR_MISMATCH_QUARANTINED',
  'INVALID_CLAIM_QUARANTINED','POST_INCIDENT_QUARANTINED') NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_az_packet_digest(log_ref,packet_sha256),
 KEY ix_az_revision(log_ref,revision),
 CONSTRAINT fk_az_packet_stream FOREIGN KEY(log_ref)
  REFERENCES inv_az_readiness_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
