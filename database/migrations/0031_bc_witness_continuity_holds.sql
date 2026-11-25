-- Phase 1BC: internally observed candidate witness Merkle heads only.
-- Source-of-truth identity, cloud WORM and DR remain UNVERIFIED; not an
-- immutable ledger or an externally authenticated authority registration.
CREATE TABLE IF NOT EXISTS inv_bc_witness_streams (
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 last_tree_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
 last_root_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_az_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 last_witness_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 governance_state ENUM('HELD_UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'HELD_UNVERIFIED',
 external_source_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 independent_key_custody_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 immutable_worm_retention_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_bc_witness_observations (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 log_ref VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 old_tree_size BIGINT UNSIGNED NOT NULL,
 old_root_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 new_tree_size BIGINT UNSIGNED NOT NULL,
 new_root_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 az_packet_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 witness_pinset_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 outcome ENUM(
  'GENESIS_UNVERIFIED','EXTENSION_UNVERIFIED',
  'FORK_QUARANTINED','ROLLBACK_QUARANTINED',
  'HISTORICAL_HEAD_MISMATCH_QUARANTINED',
  'WITNESS_PINSET_CHANGE_QUARANTINED',
  'AZ_PACKET_CHANGE_QUARANTINED','POST_INCIDENT_QUARANTINED'
 ) NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_bc_candidate_outcome(log_ref,evidence_sha256,outcome),
 KEY ix_bc_candidate_head(log_ref,new_tree_size),
 CONSTRAINT fk_bc_witness_stream FOREIGN KEY(log_ref)
  REFERENCES inv_bc_witness_streams(log_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
