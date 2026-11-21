-- Phase 1AJ: internal proof-of-possession, rotation and immediate revocation only.
-- Key ownership by an EXTERNAL SUPPLIER / WAREHOUSE remains UNVERIFIED.
CREATE TABLE IF NOT EXISTS inv_key_possession_challenges (
 id CHAR(36) NOT NULL PRIMARY KEY,
 key_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 message_sha256 CHAR(64) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 consumed_at DATETIME(3) NULL,
 status ENUM('ISSUED','MATCHED_INTERNAL') NOT NULL DEFAULT 'ISSUED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_key_pop_challenge_digest(key_id,message_sha256),
 INDEX idx_key_pop_expiry(expires_at,status),
 CONSTRAINT fk_key_pop_challenge_key FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_key_pop_challenge_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_possession_receipts (
 id CHAR(36) NOT NULL PRIMARY KEY,
 challenge_id CHAR(36) NOT NULL,
 key_id CHAR(36) NOT NULL,
 nonce_b64 VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signature_sha256 CHAR(64) NOT NULL,
 status ENUM('MATCHED_INTERNAL') NOT NULL DEFAULT 'MATCHED_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_key_pop_receipt_challenge(challenge_id),
 CONSTRAINT fk_key_pop_receipt_challenge FOREIGN KEY(challenge_id) REFERENCES inv_key_possession_challenges(id),
 CONSTRAINT fk_key_pop_receipt_key FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_possession_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 receipt_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_UNTRUSTED','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 possession_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_key_pop_review_receipt(receipt_id),
 CONSTRAINT fk_key_pop_review_receipt FOREIGN KEY(receipt_id) REFERENCES inv_key_possession_receipts(id),
 CONSTRAINT fk_key_pop_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_retirements (
 key_id CHAR(36) NOT NULL PRIMARY KEY,
 initiated_by CHAR(36) NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 event_type ENUM('EMERGENCY_REVOKED','ROTATION_RETIRED') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_key_retirement_candidate FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_key_retirement_actor FOREIGN KEY(initiated_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_rotation_proposals (
 id CHAR(36) NOT NULL PRIMARY KEY,
 old_key_id CHAR(36) NOT NULL,
 new_key_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_UNTRUSTED','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_rotation_old_key(old_key_id),
 UNIQUE KEY uq_rotation_new_key(new_key_id),
 CONSTRAINT fk_key_rotation_old FOREIGN KEY(old_key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_key_rotation_new FOREIGN KEY(new_key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_key_rotation_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id),
 CONSTRAINT chk_key_rotation_distinct CHECK(old_key_id<>new_key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_rotation_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 proposal_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_UNTRUSTED','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 possession_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_key_rotation_decision(proposal_id),
 CONSTRAINT fk_key_rotation_review_proposal FOREIGN KEY(proposal_id) REFERENCES inv_key_rotation_proposals(id),
 CONSTRAINT fk_key_rotation_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_key_lifecycle_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('CHALLENGE','POSSESSION','KEY','ROTATION') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('CHALLENGE_ISSUED','POSSESSION_MATCHED','POSSESSION_REVIEWED',
  'POSSESSION_REJECTED','EMERGENCY_REVOKED','ROTATION_PROPOSED',
  'ROTATION_REVIEWED','ROTATION_REJECTED') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_key_lifecycle_audit(entity_type,entity_id,created_at),
 CONSTRAINT fk_key_lifecycle_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
