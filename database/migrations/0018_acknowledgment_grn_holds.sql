-- Phase 1AF: claims and internal reconciliation only. No supplier order issuance,
-- supplier authenticated acknowledgment, posted GRN or available inventory.
CREATE TABLE IF NOT EXISTS proc_ack_claims (
 id CHAR(36) NOT NULL PRIMARY KEY,
 preparation_id CHAR(36) NOT NULL,
 outbox_id CHAR(36) NOT NULL,
 recorded_by CHAR(36) NOT NULL,
 supplier_ack_ref VARCHAR(80) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 document_sha256 CHAR(64) NOT NULL,
 outbox_sha256 CHAR(64) NOT NULL,
 claim_sha256 CHAR(64) NOT NULL,
 status ENUM('AWAITING_INTERNAL_REVIEW','ATTESTED_INTERNAL','DISPUTED_INTERNAL')
  NOT NULL DEFAULT 'AWAITING_INTERNAL_REVIEW',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_ack_claim_preparation(preparation_id),
 UNIQUE KEY uq_ack_claim_outbox(outbox_id),
 CONSTRAINT fk_ack_claim_preparation FOREIGN KEY(preparation_id) REFERENCES proc_dispatch_preparations(id),
 CONSTRAINT fk_ack_claim_outbox FOREIGN KEY(outbox_id) REFERENCES proc_dispatch_outbox_holds(id),
 CONSTRAINT fk_ack_claim_actor FOREIGN KEY(recorded_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_ack_claim_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 claim_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('ATTESTED_INTERNAL','DISPUTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 review_evidence_ref VARCHAR(160) NOT NULL,
 document_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ack_decision_claim(claim_id),
 CONSTRAINT fk_ack_decision_claim FOREIGN KEY(claim_id) REFERENCES proc_ack_claims(id),
 CONSTRAINT fk_ack_decision_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_grn_reconciliation_packs (
 id CHAR(36) NOT NULL PRIMARY KEY,
 claim_id CHAR(36) NOT NULL,
 observation_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 pack_sha256 CHAR(64) NOT NULL,
 pack_json JSON NOT NULL,
 status ENUM('AWAITING_INTERNAL_REVIEW','HELD_INTERNAL','REJECTED_INTERNAL')
  NOT NULL DEFAULT 'AWAITING_INTERNAL_REVIEW',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_grn_claim(claim_id),
 UNIQUE KEY uq_grn_observation(observation_id),
 CONSTRAINT fk_grn_pack_claim FOREIGN KEY(claim_id) REFERENCES proc_ack_claims(id),
 CONSTRAINT fk_grn_pack_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
 CONSTRAINT fk_grn_pack_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_grn_reconciliation_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pack_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('HELD_INTERNAL','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 review_evidence_ref VARCHAR(160) NOT NULL,
 custody_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_grn_pack_decision(pack_id),
 CONSTRAINT fk_grn_pack_decision FOREIGN KEY(pack_id) REFERENCES inv_grn_reconciliation_packs(id),
 CONSTRAINT fk_grn_reviewer FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_grn_held_records (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pack_id CHAR(36) NOT NULL,
 decision_id CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 status ENUM('HELD') NOT NULL DEFAULT 'HELD',
 stock_posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_grn_held_pack(pack_id),
 CONSTRAINT fk_grn_held_pack FOREIGN KEY(pack_id) REFERENCES inv_grn_reconciliation_packs(id),
 CONSTRAINT fk_grn_held_decision FOREIGN KEY(decision_id) REFERENCES inv_grn_reconciliation_decisions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_grn_evidence_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('ACK_CLAIM','GRN_PACK') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('CLAIM_RECORDED','CLAIM_ATTESTED','CLAIM_DISPUTED',
  'PACK_PREPARED','PACK_HELD','PACK_REJECTED') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_grn_audit(entity_type,entity_id,created_at),
 CONSTRAINT fk_grn_evidence_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
