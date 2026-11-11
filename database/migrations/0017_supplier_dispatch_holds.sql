-- Phase 1AE: supplier destination provenance and held dispatch authorizations.
-- All outbox rows stay DISABLED; no external supplier send, PO issuance,
-- acknowledgment, receipt, stock posting, reservation or payment.
CREATE TABLE IF NOT EXISTS proc_delivery_destinations (
 id CHAR(36) NOT NULL PRIMARY KEY,
 supplier_id CHAR(36) NOT NULL,
 email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_INTERNAL','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_by CHAR(36) NOT NULL,
 reviewed_by CHAR(36) NULL,
 review_evidence_ref VARCHAR(160) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_proc_destination_supplier(supplier_id),
 CONSTRAINT fk_proc_dest_supplier FOREIGN KEY(supplier_id) REFERENCES proc_suppliers(id),
 CONSTRAINT fk_proc_dest_owner FOREIGN KEY(created_by) REFERENCES auth_users(id),
 CONSTRAINT fk_proc_dest_reviewer FOREIGN KEY(reviewed_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_dispatch_preparations (
 id CHAR(36) NOT NULL PRIMARY KEY,
 hold_id CHAR(36) NOT NULL,
 destination_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 authorization_evidence_ref VARCHAR(160) NOT NULL,
 hold_sha256 CHAR(64) NOT NULL,
 manifest_sha256 CHAR(64) NOT NULL,
 manifest_json JSON NOT NULL,
 status ENUM('PENDING_INTERNAL','APPROVED_INTERNAL','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_proc_dispatch_hold(hold_id),
 INDEX idx_proc_dispatch_state(status,created_at),
 CONSTRAINT fk_proc_dispatch_hold FOREIGN KEY(hold_id) REFERENCES proc_po_holds(id),
 CONSTRAINT fk_proc_dispatch_dest FOREIGN KEY(destination_id) REFERENCES proc_delivery_destinations(id),
 CONSTRAINT fk_proc_dispatch_owner FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_dispatch_review_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 preparation_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('APPROVED_INTERNAL','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 destination_attested BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proc_dispatch_decision(preparation_id),
 CONSTRAINT fk_proc_disp_dec_preparation FOREIGN KEY(preparation_id) REFERENCES proc_dispatch_preparations(id),
 CONSTRAINT fk_proc_disp_dec_reviewer FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_dispatch_outbox_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 preparation_id CHAR(36) NOT NULL,
 decision_id CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 state ENUM('HELD') NOT NULL DEFAULT 'HELD',
 dispatch_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proc_disp_outbox(preparation_id),
 CONSTRAINT fk_proc_disp_outbox_prep FOREIGN KEY(preparation_id) REFERENCES proc_dispatch_preparations(id),
 CONSTRAINT fk_proc_disp_outbox_review FOREIGN KEY(decision_id) REFERENCES proc_dispatch_review_decisions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_dispatch_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('DESTINATION_PROPOSED','DESTINATION_ATTESTED','DESTINATION_REJECTED',
 'PREPARATION_CREATED','PREPARATION_APPROVED_HELD','PREPARATION_REJECTED') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_proc_disp_audit(entity_id,created_at),
 CONSTRAINT fk_proc_disp_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
