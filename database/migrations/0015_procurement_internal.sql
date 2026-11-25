-- Phase 1AC: internal procurement authority only. No actual supplier POs,
-- goods receipts, inventory postings, reservations, payments or dispatch.
CREATE TABLE IF NOT EXISTS proc_suppliers (
 id CHAR(36) NOT NULL PRIMARY KEY,
 code VARCHAR(32) NOT NULL,
 legal_name VARCHAR(200) NOT NULL,
 tax_id VARCHAR(15) NULL,
 status ENUM('UNVERIFIED','REVIEWED_INTERNAL') NOT NULL DEFAULT 'UNVERIFIED',
 evidence_ref VARCHAR(160) NULL,
 created_by CHAR(36) NOT NULL,
 reviewed_by CHAR(36) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_proc_supplier_code(code),
 INDEX idx_proc_supplier_status(status),
 CONSTRAINT fk_proc_supplier_owner FOREIGN KEY (created_by) REFERENCES auth_users(id),
 CONSTRAINT fk_proc_supplier_reviewer FOREIGN KEY (reviewed_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_requests (
 id CHAR(36) NOT NULL PRIMARY KEY,
 supplier_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 created_by CHAR(36) NOT NULL,
 quote_evidence_ref VARCHAR(160) NOT NULL,
 subtotal DECIMAL(18,2) NOT NULL,
 status ENUM('PENDING','APPROVED_INTERNAL','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_proc_requests_owner(created_by,created_at),
 INDEX idx_proc_requests_status(status,created_at),
 CONSTRAINT fk_proc_req_supplier FOREIGN KEY(supplier_id) REFERENCES proc_suppliers(id),
 CONSTRAINT fk_proc_req_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_proc_req_owner FOREIGN KEY(created_by) REFERENCES auth_users(id),
 CONSTRAINT chk_proc_positive_total CHECK(subtotal>0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_request_items (
 id CHAR(36) NOT NULL PRIMARY KEY,
 request_id CHAR(36) NOT NULL,
 position SMALLINT UNSIGNED NOT NULL,
 product_id CHAR(36) NOT NULL,
 sku_snapshot VARCHAR(100) NOT NULL,
 name_snapshot VARCHAR(350) NOT NULL,
 quantity SMALLINT UNSIGNED NOT NULL,
 quoted_unit_cost DECIMAL(18,2) NOT NULL,
 line_subtotal DECIMAL(18,2) NOT NULL,
 UNIQUE KEY uq_proc_item_position(request_id,position),
 UNIQUE KEY uq_proc_item_sku(request_id,product_id),
 CONSTRAINT fk_proc_item_request FOREIGN KEY(request_id) REFERENCES proc_requests(id),
 CONSTRAINT fk_proc_item_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT chk_proc_item_qty CHECK(quantity BETWEEN 1 AND 1000),
 CONSTRAINT chk_proc_item_cost CHECK(quoted_unit_cost>0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_request_keys (
 actor_id CHAR(36) NOT NULL,
 request_key CHAR(36) NOT NULL,
 request_hash CHAR(64) NOT NULL,
 purchase_request_id CHAR(36) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 PRIMARY KEY(actor_id,request_key),
 CONSTRAINT fk_proc_key_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id),
 CONSTRAINT fk_proc_key_request FOREIGN KEY(purchase_request_id) REFERENCES proc_requests(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_review_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 request_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('APPROVED_INTERNAL','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_attested BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proc_decision_request(request_id),
 CONSTRAINT fk_proc_review_request FOREIGN KEY(request_id) REFERENCES proc_requests(id),
 CONSTRAINT fk_proc_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_po_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 request_id CHAR(36) NOT NULL,
 decision_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 status ENUM('HELD') NOT NULL DEFAULT 'HELD',
 dispatch_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proc_po_request(request_id),
 CONSTRAINT fk_proc_po_request FOREIGN KEY(request_id) REFERENCES proc_requests(id),
 CONSTRAINT fk_proc_po_decision FOREIGN KEY(decision_id) REFERENCES proc_review_decisions(id),
 CONSTRAINT fk_proc_po_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proc_audit_events (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('SUPPLIER','REQUEST','REVIEW','HELD_ORDER') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 action VARCHAR(40) NOT NULL,
 detail_json JSON NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_proc_event_entity(entity_type,entity_id,created_at),
 CONSTRAINT fk_proc_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
