-- Phase 1AH: proposed internal double-entry only; never an operational inventory ledger.
-- Explicit external provenance blockers MUST remain false. 1AG hard-zero gates untouched.
CREATE TABLE IF NOT EXISTS inv_unposted_journal_headers (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_intent_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 release_sha256 CHAR(64) NOT NULL,
 manifest_sha256 CHAR(64) NOT NULL,
 manifest_json JSON NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_HELD','REJECTED_INTERNAL')
  NOT NULL DEFAULT 'PENDING_INTERNAL',
 posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_unposted_journal_release(release_intent_id),
 CONSTRAINT fk_unposted_header_release FOREIGN KEY(release_intent_id) REFERENCES inv_stock_release_intents(id),
 CONSTRAINT fk_unposted_header_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_unposted_header_owner FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_unposted_journal_legs (
 id CHAR(36) NOT NULL PRIMARY KEY,
 journal_id CHAR(36) NOT NULL,
 product_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 account_code ENUM('QUARANTINE_EVIDENCE','RELEASE_CANDIDATE_EVIDENCE') NOT NULL,
 entry_side ENUM('DEBIT','CREDIT') NOT NULL,
 quantity SMALLINT UNSIGNED NOT NULL,
 tracking_mode ENUM('SERIAL','LOT') NOT NULL,
 lot_code VARCHAR(80) NULL,
 serials_json JSON NOT NULL,
 leg_sha256 CHAR(64) NOT NULL,
 posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 UNIQUE KEY uq_unposted_journal_leg(journal_id,product_id,account_code),
 INDEX idx_unposted_leg_product_site(product_id,site_id),
 CONSTRAINT fk_unposted_leg_header FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id),
 CONSTRAINT fk_unposted_leg_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT fk_unposted_leg_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT chk_unposted_leg_quantity CHECK(quantity BETWEEN 1 AND 1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Unverified SERIAL CANDIDATE, NOT legal serial title or warehouse ownership.
CREATE TABLE IF NOT EXISTS inv_unposted_serial_candidates (
 id CHAR(36) NOT NULL PRIMARY KEY,
 journal_id CHAR(36) NOT NULL,
 product_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 serial_number VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 provenance_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 ownership_state ENUM('NOT_ESTABLISHED') NOT NULL DEFAULT 'NOT_ESTABLISHED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_unposted_serial_candidate(product_id,serial_number),
 INDEX idx_unposted_serial_journal(journal_id),
 CONSTRAINT fk_unposted_serial_journal FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id),
 CONSTRAINT fk_unposted_serial_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT fk_unposted_serial_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One immutable hard-denial record per journal: no authenticated supplier, verified
-- shipment, official GRN or authorized sellable inventory credit in this phase.
CREATE TABLE IF NOT EXISTS inv_unposted_source_blockers (
 journal_id CHAR(36) NOT NULL PRIMARY KEY,
 external_po_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 supplier_ack_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 official_grn_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 warehouse_release_authorized ENUM('NO') NOT NULL DEFAULT 'NO',
 stock_credit_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_unposted_blocker_journal FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_unposted_journal_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 journal_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 review_evidence_ref VARCHAR(160) NOT NULL,
 balancing_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_unposted_journal_review(journal_id),
 CONSTRAINT fk_unposted_review_journal FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id),
 CONSTRAINT fk_unposted_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_unposted_journal_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 journal_id CHAR(36) NOT NULL,
 review_id CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 state ENUM('HELD') NOT NULL DEFAULT 'HELD',
 posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_unposted_journal_hold(journal_id),
 CONSTRAINT fk_unposted_hold_journal FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id),
 CONSTRAINT fk_unposted_hold_review FOREIGN KEY(review_id) REFERENCES inv_unposted_journal_reviews(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_unposted_journal_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 journal_id CHAR(36) NOT NULL,
 actor_id CHAR(36) NOT NULL,
 event_type ENUM('JOURNAL_PROPOSED','JOURNAL_HELD','JOURNAL_REJECTED') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_unposted_journal_audit(journal_id,created_at),
 CONSTRAINT fk_unposted_audit_journal FOREIGN KEY(journal_id) REFERENCES inv_unposted_journal_headers(id),
 CONSTRAINT fk_unposted_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
