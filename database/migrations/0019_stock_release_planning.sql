-- Phase 1AG. Inventory ledger FOUNDATION only; no authoritative stock postings.
-- A hold/reconciliation from 1AF is NOT an authenticated GRN or receipt.
-- Hard-zero DB constraints make even accidental positive stock/reserve state fail.
CREATE TABLE IF NOT EXISTS inv_stock_position_gates (
 site_id CHAR(36) NOT NULL,
 product_id CHAR(36) NOT NULL,
 available_quantity INT NOT NULL DEFAULT 0,
 reserved_quantity INT NOT NULL DEFAULT 0,
 picked_quantity INT NOT NULL DEFAULT 0,
 posted_quantity INT NOT NULL DEFAULT 0,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 PRIMARY KEY(site_id,product_id),
 CONSTRAINT fk_position_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_position_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT chk_position_nonnegative CHECK(
  available_quantity>=0 AND reserved_quantity>=0 AND picked_quantity>=0 AND posted_quantity>=0),
 CONSTRAINT chk_position_hard_zero CHECK(
  available_quantity=0 AND reserved_quantity=0 AND picked_quantity=0 AND posted_quantity=0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_stock_release_intents (
 id CHAR(36) NOT NULL PRIMARY KEY,
 held_grn_id CHAR(36) NOT NULL,
 observation_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 source_sha256 CHAR(64) NOT NULL,
 intent_sha256 CHAR(64) NOT NULL,
 intent_json JSON NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_HELD','REJECTED_INTERNAL')
  NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_release_held_grn (held_grn_id),
 UNIQUE KEY uq_release_observation (observation_id),
 CONSTRAINT fk_release_held_grn FOREIGN KEY(held_grn_id) REFERENCES inv_grn_held_records(id),
 CONSTRAINT fk_release_obs FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
 CONSTRAINT fk_release_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_stock_intent_preparer FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_stock_release_intent_lines (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_intent_id CHAR(36) NOT NULL,
 product_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 observed_quantity SMALLINT UNSIGNED NOT NULL,
 tracking_mode ENUM('SERIAL','LOT') NOT NULL,
 lot_code VARCHAR(80) NULL,
 serials_json JSON NOT NULL,
 UNIQUE KEY uq_release_intent_line(release_intent_id,product_id),
 CONSTRAINT fk_release_line_intent FOREIGN KEY(release_intent_id) REFERENCES inv_stock_release_intents(id),
 CONSTRAINT fk_release_line_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT fk_release_line_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT chk_release_line_qty CHECK(observed_quantity BETWEEN 1 AND 1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_stock_release_decisions (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_intent_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 source_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_release_decision(release_intent_id),
 CONSTRAINT fk_release_decision FOREIGN KEY(release_intent_id) REFERENCES inv_stock_release_intents(id),
 CONSTRAINT fk_release_reviewer FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_stock_release_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_intent_id CHAR(36) NOT NULL,
 decision_id CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 state ENUM('HELD') NOT NULL DEFAULT 'HELD',
 posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_release_hold_intent(release_intent_id),
 CONSTRAINT fk_release_hold_intent FOREIGN KEY(release_intent_id) REFERENCES inv_stock_release_intents(id),
 CONSTRAINT fk_release_hold_decision FOREIGN KEY(decision_id) REFERENCES inv_stock_release_decisions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Planning ONLY, not stock allocation. Cannot request more than observed,
-- but all actual allocation and available balances remain exactly zero.
CREATE TABLE IF NOT EXISTS inv_reservation_planning_intents (
 id CHAR(36) NOT NULL PRIMARY KEY,
 release_intent_id CHAR(36) NOT NULL,
 site_id CHAR(36) NOT NULL,
 product_id CHAR(36) NOT NULL,
 requested_quantity SMALLINT UNSIGNED NOT NULL,
 planning_ref VARCHAR(160) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 intent_sha256 CHAR(64) NOT NULL,
 state ENUM('HELD') NOT NULL DEFAULT 'HELD',
 reservation_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_reservation_plan_line(release_intent_id,product_id),
 CONSTRAINT fk_reservation_release FOREIGN KEY(release_intent_id) REFERENCES inv_stock_release_intents(id),
 CONSTRAINT fk_reservation_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
 CONSTRAINT fk_reservation_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_reservation_owner FOREIGN KEY(prepared_by) REFERENCES auth_users(id),
 CONSTRAINT chk_reservation_plan_qty CHECK(requested_quantity BETWEEN 1 AND 1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_stock_foundation_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('RELEASE','PLAN') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('RELEASE_PREPARED','RELEASE_HELD','RELEASE_REJECTED','PLAN_HELD') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_stock_audit(entity_type,entity_id,created_at),
 CONSTRAINT fk_stock_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
