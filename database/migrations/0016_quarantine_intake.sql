-- Phase 1AD: internal inbound observations and QUARANTINED custody only.
-- HELD PO is never evidence of supplier dispatch. No available/reserved stock or COGS.
CREATE TABLE IF NOT EXISTS inv_inbound_observations (
  id CHAR(36) NOT NULL PRIMARY KEY,
  hold_id CHAR(36) NOT NULL,
  request_id CHAR(36) NOT NULL,
  site_id CHAR(36) NOT NULL,
  recorded_by CHAR(36) NOT NULL,
  delivery_evidence_ref VARCHAR(160) NOT NULL,
  physical_count_ref VARCHAR(160) NOT NULL,
  payload_sha256 CHAR(64) NOT NULL,
  status ENUM('AWAITING_WITNESS','QUARANTINED_INTERNAL','REJECTED_INTERNAL') NOT NULL DEFAULT 'AWAITING_WITNESS',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  decided_at DATETIME(3) NULL,
  UNIQUE KEY uq_inv_inbound_hold (hold_id),
  INDEX idx_inv_inbound_status (status,created_at),
  CONSTRAINT fk_inv_inbound_hold FOREIGN KEY (hold_id) REFERENCES proc_po_holds(id),
  CONSTRAINT fk_inv_inbound_request FOREIGN KEY (request_id) REFERENCES proc_requests(id),
  CONSTRAINT fk_inv_inbound_site FOREIGN KEY (site_id) REFERENCES inventory_sites(id),
  CONSTRAINT fk_inv_inbound_actor FOREIGN KEY (recorded_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_inbound_lines (
  id CHAR(36) NOT NULL PRIMARY KEY,
  observation_id CHAR(36) NOT NULL,
  product_id CHAR(36) NOT NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  tracking_mode ENUM('SERIAL','LOT') NOT NULL,
  lot_code VARCHAR(80) NULL,
  serials_json JSON NOT NULL,
  UNIQUE KEY uq_inv_inbound_line (observation_id,product_id),
  CONSTRAINT fk_inv_line_observation FOREIGN KEY (observation_id) REFERENCES inv_inbound_observations(id),
  CONSTRAINT fk_inv_line_product FOREIGN KEY (product_id) REFERENCES crm_products(id),
  CONSTRAINT chk_inv_inbound_quantity CHECK (quantity BETWEEN 1 AND 1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_inbound_request_keys (
  actor_id CHAR(36) NOT NULL,
  request_key CHAR(36) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  observation_id CHAR(36) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (actor_id,request_key),
  CONSTRAINT fk_inv_intake_key_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id),
  CONSTRAINT fk_inv_intake_key_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_inbound_decisions (
  id CHAR(36) NOT NULL PRIMARY KEY,
  observation_id CHAR(36) NOT NULL,
  reviewer_id CHAR(36) NOT NULL,
  outcome ENUM('ACCEPT_QUARANTINE','REJECT_INTERNAL') NOT NULL,
  inspection_evidence_ref VARCHAR(160) NOT NULL,
  reason VARCHAR(1000) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_inv_inbound_decision (observation_id),
  CONSTRAINT fk_inv_decision_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
  CONSTRAINT fk_inv_decision_reviewer FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Unique serial per product across internally witnessed quarantine observations.
-- A duplicate blocks acceptance and rolls back the entire witness transaction.
CREATE TABLE IF NOT EXISTS inv_quarantine_serials (
  id CHAR(36) NOT NULL PRIMARY KEY,
  observation_id CHAR(36) NOT NULL,
  product_id CHAR(36) NOT NULL,
  site_id CHAR(36) NOT NULL,
  serial_number VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_inv_quarantine_product_serial (product_id,serial_number),
  INDEX idx_inv_quarantine_observation (observation_id),
  CONSTRAINT fk_inv_serial_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
  CONSTRAINT fk_inv_serial_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
  CONSTRAINT fk_inv_serial_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Append-only evidence of physical observation, NOT a financial or sellable-stock ledger.
CREATE TABLE IF NOT EXISTS inv_quarantine_custody_events (
  id CHAR(36) NOT NULL PRIMARY KEY,
  observation_id CHAR(36) NOT NULL,
  line_id CHAR(36) NOT NULL,
  site_id CHAR(36) NOT NULL,
  product_id CHAR(36) NOT NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  event_type ENUM('QUARANTINE_WITNESS_ATTESTED') NOT NULL DEFAULT 'QUARANTINE_WITNESS_ATTESTED',
  recorded_by CHAR(36) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_inv_custody_line_event (line_id,event_type),
  INDEX idx_inv_custody_site_product (site_id,product_id),
  CONSTRAINT fk_inv_custody_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
  CONSTRAINT fk_inv_custody_line FOREIGN KEY(line_id) REFERENCES inv_inbound_lines(id),
  CONSTRAINT fk_inv_custody_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
  CONSTRAINT fk_inv_custody_product FOREIGN KEY(product_id) REFERENCES crm_products(id),
  CONSTRAINT fk_inv_custody_actor FOREIGN KEY(recorded_by) REFERENCES auth_users(id),
  CONSTRAINT chk_inv_custody_quantity CHECK(quantity BETWEEN 1 AND 1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_inbound_audit (
  id CHAR(36) NOT NULL PRIMARY KEY,
  observation_id CHAR(36) NOT NULL,
  actor_id CHAR(36) NOT NULL,
  event_type ENUM('OBSERVATION_RECORDED','QUARANTINE_ATTESTED','OBSERVATION_REJECTED') NOT NULL,
  event_hash CHAR(64) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_inv_inbound_audit_observation (observation_id,created_at),
  CONSTRAINT fk_inv_audit_observation FOREIGN KEY(observation_id) REFERENCES inv_inbound_observations(id),
  CONSTRAINT fk_inv_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
