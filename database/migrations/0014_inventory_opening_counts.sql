-- Phase 1AB. Explicit owner-attested opening counts ONLY. No reserved or available stock.
-- No legacy imports, implicit default warehouses, procurement receipts, sales issues or resets.
CREATE TABLE IF NOT EXISTS inventory_sites (
  id CHAR(36) NOT NULL PRIMARY KEY,
  code VARCHAR(32) NOT NULL,
  name VARCHAR(120) NOT NULL,
  created_by CHAR(36) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_inventory_site_code (code),
  CONSTRAINT fk_inventory_site_owner FOREIGN KEY (created_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inventory_opening_counts (
  id CHAR(36) NOT NULL PRIMARY KEY,
  product_id CHAR(36) NOT NULL,
  site_id CHAR(36) NOT NULL,
  quantity INT UNSIGNED NOT NULL,
  evidence_ref VARCHAR(160) NOT NULL,
  attested_by CHAR(36) NOT NULL,
  recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_inventory_opening_pair (product_id,site_id),
  INDEX idx_inventory_opening_site (site_id,recorded_at),
  CONSTRAINT fk_inventory_count_product FOREIGN KEY (product_id) REFERENCES crm_products(id),
  CONSTRAINT fk_inventory_count_site FOREIGN KEY (site_id) REFERENCES inventory_sites(id),
  CONSTRAINT fk_inventory_count_owner FOREIGN KEY (attested_by) REFERENCES auth_users(id),
  CONSTRAINT chk_inventory_opening_quantity CHECK (quantity<=1000000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A reservation is committed together with its count, serializing concurrent retries.
CREATE TABLE IF NOT EXISTS inventory_opening_requests (
  actor_id CHAR(36) NOT NULL,
  request_key CHAR(36) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  count_id CHAR(36) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (actor_id,request_key),
  CONSTRAINT fk_inventory_request_actor FOREIGN KEY (actor_id) REFERENCES auth_users(id),
  CONSTRAINT fk_inventory_request_count FOREIGN KEY (count_id) REFERENCES inventory_opening_counts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
