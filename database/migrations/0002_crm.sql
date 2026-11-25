-- Phase 1C: non-destructive master-data CRUD only. No client-editable inventory or receivable balances.
-- Do not execute the legacy database/schema.sql on production.
CREATE TABLE IF NOT EXISTS crm_customers (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  gstin VARCHAR(15) NULL,
  contactPerson VARCHAR(150) NOT NULL,
  email VARCHAR(191) NOT NULL,
  phone VARCHAR(30) NOT NULL,
  city VARCHAR(120) NOT NULL,
  state VARCHAR(120) NOT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at DATETIME(3) NULL,
  INDEX idx_crm_customers_name (name),
  INDEX idx_crm_customers_email (email),
  INDEX idx_crm_customers_gstin (gstin)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crm_leads (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  company VARCHAR(200) NOT NULL,
  email VARCHAR(191) NOT NULL,
  phone VARCHAR(30) NOT NULL,
  source ENUM('WEBSITE','WHATSAPP','INDIAMART','JUSTDIAL','EMAIL','TELEGRAM','REFERRAL','GEM_TENDER','OUTBOUND_HUNTER','HARDWARE_REFRESH','PARTNER_PORTAL','OEM_PASS') NOT NULL,
  status ENUM('NEW','CONTACTED','QUALIFIED','BOM_GENERATED','QUOTED','NEGOTIATING','WON','LOST') NOT NULL DEFAULT 'NEW',
  score ENUM('HOT','WARM','COLD','NURTURE') NOT NULL DEFAULT 'NURTURE',
  scoreReason VARCHAR(500) NOT NULL DEFAULT '',
  intentScore TINYINT UNSIGNED NOT NULL DEFAULT 0,
  requirement TEXT NOT NULL,
  estimatedBudget DECIMAL(18,2) NOT NULL DEFAULT 0.00,
  location VARCHAR(150) NOT NULL DEFAULT '',
  gstin VARCHAR(15) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at DATETIME(3) NULL,
  INDEX idx_crm_leads_status (status),
  INDEX idx_crm_leads_company (company),
  INDEX idx_crm_leads_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crm_products (
  id CHAR(36) PRIMARY KEY,
  sku VARCHAR(100) NOT NULL,
  brand VARCHAR(120) NOT NULL,
  model VARCHAR(200) NOT NULL,
  category ENUM('LAPTOP','DESKTOP','SERVER','NETWORKING','POWER_STORAGE','ACCESSORIES') NOT NULL,
  specs TEXT NOT NULL,
  unitCost DECIMAL(18,2) NOT NULL,
  freightCost DECIMAL(18,2) NOT NULL DEFAULT 0,
  riskBuffer DECIMAL(18,2) NOT NULL DEFAULT 0,
  sellingPrice DECIMAL(18,2) NOT NULL,
  minPrice DECIMAL(18,2) NOT NULL,
  gstRate DECIMAL(5,2) NOT NULL DEFAULT 18.00,
  hsn VARCHAR(16) NOT NULL,
  warrantyMonths SMALLINT UNSIGNED NOT NULL DEFAULT 12,
  leadTimeDays SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at DATETIME(3) NULL,
  UNIQUE KEY uq_crm_product_sku (sku),
  INDEX idx_crm_product_brand (brand)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crm_audit_events (
  id CHAR(36) NOT NULL PRIMARY KEY,
  actor_user_id CHAR(36) NOT NULL,
  entity_type ENUM('customers','leads','products') NOT NULL,
  entity_id CHAR(36) NOT NULL,
  operation ENUM('CREATE','UPDATE','DELETE') NOT NULL,
  before_data JSON NULL,
  after_data JSON NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_crm_audit_entity (entity_type, entity_id, created_at),
  INDEX idx_crm_audit_actor (actor_user_id),
  CONSTRAINT fk_crm_audit_owner FOREIGN KEY (actor_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
