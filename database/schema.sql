-- ==============================================================================
-- IT HARDWARE PLATFORM - PRODUCTION MYSQL DATABASE SCHEMA
-- Target: Hostinger Business Shared Web Hosting (MySQL 8.0+ / MariaDB 10.4+)
-- Management: phpMyAdmin / Hostinger Databases
-- Character Set: utf8mb4 / utf8mb4_unicode_ci
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+05:30"; -- Indian Standard Time (IST)

-- ------------------------------------------------------------------------------
-- 1. Table: app_users (Multi-Role Authentication)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `app_users`;
CREATE TABLE `app_users` (
  `id` VARCHAR(50) NOT NULL,
  `email` VARCHAR(191) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `full_name` VARCHAR(100) NOT NULL,
  `phone` VARCHAR(20) DEFAULT NULL,
  `role` ENUM('SUPER_ADMIN', 'SALES_ENGINEER', 'ACCOUNTS_FINANCE', 'WAREHOUSE_LOGISTICS') NOT NULL DEFAULT 'SALES_ENGINEER',
  `status` ENUM('ACTIVE', 'SUSPENDED', 'PENDING') NOT NULL DEFAULT 'ACTIVE',
  `telegram_chat_id` VARCHAR(50) DEFAULT NULL,
  `last_login` DATETIME DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 2. Table: company_profiles (AadiTech Master Credentials & Tax Rules)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `company_profiles`;
CREATE TABLE `company_profiles` (
  `id` VARCHAR(50) NOT NULL,
  `name` VARCHAR(150) NOT NULL,
  `legal_entity` VARCHAR(150) NOT NULL,
  `gstin` VARCHAR(20) NOT NULL,
  `pan` VARCHAR(15) NOT NULL,
  `website` VARCHAR(100) NOT NULL,
  `phone` VARCHAR(30) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `registered_address` TEXT NOT NULL,
  `warehouse_address` TEXT NOT NULL,
  `bank_name` VARCHAR(100) NOT NULL,
  `bank_account_no` VARCHAR(50) NOT NULL,
  `bank_ifsc` VARCHAR(20) NOT NULL,
  `default_margin_threshold` DECIMAL(5,2) NOT NULL DEFAULT 15.00,
  `telegram_bot_token` VARCHAR(150) DEFAULT NULL,
  `telegram_admin_chat_id` VARCHAR(50) DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 3. Table: customers (Customer 360 & Credit Intelligence)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `customers`;
CREATE TABLE `customers` (
  `id` VARCHAR(50) NOT NULL,
  `name` VARCHAR(150) NOT NULL,
  `gstin` VARCHAR(20) NOT NULL,
  `contact_person` VARCHAR(100) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `phone` VARCHAR(30) NOT NULL,
  `city` VARCHAR(60) NOT NULL,
  `state` VARCHAR(60) NOT NULL DEFAULT 'Maharashtra',
  `state_code` VARCHAR(5) NOT NULL DEFAULT '27',
  `credit_limit` DECIMAL(12,2) NOT NULL DEFAULT 1000000.00,
  `current_outstanding` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `payment_risk_score` ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL DEFAULT 'LOW',
  `payment_terms` VARCHAR(50) NOT NULL DEFAULT '30_DAYS_NET',
  `lifetime_value` DECIMAL(14,2) NOT NULL DEFAULT 0.00,
  `total_orders` INT NOT NULL DEFAULT 0,
  `last_purchase_date` DATE DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_customer_gstin` (`gstin`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 4. Table: leads (6-Channel Inbound & Outbound Pipeline)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `leads`;
CREATE TABLE `leads` (
  `id` VARCHAR(50) NOT NULL,
  `name` VARCHAR(100) NOT NULL,
  `company` VARCHAR(150) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `phone` VARCHAR(30) NOT NULL,
  `source` VARCHAR(50) NOT NULL,
  `status` ENUM('NEW', 'CONTACTED', 'QUALIFIED', 'PROPOSAL_SENT', 'WON', 'LOST') NOT NULL DEFAULT 'QUALIFIED',
  `score` ENUM('HOT', 'WARM', 'COLD', 'NURTURE') NOT NULL DEFAULT 'HOT',
  `score_reason` TEXT DEFAULT NULL,
  `intent_score` INT NOT NULL DEFAULT 85,
  `requirement` TEXT NOT NULL,
  `estimated_budget` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `location` VARCHAR(100) NOT NULL DEFAULT 'Mumbai',
  `gstin` VARCHAR(20) DEFAULT NULL,
  `tender_number` VARCHAR(100) DEFAULT NULL,
  `bid_closing_date` VARCHAR(50) DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_lead_source` (`source`),
  KEY `idx_lead_score` (`score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 5. Table: products_catalog (IT Hardware Master Catalog & HSN)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `products_catalog`;
CREATE TABLE `products_catalog` (
  `id` VARCHAR(50) NOT NULL,
  `sku` VARCHAR(100) NOT NULL UNIQUE,
  `name` VARCHAR(200) NOT NULL,
  `brand` VARCHAR(80) NOT NULL,
  `category` VARCHAR(80) NOT NULL,
  `distributor_buy_price` DECIMAL(12,2) NOT NULL,
  `list_price` DECIMAL(12,2) NOT NULL,
  `hsn_code` VARCHAR(20) NOT NULL DEFAULT '8471',
  `gst_rate` DECIMAL(5,2) NOT NULL DEFAULT 18.00,
  `stock_quantity` INT NOT NULL DEFAULT 10,
  `warehouse_location` VARCHAR(100) NOT NULL DEFAULT 'Bhiwandi Central Hub',
  `warranty_months` INT NOT NULL DEFAULT 36,
  `is_active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_product_sku` (`sku`),
  KEY `idx_product_brand` (`brand`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 6. Table: quotations (GST Tax Quotations & Margin Audits)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `quotations`;
CREATE TABLE `quotations` (
  `id` VARCHAR(50) NOT NULL,
  `quote_number` VARCHAR(50) NOT NULL UNIQUE,
  `customer_name` VARCHAR(150) NOT NULL,
  `customer_gstin` VARCHAR(20) NOT NULL,
  `lead_id` VARCHAR(50) DEFAULT NULL,
  `total_taxable` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `total_gst` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `grand_total` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `net_margin_pct` DECIMAL(5,2) NOT NULL DEFAULT 16.50,
  `status` ENUM('DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'DISPATCHED', 'WON', 'REJECTED') NOT NULL DEFAULT 'APPROVED',
  `approval_status` ENUM('NOT_REQUIRED', 'PENDING', 'APPROVED', 'REJECTED') NOT NULL DEFAULT 'NOT_REQUIRED',
  `approval_note` TEXT DEFAULT NULL,
  `quotation_data_json` LONGTEXT NOT NULL,
  `created_by` VARCHAR(100) NOT NULL DEFAULT 'Sales Team',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_quote_number` (`quote_number`),
  KEY `idx_quote_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 7. Table: sales_orders (Confirmed Orders, Invoices & Dispatch)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `sales_orders`;
CREATE TABLE `sales_orders` (
  `id` VARCHAR(50) NOT NULL,
  `order_number` VARCHAR(50) NOT NULL UNIQUE,
  `quote_id` VARCHAR(50) DEFAULT NULL,
  `customer_name` VARCHAR(150) NOT NULL,
  `customer_gstin` VARCHAR(20) NOT NULL,
  `total_amount` DECIMAL(12,2) NOT NULL,
  `payment_status` ENUM('UNPAID', 'PARTIALLY_PAID', 'PAID', 'CREDIT_HOLD') NOT NULL DEFAULT 'UNPAID',
  `order_status` ENUM('CONFIRMED', 'ALLOCATED', 'PACKED', 'DISPATCHED', 'DELIVERED', 'CANCELLED') NOT NULL DEFAULT 'CONFIRMED',
  `eway_bill_number` VARCHAR(50) DEFAULT NULL,
  `courier_name` VARCHAR(100) DEFAULT NULL,
  `awb_number` VARCHAR(50) DEFAULT NULL,
  `tracking_status` VARCHAR(100) DEFAULT 'Ready for Dispatch',
  `serial_numbers_json` TEXT DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_order_number` (`order_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 8. Table: purchase_orders (Back-to-Back Distributor POs)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `purchase_orders`;
CREATE TABLE `purchase_orders` (
  `id` VARCHAR(50) NOT NULL,
  `po_number` VARCHAR(50) NOT NULL UNIQUE,
  `sales_order_id` VARCHAR(50) DEFAULT NULL,
  `distributor_name` VARCHAR(150) NOT NULL,
  `distributor_gstin` VARCHAR(20) NOT NULL,
  `total_cost` DECIMAL(12,2) NOT NULL,
  `status` ENUM('DRAFT', 'SENT_TO_DISTRIBUTOR', 'CONFIRMED', 'DELIVERED_TO_BHIWANDI') NOT NULL DEFAULT 'SENT_TO_DISTRIBUTOR',
  `expected_delivery_date` DATE DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 9. Table: gem_tenders (GeM & PSU Bids Pipeline)
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `gem_tenders`;
CREATE TABLE `gem_tenders` (
  `id` VARCHAR(50) NOT NULL,
  `bid_number` VARCHAR(100) NOT NULL UNIQUE,
  `title` VARCHAR(255) NOT NULL,
  `department_name` VARCHAR(150) NOT NULL,
  `ministry` VARCHAR(150) NOT NULL,
  `estimated_budget` DECIMAL(12,2) NOT NULL,
  `bid_closing_date` VARCHAR(50) NOT NULL,
  `emd_amount` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `turnkey_margin_estimate` DECIMAL(5,2) NOT NULL DEFAULT 25.00,
  `specs` TEXT NOT NULL,
  `status` ENUM('OPEN', 'ANALYZING', 'BID_SUBMITTED', 'WON', 'ARCHIVED') NOT NULL DEFAULT 'OPEN',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 10. Table: audit_logs & telegram_events
-- ------------------------------------------------------------------------------
DROP TABLE IF EXISTS `audit_logs`;
CREATE TABLE `audit_logs` (
  `id` VARCHAR(50) NOT NULL,
  `event_type` VARCHAR(100) NOT NULL,
  `actor` VARCHAR(100) NOT NULL,
  `details` TEXT NOT NULL,
  `severity` ENUM('INFO', 'WARNING', 'CRITICAL') NOT NULL DEFAULT 'INFO',
  `ip_address` VARCHAR(50) DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==============================================================================
-- INITIAL SEED DATA (AadiTech Solution Master Record)
-- ==============================================================================

INSERT INTO `company_profiles` (
  `id`, `name`, `legal_entity`, `gstin`, `pan`, `website`, `phone`, `email`,
  `registered_address`, `warehouse_address`, `bank_name`, `bank_account_no`, `bank_ifsc`, `default_margin_threshold`
) VALUES (
  'aaditech-master',
  'AadiTech Solution',
  'AadiTech Solution Private Limited',
  '27AAACA1234A1Z5',
  'AAACA1234A',
  'https://aaditechs.in',
  '+91 22 2890 1234',
  'info@aaditechs.in',
  'Unit 402, Quantum Tech Park, Andheri East, Mumbai, Maharashtra 400069',
  'Warehouse Block B-4, Logistic Park, Mankoli Naka, Bhiwandi, Thane 421302',
  'HDFC Bank Limited',
  '50200089123456',
  'HDFC0000123',
  15.00
) ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `app_users` (
  `id`, `email`, `password_hash`, `full_name`, `phone`, `role`, `status`
) VALUES (
  'usr-admin-01',
  'admin@aaditechs.in',
  '$2y$10$YourBcryptPasswordHashHereForHostinger', -- Placeholder bcrypt hash for initial setup
  'AadiTech Director / Super Admin',
  '+91 96196 55391',
  'SUPER_ADMIN',
  'ACTIVE'
) ON DUPLICATE KEY UPDATE `full_name` = VALUES(`full_name`);

SET FOREIGN_KEY_CHECKS = 1;
COMMIT;
