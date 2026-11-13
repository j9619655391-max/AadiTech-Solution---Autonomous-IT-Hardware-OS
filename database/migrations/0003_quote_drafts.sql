-- Phase 1E: DRAFT ONLY. No approval, sending, reservation, invoices or orders.
CREATE TABLE IF NOT EXISTS sales_quote_drafts (
  id CHAR(36) NOT NULL PRIMARY KEY,
  customer_id CHAR(36) NOT NULL,
  lead_id CHAR(36) NULL,
  created_by CHAR(36) NOT NULL,
  status ENUM('DRAFT') NOT NULL DEFAULT 'DRAFT',
  currency CHAR(3) NOT NULL DEFAULT 'INR',
  subtotal DECIMAL(18,2) NOT NULL,
  tax_estimate DECIMAL(18,2) NOT NULL,
  total_estimate DECIMAL(18,2) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_quote_customer (customer_id,created_at),
  CONSTRAINT fk_quote_customer FOREIGN KEY (customer_id) REFERENCES crm_customers(id),
  CONSTRAINT fk_quote_lead FOREIGN KEY (lead_id) REFERENCES crm_leads(id),
  CONSTRAINT fk_quote_actor FOREIGN KEY (created_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sales_quote_draft_items (
  id CHAR(36) NOT NULL PRIMARY KEY,
  quote_id CHAR(36) NOT NULL,
  position SMALLINT UNSIGNED NOT NULL,
  product_id CHAR(36) NOT NULL,
  sku_snapshot VARCHAR(100) NOT NULL,
  name_snapshot VARCHAR(350) NOT NULL,
  hsn_snapshot VARCHAR(16) NOT NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  unit_cost DECIMAL(18,2) NOT NULL,
  unit_price DECIMAL(18,2) NOT NULL,
  gst_rate DECIMAL(5,2) NOT NULL,
  line_subtotal DECIMAL(18,2) NOT NULL,
  line_tax_estimate DECIMAL(18,2) NOT NULL,
  UNIQUE KEY uq_quote_position (quote_id,position),
  INDEX idx_quote_product (product_id),
  CONSTRAINT fk_quote_draft FOREIGN KEY (quote_id) REFERENCES sales_quote_drafts(id),
  CONSTRAINT fk_quote_product FOREIGN KEY (product_id) REFERENCES crm_products(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
