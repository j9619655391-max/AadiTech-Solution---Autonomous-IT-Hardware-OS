-- Forward-only role expansion; existing OWNER accounts and sessions remain.
ALTER TABLE auth_users MODIFY COLUMN role ENUM('OWNER','REVIEWER') NOT NULL DEFAULT 'OWNER';
CREATE TABLE IF NOT EXISTS auth_reviewer_provision_events (
  id CHAR(36) NOT NULL PRIMARY KEY,
  reviewer_user_id CHAR(36) NOT NULL,
  provisioned_by CHAR(36) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_provisioned_reviewer (reviewer_user_id),
  CONSTRAINT fk_reviewer_provisioned FOREIGN KEY (reviewer_user_id) REFERENCES auth_users(id),
  CONSTRAINT fk_reviewer_provisioner FOREIGN KEY (provisioned_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
