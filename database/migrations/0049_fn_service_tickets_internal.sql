-- Phase 1FN: Internal-only M16 ticket intake and audit. No verified customer consent, SLA, dispatch or repair execution.
CREATE TABLE IF NOT EXISTS service_tickets_internal (
 id CHAR(36) NOT NULL PRIMARY KEY,
 owner_user_id CHAR(36) NOT NULL,
 customer_id CHAR(36) NOT NULL,
 guide_id VARCHAR(64) NULL,
 subject VARCHAR(180) NOT NULL,
 description TEXT NOT NULL,
 priority ENUM('LOW','NORMAL','HIGH') NOT NULL DEFAULT 'NORMAL',
 status ENUM('OPEN_INTERNAL','TRIAGED_INTERNAL','WAITING_INTERNAL','RESOLVED_HELD') NOT NULL DEFAULT 'OPEN_INTERNAL',
 version INT UNSIGNED NOT NULL DEFAULT 1,
 customer_consent_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 external_dispatch_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 INDEX idx_service_tickets_owner (owner_user_id,created_at,id),
 INDEX idx_service_tickets_customer (owner_user_id,customer_id,status),
 CONSTRAINT fk_service_ticket_owner FOREIGN KEY (owner_user_id) REFERENCES auth_users(id),
 CONSTRAINT fk_service_ticket_customer FOREIGN KEY (customer_id) REFERENCES crm_customers(id),
 CONSTRAINT chk_service_ticket_version CHECK (version>=1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS service_ticket_audit_internal (
 id CHAR(36) NOT NULL PRIMARY KEY,
 ticket_id CHAR(36) NOT NULL,
 actor_user_id CHAR(36) NOT NULL,
 operation ENUM('CREATE','STATUS_CHANGE') NOT NULL,
 from_status VARCHAR(32) NULL,
 to_status VARCHAR(32) NOT NULL,
 note VARCHAR(500) NOT NULL,
 version_after INT UNSIGNED NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_service_ticket_audit_version (ticket_id,version_after),
 INDEX idx_service_ticket_audit_actor (actor_user_id,created_at),
 CONSTRAINT fk_service_ticket_audit_ticket FOREIGN KEY (ticket_id) REFERENCES service_tickets_internal(id),
 CONSTRAINT fk_service_ticket_audit_actor FOREIGN KEY (actor_user_id) REFERENCES auth_users(id),
 CONSTRAINT chk_service_ticket_audit_version CHECK (version_after>=1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
