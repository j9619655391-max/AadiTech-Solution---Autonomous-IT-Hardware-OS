-- Phase 1GA: immutable internal work-order/RMA planning; no real fulfillment.
CREATE TABLE IF NOT EXISTS field_service_plans_internal (
 id CHAR(36) NOT NULL PRIMARY KEY,
 ticket_id CHAR(36) NOT NULL,
 owner_user_id CHAR(36) NOT NULL,
 source_ticket_version INT UNSIGNED NOT NULL,
 kind ENUM('WORK_ORDER','RMA') NOT NULL,
 note VARCHAR(500) NOT NULL,
 status ENUM('PLANNING_HELD') NOT NULL DEFAULT 'PLANNING_HELD',
 customer_consent_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 external_dispatch_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ga_ticket_kind (ticket_id,kind),
 CONSTRAINT fk_ga_plan_ticket FOREIGN KEY (ticket_id) REFERENCES service_tickets_internal(id),
 CONSTRAINT fk_ga_plan_owner FOREIGN KEY (owner_user_id) REFERENCES auth_users(id),
 CONSTRAINT chk_ga_plan_version CHECK (source_ticket_version>=2 AND source_ticket_version<1000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS field_service_plan_audit_internal (
 plan_id CHAR(36) NOT NULL PRIMARY KEY,
 actor_user_id CHAR(36) NOT NULL,
 operation ENUM('CREATE_HELD') NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_ga_audit_plan FOREIGN KEY (plan_id) REFERENCES field_service_plans_internal(id),
 CONSTRAINT fk_ga_audit_actor FOREIGN KEY (actor_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
