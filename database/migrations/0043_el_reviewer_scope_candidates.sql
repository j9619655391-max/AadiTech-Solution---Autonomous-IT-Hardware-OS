-- Phase 1EL. Additive, non-destructive internal reviewer nomination scope.
-- NO grants are automatically populated from historic reviewer role or claims.
-- These are application workflow grants, NOT verified independent legal authority.
CREATE TABLE IF NOT EXISTS app_reviewer_scope_grants (
 owner_user_id CHAR(36) NOT NULL,
 reviewer_user_id CHAR(36) NOT NULL,
 workflow_scope ENUM('QUOTES','PROCUREMENT') NOT NULL,
 state ENUM('ACTIVE','REVOKED') NOT NULL DEFAULT 'ACTIVE',
 nominated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
 PRIMARY KEY (owner_user_id,reviewer_user_id,workflow_scope),
 INDEX idx_el_reviewer_queue (reviewer_user_id,workflow_scope,state,owner_user_id),
 CONSTRAINT fk_el_scope_owner FOREIGN KEY(owner_user_id) REFERENCES auth_users(id),
 CONSTRAINT fk_el_scope_reviewer FOREIGN KEY(reviewer_user_id) REFERENCES auth_users(id),
 CONSTRAINT chk_el_distinct_reviewer CHECK (owner_user_id<>reviewer_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS app_reviewer_scope_events (
 id CHAR(36) NOT NULL PRIMARY KEY,
 owner_user_id CHAR(36) NOT NULL,
 reviewer_user_id CHAR(36) NOT NULL,
 workflow_scope ENUM('QUOTES','PROCUREMENT') NOT NULL,
 decision ENUM('GRANT','REVOKE') NOT NULL,
 reason VARCHAR(500) NOT NULL,
 recorded_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_el_scope_history (owner_user_id,reviewer_user_id,workflow_scope,recorded_at),
 CONSTRAINT fk_el_scope_event_owner FOREIGN KEY(owner_user_id) REFERENCES auth_users(id),
 CONSTRAINT fk_el_scope_event_reviewer FOREIGN KEY(reviewer_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Future first-class corporate membership is CANDIDATE-ONLY.
-- Never attach existing CRM/order/stock rows without authenticated mandate.
CREATE TABLE IF NOT EXISTS app_organization_candidates (
 id CHAR(36) NOT NULL PRIMARY KEY,
 claimed_legal_name VARCHAR(200) NOT NULL,
 submitted_by CHAR(36) NOT NULL,
 authority_state ENUM('UNVERIFIED','QUARANTINED') NOT NULL DEFAULT 'UNVERIFIED',
 legal_registry_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 signatory_mandate_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 production_tenant_activated ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_el_org_claim_submitter FOREIGN KEY(submitted_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS app_organization_member_candidates (
 organization_id CHAR(36) NOT NULL,
 candidate_user_id CHAR(36) NOT NULL,
 requested_role ENUM('OWNER','REVIEWER') NOT NULL,
 membership_state ENUM('UNVERIFIED_CANDIDATE') NOT NULL DEFAULT 'UNVERIFIED_CANDIDATE',
 grant_business_data_access ENUM('NO') NOT NULL DEFAULT 'NO',
 PRIMARY KEY(organization_id,candidate_user_id),
 CONSTRAINT fk_el_org_candidate FOREIGN KEY(organization_id) REFERENCES app_organization_candidates(id),
 CONSTRAINT fk_el_org_member_candidate FOREIGN KEY(candidate_user_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
