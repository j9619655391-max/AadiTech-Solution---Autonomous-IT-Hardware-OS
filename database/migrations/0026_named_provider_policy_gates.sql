-- Phase 1AN: nominated named Indian licensed CA and independently assessed policy/registry prerequisite.
-- Every record is nonproduction. NO raw credentials, independently verified company identity or stock release.
CREATE TABLE IF NOT EXISTS inv_provider_named_nominations (
 id CHAR(36) NOT NULL PRIMARY KEY,
 provider_code ENUM('EMUDHRA_INDIA_CCA') NOT NULL,
 legal_name VARCHAR(160) NOT NULL,
 regulatory_source_url VARCHAR(255) NOT NULL,
 opened_by CHAR(36) NOT NULL,
 nomination_ticket VARCHAR(160) NOT NULL,
 status ENUM('NOMINATED_HELD','REJECTED_INTERNAL') NOT NULL DEFAULT 'NOMINATED_HELD',
 provider_contract ENUM('NOT_APPROVED') NOT NULL DEFAULT 'NOT_APPROVED',
 sandbox_credentials ENUM('NOT_PROVIDED') NOT NULL DEFAULT 'NOT_PROVIDED',
 external_root_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_named_code(provider_code),
 CONSTRAINT fk_provider_named_owner FOREIGN KEY(opened_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_named_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 nomination_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CANDIDATE_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 official_listing_inspected BOOLEAN NOT NULL,
 contract_missing_acknowledged BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_named_review(nomination_id),
 CONSTRAINT fk_provider_named_review_n FOREIGN KEY(nomination_id) REFERENCES inv_provider_named_nominations(id),
 CONSTRAINT fk_provider_named_review_u FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_policy_proposals (
 id CHAR(36) NOT NULL PRIMARY KEY,
 nomination_id CHAR(36) NOT NULL,
 cert_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 policy_oid VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 cps_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 cps_source_url VARCHAR(255) NOT NULL,
 purpose ENUM('SUPPLIER_ACK','WAREHOUSE_GRN') NOT NULL,
 status ENUM('PROFILE_HELD') NOT NULL DEFAULT 'PROFILE_HELD',
 full_certification_path ENUM('NOT_VALIDATED') NOT NULL DEFAULT 'NOT_VALIDATED',
 trusted_crl_ocsp ENUM('NOT_VALIDATED') NOT NULL DEFAULT 'NOT_VALIDATED',
 provider_policy_approved ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_policy_nom_cert(nomination_id,cert_id),
 CONSTRAINT fk_provider_policy_nom FOREIGN KEY(nomination_id) REFERENCES inv_provider_named_nominations(id),
 CONSTRAINT fk_provider_policy_cert FOREIGN KEY(cert_id) REFERENCES inv_sandbox_cert_packages(id),
 CONSTRAINT fk_provider_policy_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_policy_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 policy_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_POLICY_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 policy_oid_inspected BOOLEAN NOT NULL,
 missing_crl_ocsp_acknowledged BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_policy_review(policy_id),
 CONSTRAINT fk_provider_policy_review_p FOREIGN KEY(policy_id) REFERENCES inv_provider_policy_proposals(id),
 CONSTRAINT fk_provider_policy_review_u FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_registry_dossiers (
 id CHAR(36) NOT NULL PRIMARY KEY,
 nomination_id CHAR(36) NOT NULL,
 sandbox_case_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 registry_source_url VARCHAR(255) NOT NULL,
 company_master_data_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signatory_delegation_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 registry_reference VARCHAR(96) NOT NULL,
 source_evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('EVIDENCE_PENDING_EXTERNAL','INTERNALLY_INSPECTED_HELD') NOT NULL DEFAULT 'EVIDENCE_PENDING_EXTERNAL',
 registry_authentication ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 legal_signatory_authentication ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_dossier_case(nomination_id,sandbox_case_id),
 CONSTRAINT fk_provider_dossier_n FOREIGN KEY(nomination_id) REFERENCES inv_provider_named_nominations(id),
 CONSTRAINT fk_provider_dossier_case FOREIGN KEY(sandbox_case_id) REFERENCES inv_sandbox_onboarding_cases(id),
 CONSTRAINT fk_provider_dossier_u FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_registry_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 dossier_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CLAIM_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 registry_source_inspected BOOLEAN NOT NULL,
 delegation_source_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_registry_review(dossier_id),
 CONSTRAINT fk_provider_registry_review_d FOREIGN KEY(dossier_id) REFERENCES inv_provider_registry_dossiers(id),
 CONSTRAINT fk_provider_registry_review_u FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_sandbox_access_gates (
 nomination_id CHAR(36) NOT NULL PRIMARY KEY,
 requested_by CHAR(36) NOT NULL,
 access_request_ticket VARCHAR(160) NOT NULL,
 secret_reference_status ENUM('NOT_CONFIGURED') NOT NULL DEFAULT 'NOT_CONFIGURED',
 provider_authorization ENUM('NOT_VERIFIED') NOT NULL DEFAULT 'NOT_VERIFIED',
 live_test_access ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_provider_access_nom FOREIGN KEY(nomination_id) REFERENCES inv_provider_named_nominations(id),
 CONSTRAINT fk_provider_access_u FOREIGN KEY(requested_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
