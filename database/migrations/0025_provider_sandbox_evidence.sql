-- Phase 1AM: nonproduction provider sandbox onboarding and X.509 evidence checks.
-- A matched public cert signature and claimed corporate documents are NOT real KYC.
CREATE TABLE IF NOT EXISTS inv_sandbox_onboarding_cases (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pin_id CHAR(36) NOT NULL,
 issuer_id CHAR(36) NOT NULL,
 opened_by CHAR(36) NOT NULL,
 purpose ENUM('SUPPLIER_ACK','WAREHOUSE_GRN') NOT NULL,
 registry_reference VARCHAR(96) NOT NULL,
 identity_document_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signatory_reference VARCHAR(160) NOT NULL,
 signatory_document_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_EVIDENCE_HELD','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 corporate_identity_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 signatory_authority_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_sandbox_case(pin_id,issuer_id,purpose),
 CONSTRAINT fk_sandbox_case_pin FOREIGN KEY(pin_id) REFERENCES inv_provider_pin_candidates(id),
 CONSTRAINT fk_sandbox_case_issuer FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_sandbox_case_actor FOREIGN KEY(opened_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_sandbox_case_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 case_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_EVIDENCE_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 registry_document_inspected BOOLEAN NOT NULL,
 signatory_document_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_sandbox_case_review(case_id),
 CONSTRAINT fk_sandbox_review_case FOREIGN KEY(case_id) REFERENCES inv_sandbox_onboarding_cases(id),
 CONSTRAINT fk_sandbox_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_sandbox_cert_packages (
 id CHAR(36) NOT NULL PRIMARY KEY,
 case_id CHAR(36) NOT NULL,
 imported_by CHAR(36) NOT NULL,
 ca_certificate_pem TEXT NOT NULL,
 leaf_certificate_pem TEXT NOT NULL,
 ca_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 leaf_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 leaf_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 leaf_serial VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 leaf_not_before DATETIME(3) NOT NULL,
 leaf_not_after DATETIME(3) NOT NULL,
 status ENUM('CERT_SIGNATURE_MATCHED_HELD') NOT NULL DEFAULT 'CERT_SIGNATURE_MATCHED_HELD',
 provider_issued_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 rfc5280_path_validated ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_sandbox_cert_case(case_id),
 UNIQUE KEY uq_sandbox_leaf_digest(leaf_certificate_sha256),
 CONSTRAINT fk_sandbox_cert_case FOREIGN KEY(case_id) REFERENCES inv_sandbox_onboarding_cases(id),
 CONSTRAINT fk_sandbox_cert_actor FOREIGN KEY(imported_by) REFERENCES auth_users(id),
 CONSTRAINT chk_sandbox_cert_window CHECK(leaf_not_after>leaf_not_before)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_sandbox_cert_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 cert_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CRYPTO_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 certificate_inspected BOOLEAN NOT NULL,
 policy_gaps_acknowledged BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_sandbox_cert_review(cert_id),
 CONSTRAINT fk_sandbox_cert_review_cert FOREIGN KEY(cert_id) REFERENCES inv_sandbox_cert_packages(id),
 CONSTRAINT fk_sandbox_cert_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_sandbox_revocation_checks (
 id CHAR(36) NOT NULL PRIMARY KEY,
 cert_id CHAR(36) NOT NULL,
 feed_id CHAR(36) NOT NULL,
 checked_by CHAR(36) NOT NULL,
 checked_digest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('CHECKED_HELD') NOT NULL DEFAULT 'CHECKED_HELD',
 external_publisher_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 official_grn_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 stock_posting_state ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_sandbox_cert_feed(cert_id,feed_id),
 CONSTRAINT fk_sandbox_check_cert FOREIGN KEY(cert_id) REFERENCES inv_sandbox_cert_packages(id),
 CONSTRAINT fk_sandbox_check_feed FOREIGN KEY(feed_id) REFERENCES inv_provider_revocation_feeds(id),
 CONSTRAINT fk_sandbox_check_actor FOREIGN KEY(checked_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_sandbox_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('CASE','CERT','CHECK') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('CASE_OPENED','CASE_REVIEWED','CASE_REJECTED',
  'CERT_EVIDENCE_IMPORTED','CERT_REVIEWED','CERT_REJECTED','REVOCATION_RECHECKED') NOT NULL,
 digest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_sandbox_audit(entity_type,entity_id,created_at),
 CONSTRAINT fk_sandbox_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
