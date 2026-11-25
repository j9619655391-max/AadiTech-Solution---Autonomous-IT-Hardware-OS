-- Phase 1AK: candidate external issuers and signed organizational authority/revocation
-- are OFFLINE SELF-REPORTED evidence. No real externally authenticated trust root exists.
CREATE TABLE IF NOT EXISTS inv_external_issuer_candidates (
 id CHAR(36) NOT NULL PRIMARY KEY,
 party_kind ENUM('SUPPLIER','WAREHOUSE') NOT NULL,
 party_id CHAR(36) NOT NULL,
 registered_by CHAR(36) NOT NULL,
 issuer_spki_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 fingerprint_sha256 CHAR(64) NOT NULL,
 organization_registration VARCHAR(96) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_HELD','REJECTED_INTERNAL')
  NOT NULL DEFAULT 'PENDING_INTERNAL',
 external_root_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ext_issuer_fingerprint(fingerprint_sha256),
 INDEX idx_ext_issuer_party(party_kind,party_id),
 CONSTRAINT fk_ext_issuer_actor FOREIGN KEY(registered_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_issuer_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 issuer_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 registry_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ext_issuer_review(issuer_id),
 CONSTRAINT fk_ext_issuer_review_candidate FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_ext_issuer_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_authority_attestations (
 id CHAR(36) NOT NULL PRIMARY KEY,
 issuer_id CHAR(36) NOT NULL,
 key_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 purpose ENUM('SUPPLIER_ACK','WAREHOUSE_GRN') NOT NULL,
 valid_from DATETIME(3) NOT NULL,
 valid_until DATETIME(3) NOT NULL,
 statement_sha256 CHAR(64) NOT NULL,
 statement_json JSON NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_CRYPTO_HELD','REJECTED_INTERNAL')
  NOT NULL DEFAULT 'PENDING_INTERNAL',
 external_authority_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 stock_posting ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ext_authority_issuer_key_purpose(issuer_id,key_id,purpose),
 CONSTRAINT fk_ext_authority_issuer FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_ext_authority_key FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_ext_authority_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id),
 CONSTRAINT chk_ext_authority_time CHECK(valid_until>valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_authority_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 attestation_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CRYPTO_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 signature_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ext_authority_review(attestation_id),
 CONSTRAINT fk_ext_authority_review_attest FOREIGN KEY(attestation_id) REFERENCES inv_external_authority_attestations(id),
 CONSTRAINT fk_ext_authority_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_revocation_bundles (
 id CHAR(36) NOT NULL PRIMARY KEY,
 issuer_id CHAR(36) NOT NULL,
 submitted_by CHAR(36) NOT NULL,
 sequence_number INT UNSIGNED NOT NULL,
 issued_at DATETIME(3) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 manifest_sha256 CHAR(64) NOT NULL,
 manifest_json JSON NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('SIGNED_UNTRUSTED') NOT NULL DEFAULT 'SIGNED_UNTRUSTED',
 external_publisher_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ext_revocation_issuer_sequence(issuer_id,sequence_number),
 INDEX idx_ext_revocation_expiry(issuer_id,expires_at),
 CONSTRAINT fk_ext_revocation_issuer FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_ext_revocation_actor FOREIGN KEY(submitted_by) REFERENCES auth_users(id),
 CONSTRAINT chk_ext_revocation_time CHECK(expires_at>issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_revocation_entries (
 bundle_id CHAR(36) NOT NULL,
 key_fingerprint_sha256 CHAR(64) NOT NULL,
 PRIMARY KEY(bundle_id,key_fingerprint_sha256),
 CONSTRAINT fk_ext_revocation_entry_bundle FOREIGN KEY(bundle_id) REFERENCES inv_external_revocation_bundles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_external_trust_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('ISSUER','AUTHORITY','REVOCATION') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('ISSUER_REGISTERED','ISSUER_REVIEWED','ISSUER_REJECTED',
  'AUTHORITY_SIGNED','AUTHORITY_REVIEWED','AUTHORITY_REJECTED',
  'REVOCATION_IMPORTED','ISSUER_FROZEN') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_ext_audit_entity(entity_type,entity_id,created_at),
 CONSTRAINT fk_ext_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Immediate irreversible internal issuer compromise quarantine; no external CA trust.
CREATE TABLE IF NOT EXISTS inv_external_issuer_freezes (
 issuer_id CHAR(36) NOT NULL PRIMARY KEY,
 initiated_by CHAR(36) NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 frozen_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_ext_issuer_freeze_issuer FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_ext_issuer_freeze_actor FOREIGN KEY(initiated_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
