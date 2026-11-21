-- Phase 1AI: offline signature verification prerequisites ONLY; no root of trust.
-- A cryptographically valid signature from a self-registered key is NOT authenticated
-- supplier identity, issued PO, vendor ACK, official warehouse GRN or inventory.
CREATE TABLE IF NOT EXISTS inv_proof_key_candidates (
 id CHAR(36) NOT NULL PRIMARY KEY,
 party_kind ENUM('SUPPLIER','WAREHOUSE') NOT NULL,
 supplier_id CHAR(36) NULL,
 site_id CHAR(36) NULL,
 registered_by CHAR(36) NOT NULL,
 public_key_spki_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 fingerprint_sha256 CHAR(64) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_UNTRUSTED','REJECTED_INTERNAL')
   NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_proof_key_fingerprint(fingerprint_sha256),
 CONSTRAINT fk_proof_key_supplier FOREIGN KEY(supplier_id) REFERENCES proc_suppliers(id),
 CONSTRAINT fk_proof_key_site FOREIGN KEY(site_id) REFERENCES inventory_sites(id),
 CONSTRAINT fk_proof_key_actor FOREIGN KEY(registered_by) REFERENCES auth_users(id),
 CONSTRAINT chk_proof_key_party CHECK(
  (party_kind='SUPPLIER' AND supplier_id IS NOT NULL AND site_id IS NULL)
  OR (party_kind='WAREHOUSE' AND site_id IS NOT NULL AND supplier_id IS NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_proof_key_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 key_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_UNTRUSTED','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 document_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proof_key_review(key_id),
 CONSTRAINT fk_proof_key_review_key FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_proof_key_review_reviewer FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_signed_proof_claims (
 id CHAR(36) NOT NULL PRIMARY KEY,
 key_id CHAR(36) NOT NULL,
 created_by CHAR(36) NOT NULL,
 claim_kind ENUM('PO_ISSUANCE_ASSERTION','SUPPLIER_ACK_ASSERTION','WAREHOUSE_GRN_ASSERTION') NOT NULL,
 dispatch_preparation_id CHAR(36) NULL,
 held_grn_id CHAR(36) NULL,
 source_sha256 CHAR(64) NOT NULL,
 message_sha256 CHAR(64) NOT NULL,
 message_json JSON NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signature_matched BOOLEAN NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_CRYPTO_ONLY','REJECTED_INTERNAL')
   NOT NULL DEFAULT 'PENDING_INTERNAL',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 reviewed_at DATETIME(3) NULL,
 UNIQUE KEY uq_proof_claim_dispatch_kind(claim_kind,dispatch_preparation_id),
 UNIQUE KEY uq_proof_claim_grn_kind(claim_kind,held_grn_id),
 CONSTRAINT fk_proof_claim_key FOREIGN KEY(key_id) REFERENCES inv_proof_key_candidates(id),
 CONSTRAINT fk_proof_claim_owner FOREIGN KEY(created_by) REFERENCES auth_users(id),
 CONSTRAINT fk_proof_claim_preparation FOREIGN KEY(dispatch_preparation_id) REFERENCES proc_dispatch_preparations(id),
 CONSTRAINT fk_proof_claim_grn FOREIGN KEY(held_grn_id) REFERENCES inv_grn_held_records(id),
 CONSTRAINT chk_proof_claim_source CHECK(
  (claim_kind IN ('PO_ISSUANCE_ASSERTION','SUPPLIER_ACK_ASSERTION')
    AND dispatch_preparation_id IS NOT NULL AND held_grn_id IS NULL)
  OR (claim_kind='WAREHOUSE_GRN_ASSERTION'
    AND held_grn_id IS NOT NULL AND dispatch_preparation_id IS NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_signed_proof_blockers (
 claim_id CHAR(36) NOT NULL PRIMARY KEY,
 party_identity ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 actual_po_issued ENUM('NO') NOT NULL DEFAULT 'NO',
 supplier_ack_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 official_grn_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 stock_posting ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_proof_blocker_claim FOREIGN KEY(claim_id) REFERENCES inv_signed_proof_claims(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_signed_proof_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 claim_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CRYPTO_ONLY','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 signature_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proof_claim_review(claim_id),
 CONSTRAINT fk_proof_claim_review_claim FOREIGN KEY(claim_id) REFERENCES inv_signed_proof_claims(id),
 CONSTRAINT fk_proof_claim_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_signed_proof_holds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 claim_id CHAR(36) NOT NULL,
 review_id CHAR(36) NOT NULL,
 snapshot_sha256 CHAR(64) NOT NULL,
 snapshot_json JSON NOT NULL,
 status ENUM('HELD') NOT NULL DEFAULT 'HELD',
 external_trust_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 stock_posting ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_proof_hold_claim(claim_id),
 CONSTRAINT fk_proof_hold_claim FOREIGN KEY(claim_id) REFERENCES inv_signed_proof_claims(id),
 CONSTRAINT fk_proof_hold_review FOREIGN KEY(review_id) REFERENCES inv_signed_proof_reviews(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_signed_proof_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('KEY','CLAIM') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 event_type ENUM('KEY_REGISTERED','KEY_REVIEWED','KEY_REJECTED','SIGNED_CLAIM_RECORDED',
  'CLAIM_CRYPTO_REVIEWED','CLAIM_REJECTED') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_proof_audit_entity(entity_type,entity_id,created_at),
 CONSTRAINT fk_proof_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
