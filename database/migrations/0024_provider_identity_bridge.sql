-- 0024 Phase 1AL: preprovisioned provider pin + offline signed organizational
-- credentials and revocation source evidence. NO external authority is asserted.
CREATE TABLE IF NOT EXISTS inv_provider_pin_candidates (
 id CHAR(36) NOT NULL PRIMARY KEY,
 provider_code VARCHAR(64) NOT NULL,
 provider_origin VARCHAR(255) NOT NULL,
 root_spki_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 root_fingerprint_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 tls_spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 provisioned_by CHAR(36) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 external_root_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_pin_code(provider_code),
 UNIQUE KEY uq_provider_root_fingerprint(root_fingerprint_sha256),
 CONSTRAINT fk_provider_pin_actor FOREIGN KEY(provisioned_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_pin_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pin_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 pin_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_pin_review(pin_id),
 CONSTRAINT fk_provider_pin_review_pin FOREIGN KEY(pin_id) REFERENCES inv_provider_pin_candidates(id),
 CONSTRAINT fk_provider_pin_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_org_credentials (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pin_id CHAR(36) NOT NULL,
 issuer_id CHAR(36) NOT NULL,
 submitted_by CHAR(36) NOT NULL,
 purpose ENUM('SUPPLIER_ACK','WAREHOUSE_GRN') NOT NULL,
 valid_from DATETIME(3) NOT NULL,
 valid_until DATETIME(3) NOT NULL,
 message_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 message_json JSON NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('PENDING_INTERNAL','REVIEWED_CRYPTO_HELD','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 corporate_identity_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 external_issuer_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 stock_posting ENUM('DISABLED') NOT NULL DEFAULT 'DISABLED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_credential(pin_id,issuer_id,purpose),
 CONSTRAINT fk_provider_org_credential_pin FOREIGN KEY(pin_id) REFERENCES inv_provider_pin_candidates(id),
 CONSTRAINT fk_provider_org_credential_issuer FOREIGN KEY(issuer_id) REFERENCES inv_external_issuer_candidates(id),
 CONSTRAINT fk_provider_org_credential_actor FOREIGN KEY(submitted_by) REFERENCES auth_users(id),
 CONSTRAINT chk_provider_org_window CHECK(valid_until>valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_org_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 credential_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('REVIEWED_CRYPTO_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 source_inspected BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_org_review(credential_id),
 CONSTRAINT fk_provider_org_review_credential FOREIGN KEY(credential_id) REFERENCES inv_provider_org_credentials(id),
 CONSTRAINT fk_provider_org_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_revocation_feeds (
 id CHAR(36) NOT NULL PRIMARY KEY,
 pin_id CHAR(36) NOT NULL,
 sequence_number INT UNSIGNED NOT NULL,
 published_at DATETIME(3) NOT NULL,
 valid_until DATETIME(3) NOT NULL,
 imported_by CHAR(36) NOT NULL,
 message_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 message_json JSON NOT NULL,
 signature_b64 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('SIGNED_CANDIDATE') NOT NULL DEFAULT 'SIGNED_CANDIDATE',
 external_publisher_state ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_provider_feed_seq(pin_id,sequence_number),
 CONSTRAINT fk_provider_feed_pin FOREIGN KEY(pin_id) REFERENCES inv_provider_pin_candidates(id),
 CONSTRAINT fk_provider_feed_actor FOREIGN KEY(imported_by) REFERENCES auth_users(id),
 CONSTRAINT chk_provider_feed_window CHECK(valid_until>published_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_revocation_entries (
 feed_id CHAR(36) NOT NULL,
 revoked_fingerprint_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 PRIMARY KEY(feed_id,revoked_fingerprint_sha256),
 CONSTRAINT fk_provider_feed_entry FOREIGN KEY(feed_id) REFERENCES inv_provider_revocation_feeds(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_pin_freezes (
 pin_id CHAR(36) NOT NULL PRIMARY KEY,
 initiated_by CHAR(36) NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 CONSTRAINT fk_provider_pin_freeze_pin FOREIGN KEY(pin_id) REFERENCES inv_provider_pin_candidates(id),
 CONSTRAINT fk_provider_pin_freeze_actor FOREIGN KEY(initiated_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS inv_provider_audit (
 id CHAR(36) NOT NULL PRIMARY KEY,
 actor_id CHAR(36) NOT NULL,
 entity_type ENUM('PIN','CREDENTIAL','FEED') NOT NULL,
 entity_id CHAR(36) NOT NULL,
 action ENUM('PIN_CANDIDATE_RECORDED','PIN_REVIEWED','PIN_REJECTED',
 'CREDENTIAL_IMPORTED','CREDENTIAL_REVIEWED','CREDENTIAL_REJECTED',
 'FEED_IMPORTED','PIN_FROZEN') NOT NULL,
 event_sha256 CHAR(64) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 INDEX idx_provider_audit(entity_type,entity_id,created_at),
 CONSTRAINT fk_provider_audit_actor FOREIGN KEY(actor_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
