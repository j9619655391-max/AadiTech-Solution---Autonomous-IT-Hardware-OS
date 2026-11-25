-- Phase 1AO: offline sandbox onboarding crypto and dual-control evidence only.
-- No external eMudhra agreement/approved sandbox credential or MCA attestation exists.
CREATE TABLE IF NOT EXISTS inv_provider_ao_packets (
 id CHAR(36) NOT NULL PRIMARY KEY,
 nomination_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 contract_document_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 provider_onboarding_ref VARCHAR(160) NOT NULL,
 sandbox_scope_ref VARCHAR(160) NOT NULL,
 status ENUM('PENDING_INTERNAL','DUAL_REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL DEFAULT 'PENDING_INTERNAL',
 contract_authentication ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 sandbox_secret_state ENUM('NOT_CONFIGURED') NOT NULL DEFAULT 'NOT_CONFIGURED',
 provider_credential_authentication ENUM('NO') NOT NULL DEFAULT 'NO',
 production_release ENUM('HOLD') NOT NULL DEFAULT 'HOLD',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_nomination(nomination_id),
 CONSTRAINT fk_ao_packet_nom FOREIGN KEY(nomination_id) REFERENCES inv_provider_named_nominations(id),
 CONSTRAINT fk_ao_packet_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_packet_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 packet_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 review_role ENUM('LEGAL','SECURITY') NOT NULL,
 decision ENUM('INSPECTED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 no_external_contract_ack BOOLEAN NOT NULL,
 no_live_credentials_ack BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_review_role(packet_id,review_role),
 UNIQUE KEY uq_ao_review_actor(packet_id,reviewer_id),
 CONSTRAINT fk_ao_review_packet FOREIGN KEY(packet_id) REFERENCES inv_provider_ao_packets(id),
 CONSTRAINT fk_ao_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_pkix_trials (
 id CHAR(36) NOT NULL PRIMARY KEY,
 packet_id CHAR(36) NOT NULL,
 policy_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 requested_policy_oid VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 root_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 leaf_certificate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('OFFLINE_CRYPTO_HELD') NOT NULL DEFAULT 'OFFLINE_CRYPTO_HELD',
 provider_chain_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 real_issuer_status ENUM('UNVERIFIED') NOT NULL DEFAULT 'UNVERIFIED',
 trusted_crl_ocsp ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_trial_packet_policy(packet_id,policy_id),
 CONSTRAINT fk_ao_trial_packet FOREIGN KEY(packet_id) REFERENCES inv_provider_ao_packets(id),
 CONSTRAINT fk_ao_trial_policy FOREIGN KEY(policy_id) REFERENCES inv_provider_policy_proposals(id),
 CONSTRAINT fk_ao_trial_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_revocation_trials (
 id CHAR(36) NOT NULL PRIMARY KEY,
 trial_id CHAR(36) NOT NULL,
 imported_by CHAR(36) NOT NULL,
 artifact_type ENUM('CRL','OCSP') NOT NULL,
 artifact_der_b64 MEDIUMTEXT CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 artifact_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('SIGNED_OFFLINE_HELD') NOT NULL DEFAULT 'SIGNED_OFFLINE_HELD',
 issuer_authority_verified ENUM('NO') NOT NULL DEFAULT 'NO',
 external_publisher_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 serial_status ENUM('CRYPTO_GOOD_ONLY') NOT NULL DEFAULT 'CRYPTO_GOOD_ONLY',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_revocation_type(trial_id,artifact_type),
 CONSTRAINT fk_ao_revocation_trial FOREIGN KEY(trial_id) REFERENCES inv_provider_ao_pkix_trials(id),
 CONSTRAINT fk_ao_revocation_actor FOREIGN KEY(imported_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_revocation_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 artifact_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('CRYPTO_REVIEWED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 issuer_provenance_missing_ack BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_revocation_review(artifact_id),
 CONSTRAINT fk_ao_revocation_review_artifact FOREIGN KEY(artifact_id) REFERENCES inv_provider_ao_revocation_trials(id),
 CONSTRAINT fk_ao_revocation_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_mca_evidence (
 id CHAR(36) NOT NULL PRIMARY KEY,
 packet_id CHAR(36) NOT NULL,
 dossier_id CHAR(36) NOT NULL,
 prepared_by CHAR(36) NOT NULL,
 mca_master_data_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signatory_mandate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 verification_ticket VARCHAR(160) NOT NULL,
 status ENUM('PENDING_EXTERNAL','INTERNALLY_INSPECTED_HELD') NOT NULL DEFAULT 'PENDING_EXTERNAL',
 registry_authenticated ENUM('NO') NOT NULL DEFAULT 'NO',
 signatory_authorized ENUM('NO') NOT NULL DEFAULT 'NO',
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_mca_packet_dossier(packet_id,dossier_id),
 CONSTRAINT fk_ao_mca_packet FOREIGN KEY(packet_id) REFERENCES inv_provider_ao_packets(id),
 CONSTRAINT fk_ao_mca_dossier FOREIGN KEY(dossier_id) REFERENCES inv_provider_registry_dossiers(id),
 CONSTRAINT fk_ao_mca_actor FOREIGN KEY(prepared_by) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS inv_provider_ao_mca_reviews (
 id CHAR(36) NOT NULL PRIMARY KEY,
 mca_id CHAR(36) NOT NULL,
 reviewer_id CHAR(36) NOT NULL,
 decision ENUM('INSPECTED_HELD','REJECTED_INTERNAL') NOT NULL,
 reason VARCHAR(1000) NOT NULL,
 evidence_ref VARCHAR(160) NOT NULL,
 external_mca_auth_missing_ack BOOLEAN NOT NULL,
 signatory_auth_missing_ack BOOLEAN NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_ao_mca_review(mca_id),
 CONSTRAINT fk_ao_mca_review_record FOREIGN KEY(mca_id) REFERENCES inv_provider_ao_mca_evidence(id),
 CONSTRAINT fk_ao_mca_review_actor FOREIGN KEY(reviewer_id) REFERENCES auth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
