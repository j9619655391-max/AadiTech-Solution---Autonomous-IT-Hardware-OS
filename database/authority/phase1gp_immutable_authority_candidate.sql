-- 1GP disposable CI only. Install after GN and GO on a fresh isolated fixture.
-- Existing DML guards are not protection against a DBA with DDL privileges.
-- Permit only one-way consumption, and one-way key revocation at DB statement time.
CREATE TRIGGER aaditech_gp_intent_update_1 BEFORE UPDATE ON auth_gk_customer_intents_candidate
FOR EACH ROW PRECEDES aaditech_go_consume_1
BEGIN
 IF NOT ((BINARY NEW.intent_hash <=> BINARY OLD.intent_hash)
  AND (BINARY NEW.actor_id <=> BINARY OLD.actor_id)
  AND (BINARY NEW.session_hash <=> BINARY OLD.session_hash)
  AND (BINARY NEW.customer_id <=> BINARY OLD.customer_id)
  AND (BINARY NEW.audit_id <=> BINARY OLD.audit_id)
  AND (BINARY NEW.name <=> BINARY OLD.name)
  AND (BINARY NEW.gstin <=> BINARY OLD.gstin)
  AND (BINARY NEW.contactPerson <=> BINARY OLD.contactPerson)
  AND (BINARY NEW.email <=> BINARY OLD.email)
  AND (BINARY NEW.phone <=> BINARY OLD.phone)
  AND (BINARY NEW.city <=> BINARY OLD.city)
  AND (BINARY NEW.state <=> BINARY OLD.state)
  AND (BINARY NEW.expires_at <=> BINARY OLD.expires_at)
  AND (BINARY NEW.created_at <=> BINARY OLD.created_at))
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_delete_1 BEFORE DELETE ON auth_gk_customer_intents_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_update_2 BEFORE UPDATE ON auth_gl_lead_intents_candidate
FOR EACH ROW PRECEDES aaditech_go_consume_2
BEGIN
 IF NOT ((BINARY NEW.intent_hash <=> BINARY OLD.intent_hash)
  AND (BINARY NEW.actor_id <=> BINARY OLD.actor_id)
  AND (BINARY NEW.session_hash <=> BINARY OLD.session_hash)
  AND (BINARY NEW.lead_id <=> BINARY OLD.lead_id)
  AND (BINARY NEW.audit_id <=> BINARY OLD.audit_id)
  AND (BINARY NEW.name <=> BINARY OLD.name)
  AND (BINARY NEW.company <=> BINARY OLD.company)
  AND (BINARY NEW.email <=> BINARY OLD.email)
  AND (BINARY NEW.phone <=> BINARY OLD.phone)
  AND (BINARY NEW.source <=> BINARY OLD.source)
  AND (BINARY NEW.status <=> BINARY OLD.status)
  AND (BINARY NEW.score <=> BINARY OLD.score)
  AND (BINARY NEW.scoreReason <=> BINARY OLD.scoreReason)
  AND (BINARY NEW.intentScore <=> BINARY OLD.intentScore)
  AND (BINARY NEW.requirement <=> BINARY OLD.requirement)
  AND (BINARY NEW.estimatedBudget <=> BINARY OLD.estimatedBudget)
  AND (BINARY NEW.location <=> BINARY OLD.location)
  AND (BINARY NEW.gstin <=> BINARY OLD.gstin)
  AND (BINARY NEW.expires_at <=> BINARY OLD.expires_at)
  AND (BINARY NEW.created_at <=> BINARY OLD.created_at))
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_delete_2 BEFORE DELETE ON auth_gl_lead_intents_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_update_3 BEFORE UPDATE ON auth_gl_product_intents_candidate
FOR EACH ROW PRECEDES aaditech_go_consume_3
BEGIN
 IF NOT ((BINARY NEW.intent_hash <=> BINARY OLD.intent_hash)
  AND (BINARY NEW.actor_id <=> BINARY OLD.actor_id)
  AND (BINARY NEW.session_hash <=> BINARY OLD.session_hash)
  AND (BINARY NEW.product_id <=> BINARY OLD.product_id)
  AND (BINARY NEW.audit_id <=> BINARY OLD.audit_id)
  AND (BINARY NEW.sku <=> BINARY OLD.sku)
  AND (BINARY NEW.brand <=> BINARY OLD.brand)
  AND (BINARY NEW.model <=> BINARY OLD.model)
  AND (BINARY NEW.category <=> BINARY OLD.category)
  AND (BINARY NEW.specs <=> BINARY OLD.specs)
  AND (BINARY NEW.unitCost <=> BINARY OLD.unitCost)
  AND (BINARY NEW.freightCost <=> BINARY OLD.freightCost)
  AND (BINARY NEW.riskBuffer <=> BINARY OLD.riskBuffer)
  AND (BINARY NEW.sellingPrice <=> BINARY OLD.sellingPrice)
  AND (BINARY NEW.minPrice <=> BINARY OLD.minPrice)
  AND (BINARY NEW.gstRate <=> BINARY OLD.gstRate)
  AND (BINARY NEW.hsn <=> BINARY OLD.hsn)
  AND (BINARY NEW.warrantyMonths <=> BINARY OLD.warrantyMonths)
  AND (BINARY NEW.leadTimeDays <=> BINARY OLD.leadTimeDays)
  AND (BINARY NEW.expires_at <=> BINARY OLD.expires_at)
  AND (BINARY NEW.created_at <=> BINARY OLD.created_at))
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_delete_3 BEFORE DELETE ON auth_gl_product_intents_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_update_4 BEFORE UPDATE ON auth_gj_quote_intents_candidate
FOR EACH ROW PRECEDES aaditech_go_consume_4
BEGIN
 IF NOT ((BINARY NEW.intent_hash <=> BINARY OLD.intent_hash)
  AND (BINARY NEW.actor_id <=> BINARY OLD.actor_id)
  AND (BINARY NEW.session_hash <=> BINARY OLD.session_hash)
  AND (BINARY NEW.quote_id <=> BINARY OLD.quote_id)
  AND (BINARY NEW.request_key <=> BINARY OLD.request_key)
  AND (BINARY NEW.request_hash <=> BINARY OLD.request_hash)
  AND (BINARY NEW.expires_at <=> BINARY OLD.expires_at)
  AND (BINARY NEW.created_at <=> BINARY OLD.created_at))
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_intent_delete_4 BEFORE DELETE ON auth_gj_quote_intents_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_key_update BEFORE UPDATE ON auth_go_issuer_keys_candidate
FOR EACH ROW
BEGIN
 IF NOT ((BINARY NEW.key_id <=> BINARY OLD.key_id)
  AND (BINARY NEW.spki_sha256 <=> BINARY OLD.spki_sha256)
  AND (BINARY NEW.scope_mask <=> BINARY OLD.scope_mask)
  AND (BINARY NEW.not_before <=> BINARY OLD.not_before)
  AND (BINARY NEW.not_after <=> BINARY OLD.not_after))
 OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_at<>UTC_TIMESTAMP(3) THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_key_delete BEFORE DELETE ON auth_go_issuer_keys_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_approval_update BEFORE UPDATE ON auth_go_intent_approvals_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_approval_delete BEFORE DELETE ON auth_go_intent_approvals_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
-- statement-break
CREATE TRIGGER aaditech_gp_nonce_update BEFORE UPDATE ON auth_gn_intent_nonces_candidate
FOR EACH ROW
BEGIN
 IF NOT ((BINARY NEW.intent_hash <=> BINARY OLD.intent_hash)
  AND (BINARY NEW.operation <=> BINARY OLD.operation)
  AND (BINARY NEW.actor_id <=> BINARY OLD.actor_id)
  AND (BINARY NEW.entity_id <=> BINARY OLD.entity_id)
  AND (BINARY NEW.reserved_at <=> BINARY OLD.reserved_at))
 OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE';
 END IF;
END
-- statement-break
CREATE TRIGGER aaditech_gp_nonce_delete BEFORE DELETE ON auth_gn_intent_nonces_candidate
FOR EACH ROW BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GP_AUTHORITY_IMMUTABLE'; END
