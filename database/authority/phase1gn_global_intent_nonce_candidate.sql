-- 1GN disposable CI only; install all four candidate intent tables first.
-- No app/staging installer. No direct issuer/runtime DML on this registry.
-- AFTER INSERT triggers reserve a global nonce in the same statement/transaction.
-- A rollback of issuance rolls back the reservation; a committed reservation is retained.
CREATE TABLE auth_gn_intent_nonces_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 operation ENUM('customers','leads','products','quote-binding') NOT NULL,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 entity_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 reserved_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB
-- statement-break
CREATE TRIGGER aaditech_gn_nonce_1 AFTER INSERT ON auth_gk_customer_intents_candidate
FOR EACH ROW
BEGIN
 IF NOT REGEXP_LIKE(NEW.intent_hash,'^[0-9a-f]{64}$','c') THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GN_NONCE_INVALID';
 END IF;
 INSERT INTO auth_gn_intent_nonces_candidate(intent_hash,operation,actor_id,entity_id)
 VALUES (NEW.intent_hash,'customers',NEW.actor_id,NEW.customer_id);
END
-- statement-break
CREATE TRIGGER aaditech_gn_nonce_2 AFTER INSERT ON auth_gl_lead_intents_candidate
FOR EACH ROW
BEGIN
 IF NOT REGEXP_LIKE(NEW.intent_hash,'^[0-9a-f]{64}$','c') THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GN_NONCE_INVALID';
 END IF;
 INSERT INTO auth_gn_intent_nonces_candidate(intent_hash,operation,actor_id,entity_id)
 VALUES (NEW.intent_hash,'leads',NEW.actor_id,NEW.lead_id);
END
-- statement-break
CREATE TRIGGER aaditech_gn_nonce_3 AFTER INSERT ON auth_gl_product_intents_candidate
FOR EACH ROW
BEGIN
 IF NOT REGEXP_LIKE(NEW.intent_hash,'^[0-9a-f]{64}$','c') THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GN_NONCE_INVALID';
 END IF;
 INSERT INTO auth_gn_intent_nonces_candidate(intent_hash,operation,actor_id,entity_id)
 VALUES (NEW.intent_hash,'products',NEW.actor_id,NEW.product_id);
END
-- statement-break
CREATE TRIGGER aaditech_gn_nonce_4 AFTER INSERT ON auth_gj_quote_intents_candidate
FOR EACH ROW
BEGIN
 IF NOT REGEXP_LIKE(NEW.intent_hash,'^[0-9a-f]{64}$','c') THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GN_NONCE_INVALID';
 END IF;
 INSERT INTO auth_gn_intent_nonces_candidate(intent_hash,operation,actor_id,entity_id)
 VALUES (NEW.intent_hash,'quote-binding',NEW.actor_id,NEW.quote_id);
END
