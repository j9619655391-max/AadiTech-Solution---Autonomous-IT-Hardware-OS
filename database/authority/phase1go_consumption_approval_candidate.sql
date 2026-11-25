-- 1GO disposable CI only, after all GN tables/triggers. No live installer.
-- Separate key registrar (DBA fixture), issuer, approval writer and runtime.
CREATE TABLE auth_go_issuer_keys_candidate (
 key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 scope_mask TINYINT UNSIGNED NOT NULL,
 not_before DATETIME(3) NOT NULL,
 not_after DATETIME(3) NOT NULL,
 revoked_at DATETIME(3) NULL,
 CHECK (scope_mask BETWEEN 1 AND 15),
 CHECK (not_before<not_after)
) ENGINE=InnoDB
-- statement-break
CREATE TABLE auth_go_intent_approvals_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 spki_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 evidence_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 approved_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 FOREIGN KEY(intent_hash) REFERENCES auth_gn_intent_nonces_candidate(intent_hash),
 FOREIGN KEY(key_id) REFERENCES auth_go_issuer_keys_candidate(key_id)
) ENGINE=InnoDB
-- statement-break
ALTER TABLE auth_gn_intent_nonces_candidate ADD COLUMN consumed_at DATETIME(3) NULL
-- statement-break
CREATE TRIGGER aaditech_go_consume_1 BEFORE UPDATE ON auth_gk_customer_intents_candidate
FOR EACH ROW
BEGIN
 DECLARE v_ok INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_ok=0;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED';
 END IF;
 -- Lock current key and receipt, serialize with key revocation.
 SELECT 1 INTO v_ok FROM auth_go_intent_approvals_candidate a
 JOIN auth_go_issuer_keys_candidate k ON k.key_id=a.key_id AND k.spki_sha256=a.spki_sha256
 WHERE a.intent_hash=OLD.intent_hash AND a.expires_at=OLD.expires_at
 AND a.approved_at<=UTC_TIMESTAMP(3) AND a.expires_at>UTC_TIMESTAMP(3)
 AND k.revoked_at IS NULL AND k.not_before<=UTC_TIMESTAMP(3)
 AND k.not_after>=a.expires_at AND (k.scope_mask & 1)=1 FOR UPDATE;
 IF v_ok<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
 UPDATE auth_gn_intent_nonces_candidate SET consumed_at=NEW.consumed_at
 WHERE intent_hash=OLD.intent_hash AND operation='customers' AND consumed_at IS NULL
 AND BINARY actor_id=BINARY OLD.actor_id AND BINARY entity_id=BINARY OLD.customer_id;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
END
-- statement-break
CREATE TRIGGER aaditech_go_consume_2 BEFORE UPDATE ON auth_gl_lead_intents_candidate
FOR EACH ROW
BEGIN
 DECLARE v_ok INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_ok=0;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED';
 END IF;
 -- Lock current key and receipt, serialize with key revocation.
 SELECT 1 INTO v_ok FROM auth_go_intent_approvals_candidate a
 JOIN auth_go_issuer_keys_candidate k ON k.key_id=a.key_id AND k.spki_sha256=a.spki_sha256
 WHERE a.intent_hash=OLD.intent_hash AND a.expires_at=OLD.expires_at
 AND a.approved_at<=UTC_TIMESTAMP(3) AND a.expires_at>UTC_TIMESTAMP(3)
 AND k.revoked_at IS NULL AND k.not_before<=UTC_TIMESTAMP(3)
 AND k.not_after>=a.expires_at AND (k.scope_mask & 2)=2 FOR UPDATE;
 IF v_ok<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
 UPDATE auth_gn_intent_nonces_candidate SET consumed_at=NEW.consumed_at
 WHERE intent_hash=OLD.intent_hash AND operation='leads' AND consumed_at IS NULL
 AND BINARY actor_id=BINARY OLD.actor_id AND BINARY entity_id=BINARY OLD.lead_id;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
END
-- statement-break
CREATE TRIGGER aaditech_go_consume_3 BEFORE UPDATE ON auth_gl_product_intents_candidate
FOR EACH ROW
BEGIN
 DECLARE v_ok INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_ok=0;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED';
 END IF;
 -- Lock current key and receipt, serialize with key revocation.
 SELECT 1 INTO v_ok FROM auth_go_intent_approvals_candidate a
 JOIN auth_go_issuer_keys_candidate k ON k.key_id=a.key_id AND k.spki_sha256=a.spki_sha256
 WHERE a.intent_hash=OLD.intent_hash AND a.expires_at=OLD.expires_at
 AND a.approved_at<=UTC_TIMESTAMP(3) AND a.expires_at>UTC_TIMESTAMP(3)
 AND k.revoked_at IS NULL AND k.not_before<=UTC_TIMESTAMP(3)
 AND k.not_after>=a.expires_at AND (k.scope_mask & 4)=4 FOR UPDATE;
 IF v_ok<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
 UPDATE auth_gn_intent_nonces_candidate SET consumed_at=NEW.consumed_at
 WHERE intent_hash=OLD.intent_hash AND operation='products' AND consumed_at IS NULL
 AND BINARY actor_id=BINARY OLD.actor_id AND BINARY entity_id=BINARY OLD.product_id;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
END
-- statement-break
CREATE TRIGGER aaditech_go_consume_4 BEFORE UPDATE ON auth_gj_quote_intents_candidate
FOR EACH ROW
BEGIN
 DECLARE v_ok INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_ok=0;
 IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED';
 END IF;
 -- Lock current key and receipt, serialize with key revocation.
 SELECT 1 INTO v_ok FROM auth_go_intent_approvals_candidate a
 JOIN auth_go_issuer_keys_candidate k ON k.key_id=a.key_id AND k.spki_sha256=a.spki_sha256
 WHERE a.intent_hash=OLD.intent_hash AND a.expires_at=OLD.expires_at
 AND a.approved_at<=UTC_TIMESTAMP(3) AND a.expires_at>UTC_TIMESTAMP(3)
 AND k.revoked_at IS NULL AND k.not_before<=UTC_TIMESTAMP(3)
 AND k.not_after>=a.expires_at AND (k.scope_mask & 8)=8 FOR UPDATE;
 IF v_ok<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
 UPDATE auth_gn_intent_nonces_candidate SET consumed_at=NEW.consumed_at
 WHERE intent_hash=OLD.intent_hash AND operation='quote-binding' AND consumed_at IS NULL
 AND BINARY actor_id=BINARY OLD.actor_id AND BINARY entity_id=BINARY OLD.quote_id;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GO_CONSUMPTION_DENIED'; END IF;
END
