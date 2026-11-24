-- Phase 1GK: disposable CI fixture only. No app/staging installer.
-- Issuer column-level INSERT only; runtime procedure EXECUTE only.
CREATE TABLE auth_gk_customer_intents_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 session_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 customer_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 audit_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 name VARCHAR(200) NOT NULL,
 gstin VARCHAR(15) NULL,
 contactPerson VARCHAR(150) NOT NULL,
 email VARCHAR(191) NOT NULL,
 phone VARCHAR(30) NOT NULL,
 city VARCHAR(120) NOT NULL,
 state VARCHAR(120) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 consumed_at DATETIME(3) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_gk_customer (customer_id),
 UNIQUE KEY uq_gk_audit (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
-- statement-break
CREATE PROCEDURE aaditech_gk_create_customer_candidate(
 IN p_actor CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_session_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin
)
SQL SECURITY DEFINER
MODIFIES SQL DATA
BEGIN
 DECLARE v_found INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_found=0;
 -- Probe caller transaction before any data writes. Reserved savepoint name.
 SAVEPOINT gk_customer_candidate;
 ROLLBACK TO SAVEPOINT gk_customer_candidate;
 BEGIN
 DECLARE EXIT HANDLER FOR SQLEXCEPTION
 BEGIN
  ROLLBACK TO SAVEPOINT gk_customer_candidate;
  RELEASE SAVEPOINT gk_customer_candidate;
  RESIGNAL;
 END;
 -- Lock OWNER, session, then intent. No raw caller-provided payload.
 SELECT 1 INTO v_found FROM auth_users
 WHERE id=p_actor AND BINARY id=BINARY p_actor AND role='OWNER' AND status='ACTIVE' FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_sessions
 WHERE token_hash=p_session_hash AND BINARY token_hash=BINARY p_session_hash
 AND BINARY user_id=BINARY p_actor AND expires_at>UTC_TIMESTAMP(3)
 AND mfa_verified_at IS NOT NULL FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_gk_customer_intents_candidate
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL
 AND BINARY actor_id=BINARY p_actor AND BINARY session_hash=BINARY p_session_hash
 AND expires_at>UTC_TIMESTAMP(3) AND created_at<=UTC_TIMESTAMP(3)
 AND expires_at<=DATE_ADD(created_at,INTERVAL 5 MINUTE) FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 INSERT INTO crm_customers(id,name,gstin,contactPerson,email,phone,city,state)
 SELECT customer_id,name,gstin,contactPerson,email,phone,city,state
 FROM auth_gk_customer_intents_candidate WHERE intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 -- Audit is derived from the actual newly inserted row; no historical-row claim.
 INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation,before_data,after_data)
 SELECT i.audit_id,i.actor_id,'customers',c.id,'CREATE',NULL,
 JSON_OBJECT('id',c.id,'name',c.name,'gstin',c.gstin,'contactPerson',c.contactPerson,
 'email',c.email,'phone',c.phone,'city',c.city,'state',c.state,'version',c.version,
 'created_at',c.created_at,'updated_at',c.updated_at)
 FROM auth_gk_customer_intents_candidate i JOIN crm_customers c ON c.id=i.customer_id
 WHERE i.intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 UPDATE auth_gk_customer_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GK_CUSTOMER_INTENT_DENIED'; END IF;
 RELEASE SAVEPOINT gk_customer_candidate;
 END;
END
