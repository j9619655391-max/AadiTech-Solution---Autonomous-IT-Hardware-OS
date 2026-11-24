-- Phase 1GL: disposable CI fixture only. No app/staging installer.
-- Issuer column-level INSERT only; runtime procedure EXECUTE only.
CREATE TABLE auth_gl_lead_intents_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 session_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 lead_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 audit_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 name VARCHAR(150) NOT NULL,
 company VARCHAR(200) NOT NULL,
 email VARCHAR(191) NOT NULL,
 phone VARCHAR(30) NOT NULL,
 source ENUM('WEBSITE','WHATSAPP','INDIAMART','JUSTDIAL','EMAIL','TELEGRAM','REFERRAL','GEM_TENDER','OUTBOUND_HUNTER','HARDWARE_REFRESH','PARTNER_PORTAL','OEM_PASS') NOT NULL,
 status ENUM('NEW','CONTACTED','QUALIFIED','BOM_GENERATED','QUOTED','NEGOTIATING','WON','LOST') NOT NULL DEFAULT 'NEW',
 score ENUM('HOT','WARM','COLD','NURTURE') NOT NULL DEFAULT 'NURTURE',
 scoreReason VARCHAR(500) NOT NULL DEFAULT '',
 intentScore TINYINT UNSIGNED NOT NULL DEFAULT 0,
 requirement TEXT NOT NULL,
 estimatedBudget DECIMAL(18,2) NOT NULL DEFAULT 0,
 location VARCHAR(150) NOT NULL DEFAULT '',
 gstin VARCHAR(15) NULL,
 expires_at DATETIME(3) NOT NULL,
 consumed_at DATETIME(3) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_gl_lead (lead_id),
 UNIQUE KEY uq_gl_audit (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
-- statement-break
CREATE PROCEDURE aaditech_gl_create_lead_candidate(
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
 SAVEPOINT gl_lead_candidate;
 ROLLBACK TO SAVEPOINT gl_lead_candidate;
 BEGIN
 DECLARE EXIT HANDLER FOR SQLEXCEPTION
 BEGIN
  ROLLBACK TO SAVEPOINT gl_lead_candidate;
  RELEASE SAVEPOINT gl_lead_candidate;
  RESIGNAL;
 END;
 -- Lock OWNER, session, then intent. No raw caller-provided payload.
 SELECT 1 INTO v_found FROM auth_users
 WHERE id=p_actor AND BINARY id=BINARY p_actor AND role='OWNER' AND status='ACTIVE' FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_sessions
 WHERE token_hash=p_session_hash AND BINARY token_hash=BINARY p_session_hash
 AND BINARY user_id=BINARY p_actor AND expires_at>UTC_TIMESTAMP(3)
 AND mfa_verified_at IS NOT NULL FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_gl_lead_intents_candidate
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL
 AND BINARY actor_id=BINARY p_actor AND BINARY session_hash=BINARY p_session_hash
 AND expires_at>UTC_TIMESTAMP(3) AND created_at<=UTC_TIMESTAMP(3)
 AND expires_at<=DATE_ADD(created_at,INTERVAL 5 MINUTE)
 AND CHAR_LENGTH(TRIM(name))>0 AND CHAR_LENGTH(TRIM(company))>0
 AND email REGEXP '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 INSERT INTO crm_leads(id,name,company,email,phone,source,status,score,scoreReason,intentScore,requirement,estimatedBudget,location,gstin)
 SELECT lead_id,name,company,email,phone,source,status,score,scoreReason,intentScore,requirement,estimatedBudget,location,gstin
 FROM auth_gl_lead_intents_candidate WHERE intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 -- Audit is derived from the actual newly inserted row; no historical-row claim.
 INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation,before_data,after_data)
 SELECT i.audit_id,i.actor_id,'leads',c.id,'CREATE',NULL,
 JSON_OBJECT('id',c.id,'name',c.name,'company',c.company,'email',c.email,'phone',c.phone,'source',c.source,'status',c.status,'score',c.score,'scoreReason',c.scoreReason,'intentScore',c.intentScore,'requirement',c.requirement,'estimatedBudget',c.estimatedBudget,'location',c.location,'gstin',c.gstin,'version',c.version,'created_at',c.created_at,'updated_at',c.updated_at)
 FROM auth_gl_lead_intents_candidate i JOIN crm_leads c ON c.id=i.lead_id
 WHERE i.intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 UPDATE auth_gl_lead_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 RELEASE SAVEPOINT gl_lead_candidate;
 END;
END

 AND CHAR_LENGTH(TRIM(phone))>0 AND CHAR_LENGTH(TRIM(requirement)) BETWEEN 1 AND 10000
 AND source<>'' AND status<>'' AND score<>'' AND intentScore<=100 AND estimatedBudget>=0
 AND (gstin IS NULL OR REGEXP_LIKE(gstin,'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 INSERT INTO crm_leads(id,name,gstin,contactPerson,email,phone,city,state)
 SELECT lead_id,name,gstin,contactPerson,email,phone,city,state
 FROM auth_gl_lead_intents_candidate WHERE intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 -- Audit is derived from the actual newly inserted row; no historical-row claim.
 INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation,before_data,after_data)
 SELECT i.audit_id,i.actor_id,'leads',c.id,'CREATE',NULL,
 JSON_OBJECT('id',c.id,'name',c.name,'gstin',c.gstin,'contactPerson',c.contactPerson,
 'email',c.email,'phone',c.phone,'city',c.city,'state',c.state,'version',c.version,
 'created_at',c.created_at,'updated_at',c.updated_at)
 FROM auth_gl_lead_intents_candidate i JOIN crm_leads c ON c.id=i.lead_id
 WHERE i.intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 UPDATE auth_gl_lead_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 RELEASE SAVEPOINT gl_lead_candidate;
 END;
END
,'c')) FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 INSERT INTO crm_leads(id,name,gstin,contactPerson,email,phone,city,state)
 SELECT lead_id,name,gstin,contactPerson,email,phone,city,state
 FROM auth_gl_lead_intents_candidate WHERE intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 -- Audit is derived from the actual newly inserted row; no historical-row claim.
 INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation,before_data,after_data)
 SELECT i.audit_id,i.actor_id,'leads',c.id,'CREATE',NULL,
 JSON_OBJECT('id',c.id,'name',c.name,'gstin',c.gstin,'contactPerson',c.contactPerson,
 'email',c.email,'phone',c.phone,'city',c.city,'state',c.state,'version',c.version,
 'created_at',c.created_at,'updated_at',c.updated_at)
 FROM auth_gl_lead_intents_candidate i JOIN crm_leads c ON c.id=i.lead_id
 WHERE i.intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 UPDATE auth_gl_lead_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_LEAD_INTENT_DENIED'; END IF;
 RELEASE SAVEPOINT gl_lead_candidate;
 END;
END
