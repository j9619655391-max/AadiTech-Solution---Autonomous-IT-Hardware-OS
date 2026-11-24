-- Phase 1GL: disposable CI fixture only. No app/staging installer.
-- Issuer column-level INSERT only; runtime procedure EXECUTE only.
CREATE TABLE auth_gl_product_intents_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 session_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 product_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 audit_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 sku VARCHAR(100) NOT NULL,
 brand VARCHAR(120) NOT NULL,
 model VARCHAR(200) NOT NULL,
 category ENUM('LAPTOP','DESKTOP','SERVER','NETWORKING','POWER_STORAGE','ACCESSORIES') NOT NULL,
 specs TEXT NOT NULL,
 unitCost DECIMAL(18,2) NOT NULL,
 freightCost DECIMAL(18,2) NOT NULL DEFAULT 0,
 riskBuffer DECIMAL(18,2) NOT NULL DEFAULT 0,
 sellingPrice DECIMAL(18,2) NOT NULL,
 minPrice DECIMAL(18,2) NOT NULL,
 gstRate DECIMAL(5,2) NOT NULL DEFAULT 18,
 hsn VARCHAR(16) NOT NULL,
 warrantyMonths SMALLINT UNSIGNED NOT NULL DEFAULT 12,
 leadTimeDays SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 expires_at DATETIME(3) NOT NULL,
 consumed_at DATETIME(3) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_gl_product (product_id),
 UNIQUE KEY uq_gl_audit (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
-- statement-break
CREATE PROCEDURE aaditech_gl_create_product_candidate(
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
 SAVEPOINT gl_product_candidate;
 ROLLBACK TO SAVEPOINT gl_product_candidate;
 BEGIN
 DECLARE EXIT HANDLER FOR SQLEXCEPTION
 BEGIN
  ROLLBACK TO SAVEPOINT gl_product_candidate;
  RELEASE SAVEPOINT gl_product_candidate;
  RESIGNAL;
 END;
 -- Lock OWNER, session, then intent. No raw caller-provided payload.
 SELECT 1 INTO v_found FROM auth_users
 WHERE id=p_actor AND BINARY id=BINARY p_actor AND role='OWNER' AND status='ACTIVE' FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_sessions
 WHERE token_hash=p_session_hash AND BINARY token_hash=BINARY p_session_hash
 AND BINARY user_id=BINARY p_actor AND expires_at>UTC_TIMESTAMP(3)
 AND mfa_verified_at IS NOT NULL FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 SET v_found=0;
 SELECT 1 INTO v_found FROM auth_gl_product_intents_candidate
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL
 AND BINARY actor_id=BINARY p_actor AND BINARY session_hash=BINARY p_session_hash
 AND expires_at>UTC_TIMESTAMP(3) AND created_at<=UTC_TIMESTAMP(3)
 AND expires_at<=DATE_ADD(created_at,INTERVAL 5 MINUTE)
 AND CHAR_LENGTH(TRIM(sku))>0 AND CHAR_LENGTH(TRIM(brand))>0 AND CHAR_LENGTH(TRIM(model))>0
 AND category<>'' AND CHAR_LENGTH(TRIM(specs)) BETWEEN 1 AND 10000 AND CHAR_LENGTH(TRIM(hsn))>0
 AND unitCost>=0 AND freightCost>=0 AND riskBuffer>=0 AND sellingPrice>=0 AND minPrice>=0
 AND minPrice<=sellingPrice AND gstRate BETWEEN 0 AND 100 AND warrantyMonths<=1200 AND leadTimeDays<=3650 FOR UPDATE;
 IF v_found<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 INSERT INTO crm_products(id,sku,brand,model,category,specs,unitCost,freightCost,riskBuffer,sellingPrice,minPrice,gstRate,hsn,warrantyMonths,leadTimeDays)
 SELECT product_id,sku,brand,model,category,specs,unitCost,freightCost,riskBuffer,sellingPrice,minPrice,gstRate,hsn,warrantyMonths,leadTimeDays
 FROM auth_gl_product_intents_candidate WHERE intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 -- Audit is derived from the actual newly inserted row; no historical-row claim.
 INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation,before_data,after_data)
 SELECT i.audit_id,i.actor_id,'products',c.id,'CREATE',NULL,
 JSON_OBJECT('id',c.id,'sku',c.sku,'brand',c.brand,'model',c.model,'category',c.category,'specs',c.specs,'unitCost',c.unitCost,'freightCost',c.freightCost,'riskBuffer',c.riskBuffer,'sellingPrice',c.sellingPrice,'minPrice',c.minPrice,'gstRate',c.gstRate,'hsn',c.hsn,'warrantyMonths',c.warrantyMonths,'leadTimeDays',c.leadTimeDays,'version',c.version,'created_at',c.created_at,'updated_at',c.updated_at)
 FROM auth_gl_product_intents_candidate i JOIN crm_products c ON c.id=i.product_id
 WHERE i.intent_hash=p_intent_hash;
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 UPDATE auth_gl_product_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
 WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GL_PRODUCT_INTENT_DENIED'; END IF;
 RELEASE SAVEPOINT gl_product_candidate;
 END;
END
