-- 1GJ isolated disposable CI only; no staging or production installer.
-- The issuer is a separate restricted principal with INSERT only on this table.
-- Runtime cannot read or write the authority namespace, only CALL the routine.
CREATE TABLE auth_gj_quote_intents_candidate (
 intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 session_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_key CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 quote_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 consumed_at DATETIME(3) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB
-- statement-break
CREATE PROCEDURE aaditech_gj_bind_intent_candidate(
 IN p_actor CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_session_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_request_key CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_request_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_quote CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_intent_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin
)
SQL SECURITY DEFINER
MODIFIES SQL DATA
BEGIN
 DECLARE v_found INT DEFAULT 0;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_found=0;
 -- The same caller transaction must contain both binding and consumption.
 -- A savepoint makes failed calls atomic even when the caller catches SIGNAL.
 DECLARE EXIT HANDLER FOR SQLEXCEPTION
 BEGIN
  ROLLBACK TO SAVEPOINT gj_intent_candidate;
  RELEASE SAVEPOINT gj_intent_candidate;
  RESIGNAL;
 END;
 SAVEPOINT gj_intent_candidate;
 SELECT 1 INTO v_found FROM auth_gj_quote_intents_candidate
  WHERE intent_hash=p_intent_hash AND consumed_at IS NULL
   AND expires_at>UTC_TIMESTAMP(3)
   AND created_at<=UTC_TIMESTAMP(3)
   AND expires_at<=DATE_ADD(created_at,INTERVAL 5 MINUTE)
   AND BINARY actor_id=BINARY p_actor AND BINARY session_hash=BINARY p_session_hash
   AND BINARY request_key=BINARY p_request_key AND BINARY request_hash=BINARY p_request_hash
   AND BINARY quote_id=BINARY p_quote FOR UPDATE;
 IF v_found<>1 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GJ_INTENT_DENIED';
 END IF;
 CALL aaditech_gi_bind_quote_candidate(p_actor,p_session_hash,p_request_key,p_request_hash,p_quote);
 UPDATE auth_gj_quote_intents_candidate SET consumed_at=UTC_TIMESTAMP(3)
  WHERE intent_hash=p_intent_hash AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3);
 IF ROW_COUNT()<>1 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GJ_INTENT_DENIED';
 END IF;
 RELEASE SAVEPOINT gj_intent_candidate;
END
