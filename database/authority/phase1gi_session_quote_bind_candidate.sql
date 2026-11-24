-- Phase 1GI isolated-CI candidate only. NOT installed by app or migration.
-- Never grant this procedure to production or staging runtime accounts.
-- Caller must own a transaction. No commit, rollback, dynamic SQL or result set.
CREATE PROCEDURE aaditech_gi_bind_quote_candidate(
 IN p_actor CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_session_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_request_key CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_request_hash CHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
 IN p_quote CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
)
SQL SECURITY DEFINER
MODIFIES SQL DATA
BEGIN
 DECLARE v_role VARCHAR(20) DEFAULT NULL;
 DECLARE v_status VARCHAR(20) DEFAULT NULL;
 DECLARE v_session CHAR(36) DEFAULT NULL;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_session=NULL;
 SELECT role,status INTO v_role,v_status FROM auth_users WHERE id=p_actor FOR UPDATE;
 IF v_role IS NULL OR v_role<>'OWNER' OR v_status<>'ACTIVE' THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GI_BIND_AUTHORITY_DENIED';
 END IF;
 -- Lock current authenticated session on same connection, after OWNER.
 -- The digest is a sensitive bearer-equivalent argument; use synthetic CI only.
 SELECT user_id INTO v_session FROM auth_sessions
  WHERE token_hash=p_session_hash AND BINARY token_hash=BINARY p_session_hash
   AND user_id=p_actor AND expires_at>UTC_TIMESTAMP(3)
   AND mfa_verified_at IS NOT NULL FOR UPDATE;
 IF v_session IS NULL OR v_session<>p_actor THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GI_BIND_AUTHORITY_DENIED';
 END IF;
 UPDATE sales_quote_create_requests
  SET quote_id=p_quote
  WHERE actor_id=p_actor AND request_key=p_request_key
   AND BINARY request_hash=BINARY p_request_hash AND quote_id IS NULL;
 IF ROW_COUNT()<>1 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GI_BIND_AUTHORITY_DENIED';
 END IF;
END
