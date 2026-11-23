-- Phase 1FO: DBA-owned SECURITY DEFINER candidate. This file is a reviewed
-- isolated-CI fixture, NOT an automatic production/staging deployment.
-- NEVER run under the unprivileged application runtime account.
-- No GRANT and no customer/email/MFA data returned to the invoker.
CREATE PROCEDURE aaditech_guard_active_owner(IN p_actor CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci)
SQL SECURITY DEFINER
MODIFIES SQL DATA
BEGIN
 DECLARE v_role VARCHAR(20) DEFAULT NULL;
 DECLARE v_status VARCHAR(20) DEFAULT NULL;
 DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_role=NULL;
 SELECT role,status INTO v_role,v_status
 FROM auth_users WHERE id=p_actor FOR UPDATE;
 IF v_role IS NULL OR v_role<>'OWNER' OR v_status<>'ACTIVE' THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='AUTH_OWNER_INACTIVE';
 END IF;
END
