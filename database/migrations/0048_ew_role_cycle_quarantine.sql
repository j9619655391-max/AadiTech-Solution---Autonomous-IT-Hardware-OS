-- Phase 1EW: database-level role/status transition quarantine for app-local reviewers.
-- Trigger bodies are deliberately single-statement for the checksum-locked runner.
-- No triggers automatically grant/re-enable a reviewer, authorize an external party,
-- or create a production release. MySQL 8.0 disposable CI / approved staging only.
CREATE TRIGGER trg_ew_reviewer_grant_quarantine
AFTER UPDATE ON auth_users
FOR EACH ROW
UPDATE app_reviewer_scope_grants SET state='REVOKED'
 WHERE reviewer_user_id=NEW.id AND state='ACTIVE'
   AND (OLD.role<>NEW.role OR OLD.status<>NEW.status);

CREATE TRIGGER trg_ew_reviewer_session_quarantine
AFTER UPDATE ON auth_users
FOR EACH ROW
DELETE FROM auth_sessions WHERE user_id=NEW.id
  AND (OLD.role<>NEW.role OR OLD.status<>NEW.status);
