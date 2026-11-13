-- Phase 1L: append-only security journal expands to cover MFA lifecycle.
ALTER TABLE auth_security_events MODIFY COLUMN event_type ENUM(
 'REVIEWER_DISABLED','REVIEWER_ENABLED','SESSIONS_REVOKED','OWN_SESSIONS_REVOKED',
 'MFA_ENROLLED','MFA_LOGIN_SUCCEEDED','MFA_LOGIN_FAILED','MFA_RECOVERY_USED',
 'MFA_POLICY_DENIED'
) NOT NULL;

-- Privileged MFA enforcement must check the *session*, not only enrollment.
ALTER TABLE auth_sessions ADD COLUMN mfa_verified_at DATETIME(3) NULL;
