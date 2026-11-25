# Phase 1FE — deny runtime authority-table SQL mutation (HARD HOLD)

Date: 2026-11-23. Target: `chore/phase0-foundation-20261106`, Draft PR #1 only. This is a **deny-only grant observation policy**. It does not execute SQL migrations, change real user grants, publish provider evidence or authorize staging/production.

## Finding and narrow fix

Phase 1FC correctly requires CURRENT_USER()/SHOW GRANTS from one authenticated MySQL session during approved staging preflight, but the 1FB classifier also accepted a schema-wide `SELECT,INSERT,UPDATE,DELETE` grant. A stolen runtime DB connection could restore a revoked `app_reviewer_scope_grants` nomination after the Phase 1EW `auth_users` trigger quarantined it. Merely checking for TRIGGER/DDL/GRANT OPTION did not close this application-authority bypass.

Phase 1FE rejects:

1. All schema-wide INSERT/UPDATE/DELETE grants on the target schema. Schema-wide SELECT remains visible and acceptable in this narrow grant parser.
2. Any table-scoped INSERT/UPDATE/DELETE on: `auth_users`, `auth_sessions`, `app_reviewer_scope_grants`, `app_reviewer_scope_events`, `auth_security_events`, `auth_totp_credentials`, `auth_totp_recovery_codes`, `auth_mfa_challenges`.
3. Existing disallowed global privileges, unknown SQL forms, non-target scopes, delegated roles, GRANT OPTION and DDL remain denied.

Non-protected **table-bounded** DML can be acceptable to this narrow classifier. Every accepted grant still requires independent DBA privilege attestation, MySQL effective-role/routine/cross-account audit, and staging functional tests. In the disposable MySQL test, a real temporary user with SELECT passes; deliberately adding table-scoped reviewer UPDATE or schema-wide INSERT produces HOLD; after revocation it passes. Unit tests cover each protected table and deny cases. No production SQL or DB account was changed.

## Integration and acceptance gaps

The app currently performs privileged reviewer/authentication workflows through its own runtime connection. Removing direct writes from its sole account may break login, MFA, session renewal and OWNER nomination unless those operations move behind a *separate*, least-privileged, independently governed authority boundary with required authorization, CSRF/MFA, audit and transactional SQL checks. **No such live trusted writer is asserted or auto-created.** A PASS from this checker alone is not an app functional acceptance result. Preserve release HOLD until that architecture has an approved security design, integrated HTTP and MySQL tests, and independent live staging execution with external DBA + Security signoff.

Staging test prerequisites still require disposable isolated TLS schema, secured credentials, named authorized operators, full staged migrations/installed triggers, no direct production connection, and operator-controlled evidence custody. Application-produced receipts are not independent identity, corporate mandate or production trust.

## Release gate

`productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. `main` must stay unchanged; Draft PR #1 remains unmerged, Issue #2 open. M01–M30 business acceptance, actual MCA/signatory/eMudhra/CCA/RCAI trust and revocation, signed off-platform provenance, protected branch + independent reviewer quorum, approved data reconciliation, independent restore/DR and business/staging acceptance all remain pending.

References: [1FB grant observer](PHASE_1FB_RUNTIME_DB_PRIVILEGE_ENVELOPE_HARD_HOLD.md), [1FC mandatory staging gate](PHASE_1FC_STAGING_RUNTIME_PRIVILEGE_GATE_HARD_HOLD.md), [master M01–M30](../completion/MASTER_M01_M30_COMPLETION_PLAN.md), [release Issue #2](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/issues/2).
