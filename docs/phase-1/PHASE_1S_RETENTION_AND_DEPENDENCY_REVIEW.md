# Phase 1S — Authentication retention, dependency audit, restore evidence

## Scope

Development-branch safeguard and disposable CI only. No production, Hostinger, external dispatch, or real customer database was accessed. No new schema migration.

### Retention implementation

`bun run auth:retention` is **dry-run by default** and refuses every database other than `DB_NAME=aaditech_ci`, `CRM_TEST_DB=1`, `NODE_ENV=test`. To perform a bounded apply on the disposable CI database only, set `RETENTION_APPLY=YES_DELETE_TEST_ONLY` and run `bun run auth:retention --apply`. No background job or production cleaning schedule exists.

Eligible rows:
- `auth_sessions` whose expiration has passed.
- `auth_step_up_sessions` whose five-minute expiry has passed.
- `auth_mfa_challenges` whose pre-session expiry has passed.
- `auth_login_rate_buckets` older than the seven-day cutoff (minimum seven days kept).

Each DELETE uses an indexed predicate, deterministic `ORDER BY` and a maximum batch size of 250 rows to reduce lock duration. The dry run reports counts but never deletes. Both modes refuse non-CI databases, including staging targets. Retention eligibility is based on DB UTC timestamps for sessions/challenges and a computed 15-minute bucket for rate counters.

**Never automatically delete:** `auth_security_events` (immutable audit history), `auth_users`, `auth_totp_credentials`, `auth_totp_recovery_codes`, `schema_migrations`, CRM, quote, or accounting records. Any policy changes to those require legal/privacy review, retention schedule, formal authorization and separately reviewed migration tooling.

The disposable MySQL test inserts synthetic expired and valid sessions, expired step-up/challenge records, current/old attempt buckets and a security event. It confirms the dry-run does not mutate data; bounded apply removes only eligible rows; active sessions, current counters and immutable audit survive; and a second apply deletes nothing.

### Dependency vulnerability review

CI's baseline job now runs `bun audit --json` and uploads `dependency-audit.json` as an artifact. **Non-gating means vulnerabilities may still be present**; failures or findings are visible for human triage, not silently fixed or production-approved. Review direct/transitive dependencies, severity, exploitability, reachability, and suitable updates in a separately tested PR. No `npm audit fix`, auto-upgrade, lockfile rewrite or runtime deployment occurs in this phase.

### Recovery evidence validation

The synthetic restore-evidence evaluator rejects impossible chronology, including a source snapshot later than the completed backup and a recovery point later than restore start. Existing validations still require signed independent reviewer evidence, checksum match, table reconciliations and MFA key-recovery confirmation. A passing synthetic fixture **does not mean any real backup was restored**.

## Before allowing production retention or staging sign-off

1. Obtain written retention periods from authorized owner/legal/privacy reviewers and assess audit immutability, investigation holds, incident/legal holds, retention audit and access controls.
2. Test under isolated restored staging with real workload, minimum permissions, index performance, lock contention and rollback/backup evidence. Independently review any scheduled operations.
3. Review the dependency audit artifact and open risk-treatment tickets for significant findings. Never interpret the non-gating audit as clean or passing automatically.
4. Perform independently witnessed encrypted backup and actual restore with TLS, MFA key backup, data reconciliation, real-browser HTTPS checks and **measured** RTO/RPO against approved objectives (60/5 minutes are planning assumptions only).
5. Maintain customer quote outbox in HELD/DISABLED state. Do not merge/deploy without explicit business/security authorization.
