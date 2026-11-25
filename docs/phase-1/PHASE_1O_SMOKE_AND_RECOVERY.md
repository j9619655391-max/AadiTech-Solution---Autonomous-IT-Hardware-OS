# Phase 1O — CI HTTP auth smoke and disaster recovery acceptance

## Automated CI checks

`bun run test:auth-smoke` starts a temporary HTTP server on **127.0.0.1 with an ephemeral port**, using the existing application auth/CRM/quote routers against `DB_NAME=aaditech_ci` only. It creates a synthetic MFA-enabled owner and checks: anonymous CRM denial, bad password, password-only login returning a no-cookie challenge, invalid TOTP, valid authenticator challenge issuing an HttpOnly SameSite cookie, owner CRM read, reviewer queue role-denial, mutation without CSRF denial, logout, session invalidation, and challenge replay denial. It is a real HTTP/MySQL smoke check, **not browser automation, staging HTTPS, or real-device MFA**. Disposable integration tests run first; CI has no credentials for real production.

`tests/restore-evidence.test.ts` validates the pure recovery acceptance evaluator with *synthetic* example timestamps. **This is not proof that any backup was restored.** An independent operator must measure a real isolated rehearsal and supply evidence before accepting production recovery readiness.

## Disaster recovery acceptance worksheet

Choose objectives in an approved operational ticket. Suggested *initial planning targets* (not commitments): RTO at most **60 minutes**, RPO at most **5 minutes**, subject to achievable backup frequency and verified restore capacity. The evaluation uses elapsed time from restore start to successful restore completion for RTO, and elapsed time between source-as-of and recovery-point timestamps for RPO. It rejects negative intervals, missing independent signoff, non-staging targets, mismatched backup checksums, unreconciled table counts or sampled records, and failed MFA key restore.

Minimum evidence required:
- An approved isolated `aaditech_staging_*` target, controlled access, verified backup and restored digest.
- UTC source/recovery-point and restore start/finish timestamps, operator ticket and independent reviewer signoff time.
- Reconciled schema and table counts, privacy-safe sampled record hashes, encrypted MFA key recovery, no outbound integrations and recorded teardown.
- Separate real HTTPS browser MFA/role/CSRF/recovery user flows with signed test results.

The evaluator compares **submitted** data; it does not itself generate/attest backups or independently verify that timestamps are true. Keep recovery evidence in an approved secure system, not public GitHub CI logs or the repository.

## Readiness gates not achieved

No real browser E2E framework deployed yet, no Hostinger staging restoration, no device-authenticator verification, no production TLS/CA certificate trial, no backup export, and no RTO/RPO measurement from real data. The quote outbox remains `HELD` / `DISABLED`; do not deploy or merge PR without owner/security acceptance.
