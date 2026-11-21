# Phase 1J — Reviewer lifecycle and session security

## What is implemented
- Migration `0009_auth_security_events.sql` adds an append-only security event table.
- `GET /api/security/reviewers`: owner-only reviewer inventory, status and live session count (no credentials or token hashes returned).
- `PATCH /api/security/reviewers/:id/status`: owner-only state change. DISABLED immediately rejects further authentication; all reviewer sessions are deleted atomically with both status and audit event. Reactivation also deletes any sessions.
- `POST /api/security/reviewers/:id/revoke-sessions`: owner-only revocation of all reviewer sessions, audit event included.
- `GET /api/security/events?limit=20`: owner-only recent security events.
- `POST /api/auth/revoke-my-sessions`: any authenticated account may revoke every one of its own sessions, including the current browser, and creates an audit record in the same transaction.
- The owner dashboard offers reviewer management; owner and reviewer sessions can be revoked using “Sign out all sessions”. All mutating operations require CSRF verification.
- Existing OWNER accounts cannot be disabled or reassigned by these reviewer-only endpoints.

## Database
Apply migrations 0001–0008 first, then `bun run db:migrate:security-events`. Run migration on a protected staging restoration before touching real data. The SQL is additive; no legacy data is deleted.

## Verification
Disposable MySQL integration tests cover role denial, disabling a reviewer and invalidating live sessions, re-enabling without restoring old sessions, session-only revocation, immutable audit events, self revocation, and input validation. TypeScript, unit tests and bundled build run in standard CI.

## Not yet implemented — blockers
- **MFA is not enabled.** Enrollment, step-up challenge, recovery, device trust and recovery-code handling require a dedicated hardened implementation.
- No forced credential reauthentication for status changes, rate-limited administrative actions, device-specific session dashboard, distributed rate limiter, account recovery or SIEM integration.
- A staff management dashboard is not a substitute for real security monitoring or production access review.
- Production database changes, independent reviewer identities, HTTPS browser E2E and operational backup/restore have not been performed.
- Customer sending remains disabled; internal review statuses are not legal approvals.
