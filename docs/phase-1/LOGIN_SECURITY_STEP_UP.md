# Phase 1K Part 1 — MySQL login throttling and password reauthentication

## Implemented
- Additive migration `0010_auth_login_security.sql` adds hashed per-account/per-network login attempt counters and five-minute session-bound reauthentication records.
- Before verifying a login password, the server atomically reserves an attempt in a fixed 15-minute MySQL window. Per-account limit is 6 attempts, per-IP limit 30 attempts (HTTP 429 thereafter). Counts are shared across server processes and contain SHA-256 digests, not raw email/IP addresses.
- `POST /api/auth/step-up` accepts **only** the current password, requires an existing authenticated session and CSRF token, and returns a five-minute short-lived token to the currently authenticated tab. Reauthentication attempts are also rate-limited in MySQL.
- Admin writes (reviewer disable/enable and reviewer session revocation), and `POST /api/auth/revoke-my-sessions`, require `x-step-up-token` validated against the same session and a five-minute database expiry. Unauthorized attempts return HTTP 403.
- React controls request password confirmation before sensitive actions; CSRF and step-up tokens remain in module memory, not localStorage. No raw password is retained by the client after successful verification.
- Deleting the underlying auth session automatically cascades to its step-up row.
- No email/SMS recovery links or TOTP MFA are enabled in this increment.

## Operational security limitations
- **This is single-factor step-up, not MFA.** TOTP or phishing-resistant WebAuthn would need enrollment, challenge, recovery, revocation and independent E2E testing.
- Fixed-window throttles can permit bursts near window boundaries, and account-based lockout can be abused. More robust risk/rate controls plus alerting, reverse-proxy IP trust configuration and staged load testing are required.
- Attempt buckets grow over time. A maintenance process must delete buckets outside retention (for example older than 7 days); do not run cleanup without a documented retention/monitoring policy. Do not expose client-supplied forwarded IPs as trusted identity.
- Short-lived token is bearer proof *in addition* to the HttpOnly cookie and CSRF token, not a second factor. Do not log it.
- An admin session password verification does not ensure the device is malware-free. Reauthentication token rotation and server-side expiry are essential.
- The existing `DB_SSL=true` configuration still disables CA verification; security hardening remains required before production.
- Production schema migration, staged restore rehearsal, HTTPS browser E2E, MFA, credential reset, account recovery, session analytics and security monitoring remain pending.

## Staging-only migration
Run migrations 0001–0009 in order, then `bun run db:migrate:login-security`. Verify the migration checksum and idempotent rerun on a disposable MySQL 8 instance. Never execute the legacy destructive `database/schema.sql` on live customer records.
