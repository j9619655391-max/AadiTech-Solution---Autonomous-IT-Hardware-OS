# Phase 1L — Privileged MFA policy, audit and MySQL TLS validation

The policy is **explicit and staged**:
- `MFA_REQUIRE_PRIVILEGED=false` (default) preserves compatibility for users who have not yet enrolled.
- `MFA_REQUIRE_PRIVILEGED=true` denies privileged mutations for unenrolled staff, including independent internal review decisions, reviewer lifecycle changes and HELD release preparation. MFA enrollment endpoints remain usable, allowing staff to enroll before policy activation.
- Invalid values fail closed with HTTP 503 on protected actions.
- Active sessions issued *before* MFA activation are deleted when MFA is enabled. A subsequent signed-in session for an enrolled user requires the authenticator challenge.
- Every MFA enrollment, successful/failed second-factor verification, recovery-code consumption and privileged policy denial is recorded in the existing append-only security journal (migration 0012). No passwords, MFA secrets, recovery codes, challenge tokens, or raw IPs are logged as audit event details.

## Database TLS safety
`DB_SSL=true` must verify the server certificate chain (`rejectUnauthorized:true`). Optionally set `DB_SSL_CA_BASE64` to a base64-encoded trusted CA PEM chain, or rely on system trust roots; validate against staging first. `DB_SSL=false` is permitted only for isolated disposable CI/local MySQL. Production hosting must validate a proper CA bundle and hostname. Environment names vary by provider; confirm Hostinger certificate settings rather than disabling verification.

## Deployment sequence
1. Restore a backup into isolated staging; apply migrations 0001–0012 in order (`bun run db:migrate:mfa-audit` last).
2. Provision and validate a stable 32-byte `MFA_ENCRYPTION_KEY` in a managed secret store; ensure every replica has the same key and a tested recovery process.
3. Enroll owner and reviewer staff independently and store recovery codes securely.
4. Set `MFA_REQUIRE_PRIVILEGED=true` only after enrollment and staging verification.
5. Exercise role denial, reviewer decisions, held-release audit and device/browser MFA sign-in with HTTPS; monitor audit activity.

**Remaining blockers:** MFA is not mandatory for all routes or login accounts, no safe lost-device account recovery procedure exists, admin MFA recovery requires formal multi-person identity checks, TOTP is phishable, browser E2E/HA and operational alerting are incomplete. This milestone creates no send worker, production migration or deployment. All customer delivery remains DISABLED.
