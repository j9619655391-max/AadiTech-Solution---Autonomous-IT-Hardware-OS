# Phase 1Q — Extended browser authentication and staging release evidence

**Scope:** Draft PR / disposable CI only. No production services, customer dispatch, or live database operations.

## Chromium UI acceptance scenarios

The CI `scripts/browser-smoke.mjs` now checks a complete set of negative and positive browser interactions against `aaditech_ci`:

1. An incorrect password shows a visible error without creating an authenticated session.
2. A correct password for an MFA-enabled owner produces an authenticator challenge, not a session cookie.
3. An incorrect recovery code shows a UI error and keeps the user unauthenticated.
4. A valid authenticator code completes the owner sign-in; the owner sees reviewer-security controls, but not the reviewer workspace.
5. Logging out invalidates the owner session and returns the browser to the sign-in screen.
6. A distinct reviewer must complete their own MFA challenge, sees only the reviewer workspace and cannot read or mutate CRM/draft endpoints or read owner security administration.
7. A freshly issued synthetic recovery code signs the reviewer in **once**; after logout, replay of that code fails, displays an error, and never creates a session. Cancel returns to login.
8. Browser rejects off-host HTTP requests. Synthetic secrets are created inside the disposable MySQL CI environment and are never uploaded as test artifacts.

This complements, but does **not** replace, production-grade browser coverage for HTTPS, authenticator time drift, accessibility, multiple devices, cross-origin restrictions, rate limits, lost-device governance, or actual disaster recovery.

## Staging acceptance evidence checklist

An independent operator must record the following in the approved private change-control system. Do **not** store customer identifiers, passwords, MFA secrets, recovery codes, or backup archives in GitHub.

| Gate | Evidence required | Status |
| --- | --- | --- |
| Safe target | Isolated `aaditech_staging_*` instance, network isolation, outbound delivery disabled | NOT VERIFIED |
| Database recovery | Encrypted backup digest, actual restore log, row reconciliation, independent sign-off | NOT VERIFIED |
| RTO / RPO | Measured values, compared with approved planning goals (60 / 5 minutes) | NOT VERIFIED |
| MFA crypto recovery | Key backup custody and tested nonproduction decrypt/restore | NOT VERIFIED |
| Real-browser HTTPS | Valid TLS CA and real-device owner/reviewer TOTP, recovery, CSRF and logout test | NOT VERIFIED |
| Privileged IAM | Least-privilege reviewer provisioning, reauthentication, incident response review | NOT VERIFIED |
| Customer communication | HELD outbox / DISABLED dispatcher invariant | MUST REMAIN DISABLED |

`runStagingPreflight` and synthetic `restoreEvidence` tests only check data supplied to CI: neither independently attests a real backup, restore, audit signature, disaster recovery capability, or production readiness. Launch still requires explicit security and business approval.

## Next recommended engineering work

Move browser scenarios into a first-class version-locked test workspace, add scheduled dependency/security reviews and meaningful credential-risk monitoring, and validate the complete staging recovery rehearsal with independent evidence. Do not activate outbound messaging as an incidental part of staging testing.
