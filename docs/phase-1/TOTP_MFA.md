# Phase 1K Part 2 — Opt-in TOTP MFA (development staging)

## Implemented
- Database migration `0011_totp_mfa.sql`: encrypted TOTP enrollment credentials, one-time recovery-code hashes, short-lived pre-session MFA challenges.
- `MFA_ENCRYPTION_KEY`: **mandatory** 32-byte random AES-256-GCM key encoded as 64 hex digits. Store in secret manager, do not commit to git. Backup key securely; key loss can lock out MFA-enabled users. CI uses a test-only fixed key.
- Authenticator enrollment requires authenticated session, CSRF, current-password step-up, and successful TOTP verification within 10 minutes. OTP secret is never persisted as plaintext. The setup URI and secret are shown only while enrolling.
- Activation provides eight high-entropy, one-use recovery codes **once**; SHA-256 hashes are stored server-side, and all previously issued sessions are revoked to prevent MFA bypass.
- MFA-enabled login with correct password returns HTTP 202 and an opaque five-minute challenge token **without issuing a session cookie**. Finish via `POST /api/auth/mfa/challenge/verify` with either a 6-digit RFC6238 TOTP or a one-use recovery code.
- Challenge has maximum five incorrect attempts and is transactionally consumed upon successful login; OTP counters prevent reuse.
- `GET /api/auth/mfa/status`, `POST /api/auth/mfa/enroll/start`, `POST /api/auth/mfa/enroll/activate` are authenticated endpoints. No password-less reset or MFA disable endpoint exists.

## Limitations / critical release blockers
- TOTP is phishable. Evaluate WebAuthn/passkeys for privileged user protection and risk review.
- **Account recovery in case both authenticator and recovery codes are lost is not implemented.** Users must securely store recovery codes; manual administrator recovery policy, identity verification and auditing require future design.
- Recovery-code rotation/replacement, MFA method/device inventory, admin MFA enforcement policy, account lockout incident playbooks, sensitive-change MFA step-up, enterprise identity policy and real HTTPS/browser E2E tests are pending.
- OTP activation now uses the shared MySQL step-up attempt budget (six attempts per 15-minute bucket). Dedicated MFA-specific risk controls, administrative audit events and monitoring remain pending.
- Hard-coded CI test encryption key is not a production secret. Production key must be injected securely and persisted across all replicas.
- MySQL SSL verification remains an existing blocker. No production deployments, migrations, or customer messaging.
- Existing demo features remain non-authoritative. Never execute destructive legacy database/schema.sql on real data.

Run migrations 0001–0010 first and then `bun run db:migrate:mfa` in disposable staging. Confirm backup/restore and stored-key recovery before real deployment.

## Test verification
CI includes the RFC6238 TOTP unit vector, AES-GCM tamper detection, real MySQL enrollment and session revocation, password-only session denial, TOTP counter replay rejection, five-attempt challenge limits, and single-use recovery codes. These automated tests do not replace real authenticator/browser/HTTPS staging E2E checks.
