# Phase 1FL — Auth/runtime MySQL credential separation candidate (HARD HOLD)

Date: 24 November 2026 IST. **Internal engineering, not independent staging acceptance.** This increment makes the previously documented contradiction explicit: 1FH/FJ forbid the general runtime DB identity from directly reading protected authentication and reviewer tables, while the monolithic application's login, MFA and reviewer administration handlers had used the same general `getPool()` credential.

## Narrow implementation

- `server/db.ts` adds `getAuthPool()` with a separately configured **AUTH_DB_USER/AUTH_DB_PASSWORD** credential, sharing the explicitly configured database host/schema/TLS policy with the main DB connection. It does NOT provision MySQL users, grants, an external key vault, or role separation in the database.
- `authDatabaseCredentialState()` classifies configuration as `DEV_SHARED`, `SEPARATE_CANDIDATE` or `HOLD`. Only local developer/disposable CI without dedicated credentials may fall back to the existing shared pool. **Staging/production never silently fall back.** Partial AUTH_DB configuration, matching runtime username or password, absent runtime credentials, or invalid credential username returns HOLD; protected handlers fail unavailable rather than reusing the main runtime pool. A `SEPARATE_CANDIDATE` is just a user-supplied configuration assertion, *not proof of authenticated distinct MySQL principals*.
- `server/auth/router.ts`, `server/auth/mfaRouter.ts`, `server/security/adminRouter.ts`, and `server/security/reviewerScopeRouter.ts` now request the candidate auth pool for internal login, session, step-up, MFA, first-party reviewer administration and reviewer nomination.
- `scripts/staging-preflight.ts` exposes `authCredentialSeparation: HOLD | UNVERIFIED_CANDIDATE | NOT_EVALUATED_CI` and `authFunctionalSeparationVerified:false`. It **refuses staging READY** regardless of configuration claims until independently authorized end-to-end work genuinely closes the remaining split. Disposable CI readiness does not pretend to be real staging acceptance.
- `tests/staging-preflight.test.ts` includes configuration adversarial cases, authority-handler source-boundary checks, and staging HOLD assertions.

## Significant remaining architectural and evidence gaps

1. Other business modules still use `getPool()` and can query protected identity or reviewer tables; notably the **transactional CRM owner row lock** relies on `auth_users` under the general DB connection. Simply installing denied grants will break some features. Do not remove the lock or relax 1FH to produce an artificial green run. The separated services/transactions and least-privilege API contract require redesign and independent review.
2. The separate pool does not authenticate `CURRENT_USER()` versus the runtime account, prove active/default/mandatory role absence, check the effective grant graph, verify `SQL SECURITY DEFINER` routines/views or survive grant changes after observation. The AUTH_DB_* candidate must be provisioned by an authorized external DBA from a secrets manager and positively authenticated under isolated approved TLS staging.
3. Complete role-scoped functional flows must be demonstrated under real separate principals: login/password throttling, MFA enrollment/login/recovery, revoked sessions/reviewer state, role/status changes and reviewer nomination, CRM CREATE/PATCH/DELETE with atomic actor lock, and all release-held business routers. Require concurrent negative tests, no raw secret disclosure, independent DBA/Security/Operations acceptance and signed evidence.
4. Existing internal test fixtures use `NODE_ENV=test` and deliberately retain the shared disposable `aaditech_ci` credential. They do **not** validate a true AUTH_DB_* deployment. There are no live independent credentials or irreversible database changes in this increment.

## Production acceptance remains OPEN

Issue #2 and M01–M30 remain unchanged. Production needs real Legal/Business/DBA/Security independent mandates, signed CCA/RCAI/eMudhra and MCA/GST evidence, live signed CRL/OCSP, approved staging, protected main/CODEOWNERS and independent reviews, signed workload provenance, immutable external WORM/CAS and encrypted DR restoration evidence. This source and any green CI receipts are **development-only**.

**Release posture is immutable:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged and `main` untouched; no external customer/supplier messages, official quote/PO/GRN, stock/finance/tax posting, provider activation, or production deployment/migration.

References: [1FH protected authority reads](PHASE_1FH_PROTECTED_AUTHORITY_TABLE_READ_HARD_HOLD.md), [1FJ view-grant quarantine](PHASE_1FJ_RUNTIME_VIEW_GRANT_QUARANTINE_HARD_HOLD.md), [M01–M30 master plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
