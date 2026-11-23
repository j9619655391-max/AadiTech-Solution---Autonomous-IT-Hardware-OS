# Phase 1EV — out-of-band reviewer re-enable MySQL/HTTP regression (HARD HOLD)

Date: 2026-11-23. **Internal development / disposable database only.** No real customer, supplier, legal provider, production SQL or deployment authority.

## Gap and implementation

Phase 1EU added transactionally ordered revocation of every ACTIVE app-local reviewer nomination **before** either ACTIVE or DISABLED status transition. Its source-contract test could not prove the real route and database did the same thing when a reviewer had been disabled by direct SQL without running the API.

The added `tests/crm-mysql.integration.ts` regression exercises the existing HTTP router against the CI-only `aaditech_ci` database (guarded by `CRM_TEST_DB=1`), using synthetic OWNER/REVIEWER identities. It:
1. Recreates an ACTIVE QUOTES grant, directly marks the reviewer DISABLED, and inserts a stale session as an adversarial fixture.
2. Confirms the disabled reviewer cannot authenticate and that unauthorized re-enable requests without CSRF or with invalid password step-up return 403 while the user remains DISABLED.
3. Performs a fresh owner password step-up, authorizes re-enable, and checks that the server revokes old app-local ACTIVE grants and stale reviewer sessions, leaves the specific grant REVOKED, returns HOLD/unauthorized-for-production, and denies replay of the stale session.

The test is intentionally executed by the **existing** `bun run test:mysql` command in the `mysql-integration` CI job; there is no hidden feature flag or migration. Source-contract regression `tests/et-reviewer-lifecycle.test.mjs` remains in the baseline.

## Acceptance / falsification

- A test pass requires a genuinely launched disposable MySQL service and HTTP router. A source-only assertion or synthetic report does not pass this gate.
- A regression that permits unverified re-enable, retains an ACTIVE grant, retains any reviewer session or changes the release HOLD must fail.
- Inspect **both** exact-development-HEAD push and Draft PR runs, job statuses, and source SHA before saying CI verified. A new code commit invalidates earlier run attestations.
- Direct SQL operations here are tests, **not recommended production remediation**. No production credential, externally verified reviewer, tenant mandate, eMudhra trust chain, MCA authority, WORM evidence or operator signature is supplied.

## Remaining uncovered threats

Out-of-band REVIEWER→OWNER→REVIEWER role cycles without status changes, hostile direct SQL writes, concurrent database interleavings, and any independent audited reviewer-identity epoch/reconciliation remain **pending**. No check here grants corporate/CCA/eMudhra authority, satisfies full M01–M30 scope, or closes Issue #2.

**Release decision:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 remains Draft/unmerged, `main` unchanged. No deployment, supplier/customer communications, quotes, stock/finance/tax postings or live provider onboarding.

## Phase 1EW follow-up (2026-11-23)

The 1EW forward-only disposable-DB trigger migration revokes grants on actual role/status changes. To preserve the earlier 1EV repair test, its hostile direct-SQL fixture now intentionally reactivates the grant **after** the SQL suspension (simulating privileged database tampering), then asserts API re-enable still quarantines it. This is not evidence that administrators with arbitrary SQL privileges cannot bypass database controls.
