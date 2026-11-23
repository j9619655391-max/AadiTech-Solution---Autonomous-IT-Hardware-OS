# Phase 1FA — deterministic InnoDB reviewer role / nomination interleavings (HARD HOLD)

Date: 2026-11-23. Scope: **disposable CI-only security tests**, not production-ready authorization, live external attack simulation, privileged DBA isolation, legal mandate or independent approval.

## Threat and bound

Phase 1EW installs checksum-locked MySQL AFTER UPDATE auth_users triggers to revoke app-local reviewer nominations and delete sessions on role/status changes. Phase 1EZ verifies installed trigger bodies in a read-only staging preflight. Neither alone proves that concurrent transactions cannot leave stale reviewer grants or sessions.

## New regression

- tests/fa-role-cycle-concurrency-mysql.integration.ts opens **two independent live MySQL connections** with randomized CI-only OWNER and REVIEWER identities. It refuses any database other than aaditech_ci with CRM_TEST_DB=1 and NODE_ENV=test.
- Ordering A: a nomination transaction holds SELECT ... FOR UPDATE on an ACTIVE reviewer and inserts an ACTIVE app-local nomination and session. The competing direct-SQL role update must receive a genuine InnoDB ER_LOCK_WAIT_TIMEOUT. Once the nomination commits, the SQL update succeeds and installed triggers must revoke **all** grants and sessions.
- Ordering B: a direct SQL role transition holds the reviewer row first. A prospective nominator cannot acquire a stale reviewer lock and must receive ER_LOCK_WAIT_TIMEOUT. After the role transition commits, a new locking read observes role OWNER, not REVIEWER; previously active grants and sessions are revoked.
- A source assertion confirms the app reviewer-scope router still locks both the acting OWNER and the subject user and requires an ACTIVE REVIEWER.
- package.json adds test:fa-role-cycle-mysql. .github/workflows/ci.yml requires the test after the 0048 migration and existing real-MySQL integration. BV/BW source custody inventories include the test source.

No 0048 schema change, production write, automatic grant repair, provider send or external business operation is authorized.

## Verification requirements

1. Run lint, existing test suites, the disposable real-MySQL setup/migrations and the new Phase 1FA step. Record exact-source GitHub push and Draft-PR CI results; distinguish historical failures from final corrections.
2. Require both competing-row tests to see MySQL ER_LOCK_WAIT_TIMEOUT, never fake it with a mock. Unexpected successful leapfrogging or remaining ACTIVE nomination/session is an incident.
3. Keep any live isolated staging concurrency test gated on separate authorization; do not run this CI fixture there or in production.
4. Require independent MySQL service account privilege analysis and privileged DBA isolation before operational acceptance.

## Residual risk and HARD HOLD

These two deterministic interleavings do **not** prove arbitrary scheduler correctness, deadlock absence, post-check trigger mutation resistance or restriction of privileged direct writes to the grant table. A DBA can still manually re-activate a grant after the trigger. External attestation, TLS staging, WORM/CAS, signed provenance, independently witnessed encrypted DR, protected main/CODEOWNERS, two nonauthor security/business signoffs, real MCA/legal mandates, official eMudhra/CCA/RCAI provider and revocation evidence, and Issue #2 M01–M30 modules remain OPEN.

**HARD HOLD:** productionReleaseAuthorized=false; productionReleaseBlocked=true; releaseDecision=HOLD. PR #1 Draft/unmerged; main unchanged. No production migration, customer/supplier dispatch, actual quote/PO/GRN, stock/finance/tax posting or live provider onboarding.
