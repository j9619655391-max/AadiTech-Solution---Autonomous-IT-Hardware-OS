# Phase 1FG — active MySQL role grant-quarantine prerequisite (HARD HOLD)

Date: 23 November 2026. Development branch only. **This is technical staging privilege observation, not an approved deployment, credential split or independent DBA evidence.**

## Security gap

Previous Phase 1FB/1FC/1FE/1FF runtime checks inspected `SHOW GRANTS FOR CURRENT_USER()` on one authenticated MySQL connection, requiring explicit table grants and refusing schema-wide reads/writes, excessive DDL and protected auth-table mutations. But MySQL 8 session roles can change effective privilege sets: `SET ROLE`, default role activation and globally activated roles can alter what a service session may do. MySQL documentation specifically states `CURRENT_ROLE()` returns comma-separated active session roles, or exactly `NONE` if there are no active roles. `SHOW GRANTS` can list role memberships without fully evaluating activated effective privileges. Both observations are relevant. Official reference: https://dev.mysql.com/doc/refman/8.0/en/information-functions.html and https://dev.mysql.com/doc/refman/8.0/en/roles.html.

## Implemented control

- `scripts/phase1fb-runtime-db-privileges.ts` exports a strict `inactiveRuntimeRoles` predicate, true **only** for the literal MySQL 8 result `NONE`. The guarded staging-only CLI samples `CURRENT_USER()`, `DATABASE()` and `CURRENT_ROLE()` in one **read-only SELECT**, followed by `SHOW GRANTS FOR CURRENT_USER()` on that same authenticated connection. Missing, malformed or any non-NONE role value returns a generic HOLD reason without printing roles/accounts.
- `scripts/staging-preflight.ts` also selects `CURRENT_ROLE()` together with authenticated username and schema on the same checked-out MySQL connection as the role grants. The phase 1FC technical staging gate now refuses missing/active roles **before** allowing any reported grant-envelope PASS.
- `tests/fb-runtime-db-privileges.test.ts` denies missing, blank, lowercase, malformed, multiple and named roles; `tests/staging-preflight.test.ts` simulates default-role escalation and preserves connection release/SQL-denial assertions. The existing real disposable MySQL fixture `tests/fc-runtime-db-privileges-mysql.integration.ts` adds a **randomly created role and user**, explicitly grants the role a protected table read, activates it with `SET DEFAULT ROLE`, verifies real `CURRENT_ROLE()` is **not** `NONE` on a fresh login and asserts the staging checker fails. Both account and role are dropped in `finally`. This fixture refuses any DB other than disposable `aaditech_ci` with `CRM_TEST_DB=1`, `NODE_ENV=test` and `DB_SSL=false`.
- The modified source/tests were already covered by the build-source 1BV and reviewer-intake 1BW manifests; no production SQL or credentials have been changed.

## What this does **not** establish

A result of `NONE` is a point-in-time fact for one session, **not proof against privileges changed after the check**, server-wide role policy changes, privileged DEFINER routines/views, proxies, direct admin credentials or a second application connection using different credentials. A client may attempt to alter its roles after observation if role memberships exist; the deny-by-default SHOW GRANTS parser separately rejects assigned role grants. This does not provide corporate/customer tenancy, signed legal authority, independently provisioned restricted runtime/authority writer accounts, least-privilege per-column read protection, real functional service tests under the split architecture or independent DBA/Security signoff. The existing application still uses a monolithic connection for auth/reviewer writes, so no staging release approval is implied.

## Required evidence before consideration of release

- Exact development HEAD push and Draft PR CI: TypeScript, unit/source guards, real disposable MySQL activated-role test, existing MySQL reviewer/CRM races, read-only CI staging preflight and governance hold jobs must pass. Historical intermediate CI failures remain visible.
- A separately authorized DBA must provision actual restricted staging runtime and authority credentials, validate *effective* privileges/default roles/routines/definers and physically isolated TLS staging, run end-to-end login/MFA/owner/reviewer/CRM tests, collect independent off-system evidence and obtain Security/Operations/business approval. **No code-driven CLI output substitutes for this.**
- All original M01–M30 external/legal/procurement/stock/finance/service/release acceptance and protected main human reviews remain OPEN.

**Production HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 must remain Draft/unmerged; Issue #2 open; main unchanged. Do not deploy/migrate production, activate providers, send real customer/supplier messages, issue official quotes/PO/GRN or post stock/payments/tax.

Related: [1FF table-level-only read policy](PHASE_1FF_NO_SCHEMA_WIDE_RUNTIME_READS_HARD_HOLD.md), [1FC staging grant gate](PHASE_1FC_STAGING_RUNTIME_PRIVILEGE_GATE_HARD_HOLD.md), [M01–M30 ledger](../completion/REMAINING_M01_M30_ACCEPTANCE_LEDGER.json).
