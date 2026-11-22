# Phase 1ER — legacy reviewer active-identity scope closure (development HARD HOLD)

Date: 2026-11-23. This change is a narrow internal authorization improvement; it does **not** complete the original Issue #2 acceptance gates or authorize production.

## Confirmed discrepancy

Phase 1EP/1EQ sensitive reviewer helpers already require an ACTIVE originating OWNER, ACTIVE assigned REVIEWER and exact ACTIVE nomination. Seven earlier reviewer modules checked the grant state but did not directly join the current source-owner account status and role. An old ACTIVE nomination therefore remained eligible in the SQL scope check after the originating OWNER's account became INACTIVE or changed role. The session middleware independently authenticates the REVIEWER, but is not a substitute for checking the original author.

## Implemented controls

- All 28 observed `app_reviewer_scope_grants` reads in QUOTES (4), PROCUREMENT (5), INTAKE (3), DISPATCH (5), EVIDENCE (5), STOCK (3) and JOURNAL (3) reviewer routes now join `auth_users` for both the originating OWNER and the REVIEWER, each requiring exactly its expected role and `status='ACTIVE'`.
- Existing workflow scope, grant `state='ACTIVE'`, creator separation, source lineage and decision `FOR UPDATE` guards are retained. The joined identity predicates also apply inside the write transaction where `FOR UPDATE` already locks the grant, so stale account state cannot be used to authorize the subsequent write without revalidation.
- No auto-grant, migration, client-side approval or production sending is created. No change to sensitive 1EP/1EQ provider or cryptographic reviewer routes.
- `tests/er-legacy-reviewer-active-identity.test.mjs` ensures every SQL grant reference in all seven legacy routes contains both role/status joins and locks the expected total count. The 28-check source contract is not a live account-suspension integration test; independent staging and adversarial operational acceptance remain pending.
- Include the new source contract in existing 1BV/1BW governed source-input inventories. Existing real disposable MySQL suites for these seven routes must still pass in hosted CI.

## Acceptance requirement before marking engineering CI verified

Require actual same-HEAD push and Draft PR workflows and inspect TypeScript compilation, Node test suite, real disposable MySQL suites, browser MFA, frozen dependency advisory checks, source custody and source identity. Do not infer CI completion until runs finish and exact IDs/source are checked.

## Unresolved

Owner/tenant/legal organization reconciliation, complete M01–M30 server-authoritative workflows, approved eMudhra/CCA/RCAI and live CRL/OCSP, MCA mandate, independent reviewer and witness credentials, signed WORM/CAS and DR, protected-main human reviews, authorized security/staging signoffs all remain pending. `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; PR #1 stays Draft, Issue #2 stays open, `main` unchanged.

## Additional disposable-MySQL adversarial verification

`tests/procurement-mysql.integration.ts` now additionally toggles the originating OWNER account to `status=DISABLED` and separately to `role=REVIEWER` in the disposable CI database, while leaving the prior `PROCUREMENT` nomination ACTIVE. It requires the unrelated acting REVIEWER to see no queue entry, to receive HTTP 404 for a known request ID, and to receive HTTP 404 for a direct known-ID decision before duplicate-review handling. Each mutation is restored in `finally`; the original scoped detail must become readable again. Real hosted execution and test results are pending; this is not independent security sign-off.
