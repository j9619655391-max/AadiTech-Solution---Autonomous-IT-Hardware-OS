# Phase 1FC — Staging readiness must observe the current runtime DB privileges (HARD HOLD)

Date: 2026-11-23. This is **development-only application preflight hardening**. It does not install grants, rotate users, claim outside-DBA control, or permit customer-facing production actions.

## Concrete gap

Phase 1FB added the separately invokable read-only command `db:runtime-privileges:preflight`, but the standard `staging:preflight` still certified its own *technical* readiness based on checksums, held business invariants, and installed auth_users triggers even when the runtime account had not been checked for global/DDL/GRANT rights. On approved isolated TLS staging, a privileged schema owner could in principle change enforcement triggers or widen its own powers outside the application.

## Implementation

- `scripts/staging-preflight.ts` imports the existing 1FB deny-by-default grant classifier and its strict staging-only opt-in guard. When (and only when) `checkPreflightTarget` classifies the connection as isolated staging, technical readiness **requires** `RUNTIME_DB_PRIVILEGE_PREFLIGHT=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `NODE_ENV=staging`, `DB_SSL=true`, an approved `aaditech_staging_*` schema name, a configured TLS CA/verification policy and bounded observed grants.
- The exported `checkStagingRuntimeDbPrivilegeIntegrity` acquires exactly **one** pool connection and issues `SELECT CURRENT_USER(), DATABASE()` and `SHOW GRANTS FOR CURRENT_USER()` on that **same** connection, releasing it even when an observation fails. It rejects absent/ambiguous principal, wrong database, unparseable statements, role delegation, global/DDL/admin/GRANT OPTION rights, no bounded DML, or metadata read denial.
- `staging:preflight` prints `runtimeDbPrivileges: PASS | HOLD | NOT_EVALUATED_CI` without exposing grant SQL, account names or error details; actual staging `ready` can be true only with PASS. On disposable CI it explicitly says `NOT_EVALUATED_CI`, never "PASS" for independent staging privileges. The preflight also prints `independentDbaApprovalVerified:false`, regardless of technical grant results.
- `tests/staging-preflight.test.ts` contains same-connection query tests and fail-closed cases for missing identity/schema, admin/DDL grants, delegated roles, SQL access denial, connection release and CI-versus-staging readiness behavior. Changed source/test files were already in 1BV/1BW review input manifests.
- `tests/fc-runtime-db-privileges-mysql.integration.ts` runs **only** on disposable `aaditech_ci` with `CRM_TEST_DB=1`, `NODE_ENV=test` and `DB_SSL=false`. It creates a random temporary CI-only MySQL user, grants SELECT, checks the actual MySQL current-user privilege readback, then adds TRIGGER to demand rejection and revokes it to require recovery; it drops that user in `finally`. This fixture does not attest externally provisioned staging users or production security. Dedicated CI step: `bun run test:fc-runtime-privileges-mysql`. The new fixture is tracked in 1BV/1BW.

## Acceptance evidence to collect

- **In CI (synthetic only):** exact-head `bun run lint`, unit/source contract tests, real disposable MySQL integration and read-only CI preflight, with push and Draft PR jobs both passing.
- **In an independently approved isolated TLS staging environment:** provision a dedicated **runtime service account** distinct from migration/DBA authority. Do not use a privileged migrator for staging readiness. Record the account fingerprint, authentic runtime grants, SQL isolation, external DBA review and `staging:preflight` output securely. Fail HOLD on any absent flag, wide grant, denied metadata or unexpected environment.
- Independently inspect privileged DBA accounts and effective roles **outside this application**. Prove service account cannot mutate triggers, schema, privileges, arbitrary protected rows, or impersonate administrators. Store signed independent evidence outside the DB account's own control. Developer-run checks do not constitute this approval.

## Limitations and security decisions

**Phase 1FE strengthens this classifier:** Phase 1FF additionally rejects schema-wide SELECT, not just writes; only explicit table-scoped SELECT/DML remains eligible, and protected authentication/reviewer authority mutations are refused. This is a conservative technical observation, not an automatic MySQL GRANT change. Existing monolithic auth/reviewer flows may rely on those writes, so the actual operational split into narrowly credentialed runtime and independent authority writer remains unresolved. A technical PASS does not attest end-to-end login/review availability or prevent SQL privilege changes after observation. Grant observation is point-in-time; it does not prove account role changes or SQL tampering are impossible later. All tests run in disposable CI without real authorized staging or outside security witnesses.

Original [master completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md), [M01–M30 acceptance ledger](../completion/REMAINING_M01_M30_ACCEPTANCE_LEDGER.json), and GitHub Issue #2 remain authoritative for the wider outstanding list: real server-backed operations, authorized tenant/company mandates, vetted supplier/provider identities, eMudhra/MCA/CCA/RCAI trust, live signed CRL/OCSP, independent nonauthor reviews, protected main/CODEOWNERS, provenance/WORM/DR and release governance.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged, main unchanged. Never run this in production; no live quote, PO/GRN, customer/supplier messages, stock or finance/tax posting, enrollment or provider activation.
