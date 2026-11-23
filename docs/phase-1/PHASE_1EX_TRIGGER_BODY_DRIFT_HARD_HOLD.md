# Phase 1EX — installed MySQL trigger-body drift detection (HARD HOLD)

Date: 2026-11-23. Scope: **internal CI** and separately authorized disposable, TLS-isolated staging. **Not** permission to deploy, migrate production, run real business operations, or claim independent provider/legal authority.

## Evidence-driven gap from 1EW

Phase 1EW installed two `AFTER UPDATE auth_users` triggers to revoke reviewer grants and sessions after changes to the account's role or status. Its migration rerun only checked `TRIGGER_NAME`. A privileged SQL operator could replace one trigger's `ACTION_STATEMENT` while keeping its name, and the runner would report an apparently healthy installed trigger. Names are not sufficient evidence of active enforcement.

## 1EX implementation

- `scripts/migrate-ew-role-cycle.ts` now reads `TRIGGER_NAME,ACTION_STATEMENT` for the actual database's `auth_users` `AFTER UPDATE` triggers from `information_schema.TRIGGERS` and **fails closed** on any unexpected/missing/duplicated trigger or changed SQL enforcement body.
- Expected bodies are fixed independently in the verification code, not derived from potentially modified SQL text at runtime. Grant-revocation predicate, table, state and session-delete predicate must all remain present and unchanged.
- Comparison tolerates whitespace and MySQL identifier quotes only. SQL literal casing, operators, predicates and identifiers otherwise remain significant; unexpected formatting fails safe and must be examined, not silently waived.
- The check runs on both the **first successful installation path** and the **checksum-verified already-applied path** of migration 0048. It does not drop/recreate, repair, or auto-promote a failed trigger or grant.
- `tests/ex-trigger-body-integrity.test.ts` covers benign formatting and adversarial name-preserving predicate/table/state mutations, missing/extra/duplicate/swapped/NULL bodies, and source-level checks that the runner uses real `ACTION_STATEMENT` and still rejects production/unapproved staging.
- No new schema migration is required for this code-only integrity check. Migration 0048 SQL and its checksum remain unchanged. Existing GitHub CI runs of the 0048 migration should exercise the live disposable MySQL verifier; source tests alone are **not** operational proof.

## Operational verification (no production access)

1. Confirm exact development-branch commit SHA, non-production MySQL target, disposable fixture and the original 47 prerequisite schema checksums.
2. Run the existing `db:migrate:ew-role-cycle` against the disposable target **after 0048 has been applied**, so the rerun verifies both the recorded checksum and installed SQL bodies. Run `test` and existing MySQL integration suites.
3. Independently inspect trigger names and `ACTION_STATEMENT` with read-only SQL credentials, record query time/database fingerprint and the result. Never copy secrets or real identity data into Git/CI logs.
4. Treat an unexpected trigger/body as an **incident and HOLD**, do not bypass the check, and require separate authorized review before remediation.
5. Confirm the exact source SHA has both successful push and Draft-PR CI, with real disposable MySQL coverage; record any failed attempts as historical evidence.

## Limitations and external blockers

This check is a point-in-time application-controlled observation. A DBA able to alter triggers, grants, the `information_schema` view or the checker can still subvert it. This change does **not** enforce least-privilege DBA separation, prohibit post-check mutation, prove adversarial concurrent transactions, provide independently witnessed timestamped/WORM attestation, prove tenant identity epochs, or establish an actual nonauthor Security/Business signer. Those require independently enforced access controls, external collection, separate identities, real staging drills and human approvals.

Issue #2's original M01–M30 server-authoritative business functionality, real legal/MCA signatory proof, authorized eMudhra sandbox and independently authenticated CCA/RCAI chain + live signed CRL/OCSP, protected-main approvals, signed provenance, encrypted independent DR, WORM/CAS and isolated-stage acceptance remain **OPEN**.

**Release controls remain immutable in policy:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Leave `main` unchanged and PR #1 Draft/unmerged; do not dispatch real quotes, POs, GRNs, stock/tax/financial postings, supplier/customer messages or production migrations.
