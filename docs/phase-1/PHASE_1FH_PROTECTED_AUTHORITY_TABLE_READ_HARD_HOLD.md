# Phase 1FH — protected authentication and reviewer table READ quarantine (HARD HOLD)

Date: 23 November 2026. **Internal engineering only**, on `chore/phase0-foundation-20261106`. The real production release stays **HOLD**; this is not a staging acceptance, security assessment, or approval of an authority-writer architecture.

## Finding

Phase 1FF correctly refused schema-wide SELECT for the app's runtime DB connection, while still allowing explicit table-scoped SELECT on `auth_users`, `auth_totp_credentials`, session/recovery and reviewer-authority tables. A compromised runtime connection with these grants could read raw password hashes, MFA recovery material, active session/authorization records and sensitive reviewer evidence even though every broad wildcard grant is rejected. Table specificity alone does not establish data minimization or credential confidentiality.

## Implemented deny-only technical control

- `scripts/phase1fb-runtime-db-privileges.ts`: `assessRuntimeGrantEnvelope` now refuses SELECT and SELECT-mixed grants on the existing eight-item `PROTECTED_AUTHORITY_TABLES` set. Schema-wide access, authority-table writes, excessive DDL and role delegation remain refused. Error receipts use a fixed generic reason, **never a grant body or account name**.
- `tests/fb-runtime-db-privileges.test.ts`: scoped CRM SELECT and ordinary CRM write remain eligible, while all eight protected tables reject explicit table SELECT, mixed SELECT/UPDATE and case/quoting variations. No source or unit test promotes a PASS to external DBA approval.
- `tests/staging-preflight.test.ts`: actual identity/schema and SHOW GRANTS observation on one held MySQL session now must return HOLD for auth-user and TOTP table reads.
- `tests/fc-runtime-db-privileges-mysql.integration.ts`: isolated disposable `aaditech_ci` creates a random candidate MySQL account, grants protected-table reads, requires the same-connection read-only preflight to fail, revokes those grants and proves recovery. **No production/staging identities are created or edited.**

## Architectural blockers that are deliberately NOT hidden

This stricter gate **cannot be interpreted as real-world application readiness**: existing monolithic login, MFA, reviewer and session flows can require SQL access to these tables using the current runtime credential. Without an independently designed and provisioned split credential model, trusted confined auth/reviewer service endpoints, bounded redacted views, validated caller authorization and genuine end-to-end HTTP auth/MFA tests, a real staging service may fail both the security preflight *and* authentication functionality. Operators must not waive the technical failure by restoring `auth_users` SELECT to the general runtime user.

An approved DBA and independent Security reviewer must inventory **all** sensitive columns, tables, definer routines, views, row grants and effective/current/default roles; provision separate lowest-privilege service identities under change control; verify denial for the general runtime principal at **real isolated TLS staging**; then demonstrate operational login/MFA, reviewer revocation, CRM and privilege separation under concurrent tests. This code is a point-in-time textual SHOW GRANTS observation, not a cryptographically witnessed account entitlement or complete MySQL privilege graph. Synthetic MySQL fixture PASS does **not** supply corporate authority, live external trust, security signoff or deployment permission.

## Evidence and required acceptance

- Development code and adversarial tests: this phase's Git commits and exact-head GitHub push/PR workflow results, once completed. **Record a CI result only after observing its actual completed conclusion.**
- External acceptance: real DBA grant reconciliation, independently authenticated credentials, approved TLS staging, Security/Operations review, actual signed source/build provenance, independent custody, DR exercise, legal/MCA/eMudhra/CCA/RCAI approval and M01–M30 functional evidence all remain **OPEN**.
- Governance: PR #1 **Draft/unmerged**, `main` unchanged, Issue #2 open; no live quote/PO/GRN, stock, payment, tax, customer messaging, provider activation or production deploy.

**Unconditional release state:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

Related: [1FE write restrictions](PHASE_1FE_RUNTIME_AUTHORITY_TABLE_MUTATION_HARD_HOLD.md), [1FF schema-wide SELECT ban](PHASE_1FF_NO_SCHEMA_WIDE_RUNTIME_READS_HARD_HOLD.md), [1FC staging grant gate](PHASE_1FC_STAGING_RUNTIME_PRIVILEGE_GATE_HARD_HOLD.md), [M01–M30 completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
