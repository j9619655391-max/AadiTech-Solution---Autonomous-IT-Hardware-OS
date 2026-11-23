# Phase 1FF — no schema-wide SELECT for runtime DB accounts (HARD HOLD)

Date: 23 November 2026. Engineering only, `chore/phase0-foundation-20261106` development branch; Draft PR #1, not production acceptance.

**Current superseding control (Phase 1FH):** explicit table SELECT on authentication, MFA, security event and reviewer-authority tables is also denied. The historical Phase 1FF description below describes the prior narrower state; use [Phase 1FH](PHASE_1FH_PROTECTED_AUTHORITY_TABLE_READ_HARD_HOLD.md) and the current source for the effective grant policy. This does not resolve the required operational auth credential split.

## Finding

Phase 1FE correctly blocked schema-wide INSERT/UPDATE/DELETE, but the read-only staging runtime grant classifier still accepted `GRANT SELECT ON <target_schema>.*`. Any compromised runtime connection with that grant could potentially read **all** tables, including password hashes, MFA credential material and recovery metadata, app reviewer/authorization state, customer contacts and confidential source evidence. Blocked DML/DDL privileges alone do not enforce read confidentiality or the principle of least privilege.

## Implemented technical guard

- In `scripts/phase1fb-runtime-db-privileges.ts`, `assessRuntimeGrantEnvelope` now rejects **any** `<target_schema>.*` privilege scope, including SELECT-only and mixed grants, with a generic non-sensitive `Runtime schema-wide data access forbidden` reason. The existing `GRANT USAGE ON *.*` identity grant remains allowed; global DML, admin/DDL rights, role delegation, non-target scopes, malformed syntax and protected authority table **writes** remain denied.
- Accepted DML or SELECT grants must now be **explicit target-schema.table scoped**. The classifier still permits explicit per-table SELECT even on auth tables, so it **does not** prove protection of individual password or MFA columns. Column-scoped grants, restricted database views, and data-access service partitioning require a separate signed design and working HTTP tests.
- `tests/fb-runtime-db-privileges.test.ts` adds both quoted and unquoted wildcard-denial cases and checks the generic failure reason. Its positive cases now use bounded `crm_customers`/ `crm_leads` table grants. `tests/staging-preflight.test.ts` uses a realistic table-only success case and must reject a current-user wildcard read under the same checked-out MySQL connection.
- `tests/fc-runtime-db-privileges-mysql.integration.ts` now creates a randomized **disposable CI** service account and begins with a table-specific `crm_customers` SELECT. It adds schema-wide SELECT and requires the read-only gate to return HOLD; revokes it and repeats denial tests for TRIGGER, direct reviewer grant UPDATE and schema-wide INSERT, then checks recovery and drops the CI identity. No prod/staging grants are changed.
- CI already runs the existing Phase 1FC real MySQL fixture and baseline source/unit tests. The changed files are already inventoried by BV build-input custody and BW review/vendor intake.

## Strict scope and release acceptance

This is a **point-in-time observation**, not live MySQL GRANT provisioning, an externally witnessed admin audit, proof of role/definer/column-effective privilege isolation, an independent legal corporate/tenant mandate, or a production app-level access control. Actual staging connections that still hold schema-wide SELECT must fail the technical preflight; operators may **not** waive this by widening the classifier. Separately authorized DBAs must provision narrow service/authority accounts, verify role/default-role/routine inheritance, conduct functional end-to-end login/MFA/reviewer/CRM checks and collect signed independent evidence before considering any staging acceptance.

In particular the current single runtime connection performs privileged auth writes while the 1FE guard refuses direct writes to protected authority tables; therefore **a real split credentials/privileged writer architecture remains unimplemented**. An isolated synthetic MySQL technical PASS is not application functionality or release GO. No legal customer/vendor access, quote/PO/GRN, warehouse, tax/payment posting or provider activation.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep `main` unchanged, PR #1 Draft/unmerged, Issue #2 and M01–M30 release gates OPEN. No production migration/deployment or external actions.

Related: [1FE authority-table write policy](PHASE_1FE_RUNTIME_AUTHORITY_TABLE_MUTATION_HARD_HOLD.md), [1FC staging privilege gate](PHASE_1FC_STAGING_RUNTIME_PRIVILEGE_GATE_HARD_HOLD.md), [1FB grant observer](PHASE_1FB_RUNTIME_DB_PRIVILEGE_ENVELOPE_HARD_HOLD.md), [M01–M30 master completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
