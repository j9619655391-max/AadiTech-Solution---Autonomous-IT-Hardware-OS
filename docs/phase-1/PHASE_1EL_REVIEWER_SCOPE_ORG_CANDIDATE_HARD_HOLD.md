# Phase 1EL — Explicit reviewer-scope nomination, organization candidates: HARD HOLD

**22 November 2026 IST.** Canonical development branch: `chore/phase0-foundation-20261106`. Draft PR #1 unmerged, Issue #2 open. This is internal engineering only, not real external reviewer/organization authority.

## Confirmed authorization problem

A globally authenticated REVIEWER was able to enumerate commercial review records for unrelated OWNER accounts, including quote drafts/revision summaries and supplier/purchase evidence. Phases 1EJ–1EK protected OWNER actor data but did not establish per-owner authorization for reviewers.

## Implemented fail-closed boundary

1. The additive, checksum-registered SQL migration `0043_el_reviewer_scope_candidates.sql` defines a unique owner–reviewer–workflow grant with QUOTES/PROCUREMENT scope and ACTIVE/REVOKED state. No default or retroactive grants. `app_reviewer_scope_events` records GRANT/REVOKE transitions in local MySQL; these are not independent signed evidence or remote WORM.
2. The OWNER API `GET /api/reviewer-scopes` lists only self-owned nominations. `POST /api/reviewer-scopes` accepts precisely reviewerId, scope, decision and 16–500 character reason, with current-password step-up, existing privileged MFA policy and CSRF. A named active REVIEWER is mandatory for GRANT; self-reviewer and duplicate/stale transitions are rejected. The transaction locks target account and grant and records decision. Responses explicitly state that independent external identity is not authenticated.
3. Quote review queue, brief/detail/read and procurement supplier/request reviewer endpoints require an active grant scoped to that record's original created_by OWNER and current authenticated REVIEWER. All reviewer decision and supplier attestation writes lock grant state inside the same MySQL transaction. Revocation prevents a new decision after it commits; unknown/unscoped reviewer gets empty queue or 404.
4. First-class corporation/member candidate tables are present ONLY as explicitly `UNVERIFIED`/`UNVERIFIED_CANDIDATE` with authority and production access flags frozen to NO. They do not attach current CRM/warehouse/product/procurement rows, issue membership, accept legal mandates or grant cross-tenant data access. Genuine verified tenant onboarding remains pending.

## Verification and migration control

`scripts/migrate-el-reviewer-scopes.ts` enforces 43-entry registry, exact predecessor hashes, advisory lock and checksum idempotency. It refuses production. Only disposable `aaditech_ci` testing or named approved isolated TLS staging with explicit review-scope approval is permitted. CI applies it twice before genuine disposable MySQL HTTP tests; read-only staging preflight subsequently checks the new SHA. `tests/el-reviewer-scope-migration.test.ts` checks gate, target and absence of implicit grants. `tests/crm-mysql.integration.ts` and `tests/procurement-mysql.integration.ts` validate genuine session role scope, unassigned/foreign denial, revocation and restore, scope API checks, transactional audit and absence of corporate candidate promotions. Phase BV/BW local provenance inventories cover the changed production paths and tests.

## Unresolved mandatory acceptance

No legally verified tenancy, corporate registry/mandate, independent human reviewer assignment or shared-resource delegation exists. Role REVIEWER alone remains insufficient; only explicit per-owner local nomination allows those two internal queues. Other intake, warehouse, dispatch, journal, provider and evidence-review routes need an analogous end-to-end audit. Historical CRM records without original CREATE-audit provenance remain unmigrated and hidden; no synthetic ownership re-attribution. Original Issue #2 authoritative-data, sales/finance/AMC/tickets/campaigns, quote legal issuance, integrations/contact consent, full route security review, DR/restore, staged operators, CODEOWNERS two non-author reviews, licensed eMudhra/MCA/CCA/RCAI, signed live CRL/OCSP and off-platform WORM/SLSA are pending.

**Immutable release state:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No main merge, provider credential enrollment, customer/supplier messages, real quote/PO/GRN/stock/finance/tax mutation, live database migration or deployment. Local MySQL audit/CI green is not legal external approval.
