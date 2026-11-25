# Phase 1EK — CRM, quotation and procurement actor BOLA/IDOR hardening — HARD HOLD

**Date:** 22 November 2026 IST. **Canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; development branch `chore/phase0-foundation-20261106`; PR #1 stays Draft, Issue #2 stays OPEN. Internal engineering on isolated CI only, no external delivery or approval.

## Confirmed server authorization failures

- `server/crm/repository.ts` previously listed all active CRM customers/leads/products and accepted GET, PATCH and DELETE across any OWNER sessions without row-level owner scope. CRM tables have **no `created_by`/tenant ID**. The existing transactional `crm_audit_events` CREATE event records the actual application actor and is the current safe provenance check; this is **not** legal or independently authenticated tenancy.
- `server/quotes/router.ts` previously allowed any OWNER to create an internal draft referencing another actor's customer, lead or product by known UUID. This permitted unauthorized use of contacts, budgets, cost and selling prices even though quote drafts themselves were scoped to `created_by`.
- `server/procurement/ownerRouter.ts` previously listed all suppliers to any OWNER, and accepted another actor's internally reviewed supplier or warehouse site in a new purchase request. That cross-owner reference could then contaminate a held internal PO snapshot.

## Corrective controls

1. Require exact server-session OWNER actor + a matching CRM CREATE audit event for every row returned by list or detail and each locked CRM update/delete. Count must use identical filter. Missing, foreign or unaudited historical rows remain **hidden and not editable** until separately reviewed and migrated; do not invent legal ownership or mutate historical data.
2. In the same MySQL quote-create transaction, check customer, optional lead and every product has matching CREATE audit provenance for the authenticated actor. Unauthorized references fail with no committed draft or idempotency key; server-side GST/margin, snapshots, revision rules and HOLD unchanged.
3. Return only OWNER-created suppliers; join supplier/site ownership on request list/details and held PO preparation, and enforce creator checks in locked supplier/site lookup during request creation. Keep reviewed supplier requirement, independent procurement review, password step-up, privileged MFA, CSRF, atomic idempotency and no supplier dispatch.
4. No schema migration, legacy browser import, loose company/warehouse delegation, arbitrary owner-id parameter, bypass, send, GRN or stock posting is introduced.

## Adversarial tests and limitations

`tests/crm-mysql.integration.ts` adds **4** actor-isolation HTTP/MySQL groups with two authenticated OWNERs: private CRM lists/count/details and update/delete, missing CREATE proof and foreign-source denial; customer/lead/product quote-reference BOLA rejections with idempotency-key rollback; valid own-draft creation, replay and isolation. `tests/procurement-mysql.integration.ts` adds **2** groups: private supplier and purchase-request reads and foreign supplier/warehouse UUID denial including transaction rollback. Local Phase 1BV/BW source receipt inventories now include four modified server modules and both tests. Source should be described as internally validated **only when exact-SHA hosted GitHub CI and MySQL/Chromium pass**, including official Checks/Jobs reconciliation.

**Limitations that are intentionally not claimed complete:** first-class organization tenant membership; legally authenticated owner; safe access/delegation to shared OEM product catalog, retailer entities or shared warehouses; full CRUD authorization in every other commercial/stock/quote-review route; legacy CRM owner attribution with independent signoff; cross-tenant reviewer scope; production readiness. Historical unaudited data remains physically present, deliberately unexposed, and requires explicit migration planning. Applicant-controlled in-app audit is not third-party immutable evidence. Do not close Issue #2 authoritative-data or security acceptance.

**Immutable release boundary:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Never merge `main`, deploy, enroll licensed provider credentials, send customers/suppliers any quote/PO, post GRN/stock/finance/tax, or call live eMudhra/MCA without real external authorization, independent review and isolated staging acceptance.


### Phase 1EK initial exact-SHA CI failure and correction audit (22 November 2026 IST)

- [ ] **Initial engineering commit `832c966d3e51d79b66d667286051cdeb9a02ed28` did NOT pass CI.** Official [push 45050817323](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45050817323) and [PR 45050821660](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45050821660) both COMPLETED/FAILURE in `mysql-integration`, specifically `tests/crm-mysql.integration.ts` 1EK foreign customer/lead/product denial at line 262: unexpected HTTP 503 rather than expected 400. Other six executed push jobs and seven PR jobs succeeded, including baseline. Root cause: the new SQL used reserved MySQL 8 window-function keyword `lead` as a raw table alias only in the optional-lead authorization query, causing SQL parse failure and generic 503. It was NOT a valid denial test or permission waiver.
- [x] **Targeted correction prepared:** changed lead table alias to non-keyword `lead_record` in the quote POST query and added a same-owner positive *lead-bound* quotation test so this SQL path executes on both valid and foreign-source requests. Historical failed run is retained as FAILURE. New exact-SHA push/PR hosted CI and official check reconciliation must pass before claiming this correction internally verified.


## Corrected Phase 1EK engineering SHA / official GitHub Actions acceptance receipt

After initial CI failure for SHA `832c966d3e51d79b66d667286051cdeb9a02ed28` (MySQL HTTP 503 from SQL reserved table alias), exact correction SHA [`abdfb04a8a5b9234f2fb4fc3de5aca38c638949e`](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/commit/abdfb04a8a5b9234f2fb4fc3de5aca38c638949e) PASSED the hosted [push workflow 45051130736](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45051130736) COMPLETED/SUCCESS (7 pass + 1 expected PR-only skip) and [PR workflow 45051136051](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45051136051) COMPLETED/SUCCESS (8/8). Both exact SHA attempt 1. Independently corroborated 16/16 official GitHub Check records (app 15368) with latest Actions Jobs by job/check ID, name, head SHA, status and conclusion; 0 mismatches. Baseline 1,441/1,441 Node, 204/204 TypeScript, 20/20 staging-security pass. Disposable MySQL/HTTP CRM suite `24/24` and procurement suite `10/10` pass including six new 1EK two-OWNER tests; Chromium MFA/role smoke succeeds. No real provider/legal authority or independent security acceptance.

**Receipt itself changes the final docs-inclusive HEAD:** exact-HEAD push and PR workflows must be verified separately on the newer SHA before final development completion can be claimed. **Production remains HOLD.**
