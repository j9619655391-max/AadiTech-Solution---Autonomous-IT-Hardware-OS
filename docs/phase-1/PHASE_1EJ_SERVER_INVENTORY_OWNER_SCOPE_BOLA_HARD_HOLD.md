# Phase 1EJ — Server inventory owner scope BOLA/IDOR denial — production HARD HOLD

**Date:** 22 November 2026 IST. **Branch:** `chore/phase0-foundation-20261106`, Draft PR #1. Original Issue #2 still OPEN. No production-side actions.

## Verified risk and exact security scope

`server/inventory/router.ts` previously selected *every* `inventory_sites` record for any authenticated OWNER and every `inventory_opening_counts` record plus aggregate count. The `POST /opening-counts` MySQL transaction checked that a warehouse/site ID existed, without confirming ownership. An OWNER who obtained another OWNER's site ID could attempt to create a count there. This is a real actor-scope BOLA/IDOR risk, not a remote authority onboarding blocker.

## Implemented enforcement

1. `GET /api/inventory/sites` must use `WHERE created_by=?` bound to authenticated server session `res.locals.auth.userId`, never a browser-provided owner ID.
2. `GET /api/inventory/opening-counts` must join warehouse site and filter both `c.attested_by=?` and `s.created_by=?`. The `COUNT(*)` total must use identical scope to avoid revealing foreign counts in pagination metadata. `availableToSell` and `reservations` remain null.
3. `POST /api/inventory/opening-counts` must lock the registered site using `WHERE id=? AND created_by=? FOR UPDATE` before count insertion. A foreign site is rejected as invalid; MySQL rollback erases its idempotency reservation. It is never a real inventory receipt, sale or stock movement.
4. Idempotent replay must verify both original `c.attested_by` and `s.created_by` against session before returning the prior count. Existing exact input validation, atomic request key and role/CSRF/MFA/step-up restrictions remain.
5. No migration, credential activation, bypass, global access elevation, browser demo import, PR merge or external business action is added.

## Test and acceptance evidence

`tests/inventory-mysql.integration.ts` uses a **real disposable CI MySQL**, two authenticated OWNER sessions with separate sites/counts, a REVIEWER and anonymous request. Four new integration tests cover actor-scoped sites, count rows and totals, known foreign site write denial including idempotency rollback and unchanged foreign quantity, and 401/403 auth rejection. Existing stock tests continue to test valid owner count creation, idempotent replay, conflicts and stock availability null. The `server/inventory/router.ts` and `tests/inventory-mysql.integration.ts` paths are included in Phase 1BV/1BW local source custody.

**Limit:** Existing system has an OWNER actor ID, not a production-ready multi-tenant legal-entity authorization model. This fix isolates existing personal warehouses but is **not** complete tenant/role ACL enforcement across CRM, procurement, vendor catalog, quotes, stock or finance. End-to-end BOLA audit and independent staging acceptance remain open in Issue #2. No trustworthy live stock quantity is asserted.

**Production release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Draft PR #1 remains unmerged, Issue #2 remains open, `main` stays unmodified; no external provider calls, supplier PO, customer quote, GRN/stock/finance/tax posting, data export or deployment.


## Exact engineering SHA GitHub-hosted verification receipt

Commit [`e193bd0f6a1668140bc30c2758004faa9f3fbd3a`](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/commit/e193bd0f6a1668140bc30c2758004faa9f3fbd3a) independently observed on official GitHub: [push run 45027948592](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45027948592) COMPLETED/SUCCESS, 7 pass + 1 PR-only skipped; [PR run 45027954706](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45027954706) COMPLETED/SUCCESS, all 8 jobs pass. Both were attempt 1. Official Actions Jobs and Checks app 15368 reconciled 16/16 exact job/check IDs, SHA, names, statuses and conclusions, zero mismatches. Hosted baseline Node 1,441/1,441, TS 204/204, staging-security TS 20/20; *real disposable CI MySQL inventory HTTP* 8/8 including 4/4 Phase 1EJ groups, other MySQL integrations and isolated Chromium role/MFA smoke successful. This is **internal engineering CI**, not an independent security audit, tenancy certification, production data migration, external authority or real staging acceptance.

**Important:** Adding this receipt creates a newer docs-inclusive commit that requires *its own* completed exact-SHA push/PR workflows. Do not cite the engineering-only SHA as evidence for the final documentation inclusive source.
