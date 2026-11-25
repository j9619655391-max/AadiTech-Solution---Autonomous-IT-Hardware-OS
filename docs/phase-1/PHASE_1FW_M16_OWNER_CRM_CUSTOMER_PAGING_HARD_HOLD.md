# Phase 1FW — M16 owner-scoped CRM customer paging in held-only ticket intake

Date: 24 November 2026 IST. Development branch `chore/phase0-foundation-20261106`; Draft PR #1 OPEN/unmerged and Issue #2 OPEN. No authorized external customer, provider, production database, legal or security authority is supplied.

## Scope: an otherwise inaccessible 101st eligible CRM customer

M16 internal ticket lists became keyset-paginated in Phase 1FV, but the **ticket-creation customer selector** still populated via one `crmClient.list('customers',1,100)` call and had no control to choose the 101st or older customer. The UI could therefore strand legitimate owner-scoped CRM customers even if the server would authorize a ticket for them.

Phase 1FW reuses the existing CRM endpoint, **not a new unreviewed CRM query or direct client database access**. The existing `GET /api/crm/customers?page=N&limit=100` is protected by `requireOwner`, per-user original `crm_audit_events` customer CREATE provenance, non-deleted CRM row checks, and read-only no-store responses. The CRM server limits `page` to 100000 and `limit` to at most 100. The M16 POST revalidates ownership and active customer creator provenance **inside its OWNER-locked MySQL transaction**, regardless of the selected browser value.

## Bounded implementation

- `src/services/serviceDeskCustomerPaging.ts` validates the server-owned `PageResult` structure: an exact requested positive bounded page number, server `limit:100`, safe nonnegative total, at most 100 customer rows, canonical customer UUIDs, distinct IDs and nonempty names. It refuses malformed/foreign-shaped data rather than blindly importing it into the selector. The helper returns page, previous/next eligibility, and retains a prior selected ID only when that ID actually exists in the newly displayed authorized page; otherwise it selects the first displayed record or empty.
- `src/components/LiveServiceDeskWorkspace.tsx` now shows `Previous 100 customers` and `Next 100 customers` for a catalog greater than 100, with exact page and total counts. Client state contains **one** 100-customer page, not an ever-growing array of sensitive CRM profiles. Navigation uses `crmClient.list('customers',requestedPage,100)` and does not invent a new permission or treat a name in the UI as consent.
- A monotonic in-memory request epoch rejects late responses from superseded customer page requests; refreshing the workspace invalidates any pending older-customer request and clears its spinner. Creating an internal ticket is disabled during customer page selection. Refresh resets selector to page 1 and clears a selection not visible there. Existing customer consent disclaimer must be explicitly acknowledged for **each** new ticket, and resulting ticket stays `customerConsentState:'UNVERIFIED'`, `externalDispatchState:'DISABLED'`, `mode:'INTERNAL_HELD'`.
- No schema migration, customer edit, external dispatch, CRM auto-discovery, actual customer communication, warranty/AMC/SLA or completed repair action is introduced. The existing CRM uses **OFFSET pagination**; inserts/deletions between page requests can shift pages. It is not an immutable historical snapshot, signed evidence, or proof of completeness under concurrent mutations.

## Tests and CI-only meaning

- Pure service-desk unit tests validate page 1/2/3 bounds, maximum 100 rows, duplicate or invalid CRM ID, bad totals/page sizes, selected-ID preservation and reset; source contracts verify `requireOwner`, original CRM creator provenance, fixed 100-row limit, bounded UI and stale-response epoch behavior.
- A disposable `CRM_TEST_DB=1`, `NODE_ENV=test`, `DB_NAME=aaditech_ci`, `DB_SSL=false` MySQL HTTP regression mounts the **actual** authenticated CRM router beside the actual service desk router; creates 101 additional synthetic CRM customers for another OWNER, confirms a 102-record CRM owner catalog across two pages, disjoint IDs, page-two access to original old customer, no other-owner leakage, 401 anonymous/403 REVIEWER denial, and a legitimate **page-two** customer ID permitted by M16 POST for the correct OWNER but rejected 404 for the foreign OWNER. All consent and dispatch flags remain held; no real external customer exists in the CI fixture.
- Do not call this work integrated VERIFIED until **both** exact latest commit GitHub Push and Draft-PR workflows are `COMPLETED/SUCCESS`, including baseline tests, build/typecheck, real MySQL integration, browser MFA/role tests and governance HOLD controls. Retain any intermediate failed runs as failures rather than rewriting history.

## Real-world blockers unchanged

This is a bounded owner-visible **internal selector improvement**, not authorization to deliver actual IT support, collect customer data, send messages, assign a technician, promise an SLA, invoice, purchase inventory, sign provider artifacts or deploy anything to production. True identity-backed customer consent, actual supplier/warehouse/technician approvals, legally validated business authority, independently provisioned TLS staging/auth/runtime separation, DBA and Security/Legal/Business independent signoffs, eMudhra/MCA/CCA/RCAI provider trust plus live signed CRL/OCSP, signed WORM/DR evidence and external acceptance for all M01–M30 modules remain OPEN.

M16 stays `SERVER_INTERNAL_HELD`; `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged, Issue #2 open and `main` unchanged. No production migration/deployment, official quote/PO/GRN, stock/finance/tax booking, outbound customer/supplier messages, provider activation or remote Windows operations.

Related: [Phase 1FV owner-ticket list keyset](PHASE_1FV_M16_OWNER_TICKET_LIST_KEYSET_HARD_HOLD.md), [M01–M30 master plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
