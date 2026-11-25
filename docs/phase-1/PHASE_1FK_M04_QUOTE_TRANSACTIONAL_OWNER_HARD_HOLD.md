# Phase 1FK — M04 quote draft transactional ACTIVE OWNER authorization (HARD HOLD)

Date: 24 November 2026 IST. Target: `chore/phase0-foundation-20261106`, Draft PR #1. Bounded server-side quote data integrity/authorization, not a production release or independently issued quotation.

## Defect / business impact

`server/quotes/router.ts` checks `requireOwner` before each HTTP handler. But a concurrent OWNER demotion/disable can commit **after middleware** and **before the quote create or revision transaction**. The M04 quote creator could still save a new internal quote, reuse a stored idempotency key, or append an internal price revision after its authority was revoked. A middleware-only role gate is insufficient for transactional integrity, even when customer/product records are owner-scoped. CRM M03 Phase 1FD already closed this race for customer/lead/product CREATE/PATCH/DELETE; M04 remained open.

## Implemented engineering changes

- Both M04 mutating routes, `POST /api/quotes/drafts` and `POST /api/quotes/drafts/:id/revisions`, now invoke the existing audited `lockActiveCrmOwner(connection, res.locals.auth.userId)` helper immediately after `BEGIN`, before any quote input, idempotency reservation/replay, revision audit or mutation. That uses `SELECT role,status FROM auth_users WHERE id=? FOR UPDATE` and requires an existing `ACTIVE OWNER`.
- Lock holding through transaction completion serializes quote draft mutations with concurrent `auth_users` role/status changes. A demotion/disable that acquires the row lock first causes quote writes to be **denied** after the role transition commits. A quote transaction that holds the lock first completes before a subsequent demotion can commit. This prevents privilege-based time-of-check/time-of-use interleavings without introducing a second transaction.
- `CRMOwnerInactiveError` maps to a generic HTTP 403 `Active OWNER account required` in the quote failure handler. The two original role, CSRF, customer/lead/product provenance, quote margin, price, revision-version, idempotency, audit and database rollback restrictions remain.
- Does **not** add any way to send, publish, accept or invoice a quote. It does **not** make historical notes, external customer data, supplier prices or real legal corporate tenancy trusted.

## Verification

- `tests/fk-quote-owner-race-mysql.integration.ts` runs **only** in disposable `aaditech_ci` (`CRM_TEST_DB=1`, `NODE_ENV=test`, `DB_SSL=false`). It creates a random synthetic OWNER, test session, CRM customer and product, and issues actual Express HTTP draft CREATE/idempotent replay/revision POST. It checks valid flows still work, then disables the OWNER and verifies that later draft, replay and revision requests cannot create rows or alter revision counts/idempotency reservations.
- The second fixture opens real concurrent InnoDB sessions: an OWNER→REVIEWER transition holds the `auth_users` write lock; a competing `lockActiveCrmOwner` attempt must hit MySQL `ER_LOCK_WAIT_TIMEOUT` rather than pass under stale middleware state; after commit the same guard must reject the demoted user. No production user or external staging connection is accessed.
- The source contract confirms both write transactions place the active OWNER lock **after BEGIN** and **before quote/idempotency writes**.
- `package.json`: `bun run test:fk-quote-owner-mysql`. `.github/workflows/ci.yml` invokes this after Phase 1FD MySQL regression. Both 1BV/1BW source custody manifests include the new test and already track the updated quote router/CI/PM inputs.
- GitHub exact-HEAD push and Draft PR CI results are required before marking this synthetic engineering test VERIFIED; real TLS staging/customer authority remains independently unverified.

## Remaining release blockers

M04 remains `SERVER_INTERNAL_HELD`, **not fully accepted**. Outstanding includes source-authoritative legal tenant/customer ownership and authorized data reconciliation, real supplier SKU/HSN/GST/cost attestations, end-to-end quote approval and historical evidence, live independent reviewer controls, customer consent, officially approved quote dispatch/invoice controls, Windows install + isolated staging acceptance, and the separate least-privileged runtime/auth/authority-writer DB architecture introduced as unmet 1FE–1FJ prerequisites.

All remaining M01–M30 acceptance gates, genuine MCA/legal mandate, eMudhra/CCA/RCAI trust, live signed CRL/OCSP, protected main with nonauthor reviewers, WORM/CAS signed provenance and independently witnessed encrypted DR remain open.

**NON-NEGOTIABLE PRODUCTION HARD HOLD:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep `main` unchanged, PR #1 Draft/unmerged, Issue #2 open. No production SQL/migration, customer/supplier messages, official quote/PO/GRN, stock/journal/finance/GST posting or live provider activation.

Related: [1FD CRM transaction guard](PHASE_1FD_CRM_TRANSACTIONAL_OWNER_AUTHORIZATION_HARD_HOLD.md), [1FI exact catalog price floors](PHASE_1FI_CRM_EXACT_MONEY_PRICE_FLOOR_HARD_HOLD.md), [M01–M30 completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
