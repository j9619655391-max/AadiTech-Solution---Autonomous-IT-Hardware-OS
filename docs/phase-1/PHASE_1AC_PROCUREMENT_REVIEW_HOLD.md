# Phase 1AC — server-authoritative internal procurement review and held PO

**2026-11-11 — Development branch only. Production release: HOLD.**

This milestone adds an auditable supplier and purchase-requisition foundation to Phase 1AB. `crm_products` remains the existing authoritative product master and `inventory_sites` supplies the registered warehouse/site master. Phase 1AC does **not** issue an external purchase order, attest external supplier identity or validate physical delivery; approvals are explicitly internal.

## Implemented data contracts

Migration `0015_procurement_internal.sql` adds seven additive MySQL tables:

- `proc_suppliers`: owner-entered legal name/code and optional claimed GSTIN. Initial state **UNVERIFIED**. Independent REVIEWER may attest a non-sensitive identity-evidence reference, changing state to **REVIEWED_INTERNAL**. This is *not* an external supplier registry/KYC verification.
- `proc_requests` and `proc_request_items`: immutable owner-submitted requisition and 1–25 SKU snapshots, site, supplier quote evidence ID, requested quantities and proposed unit purchase costs (captured from supplier quotes, **not** inferred from catalog). Monetary totals calculated on server with exact decimal paise arithmetic. No expenses, tax or inventory balances posted.
- `proc_request_keys`: transactionally reserved UUID idempotency key scoped to requesting owner, canonical request SHA-256, exact replay semantics and changed-payload rejection. Prevents ambiguous network retries from duplicating purchase requests.
- `proc_review_decisions`: one immutable independent REVIEWER decision per request with explicit quote-evidence attestation required for approval, reason and foreign-key audit actor; requester cannot review their own request. Parent row lock serializes approval.
- `proc_po_holds`: approved internal requests may be snapshotted once into a held hash-recorded **internal** PO preparation, with constant `status='HELD'`, `dispatch_state='DISABLED'`; SHA-256 reflects captured snapshot. No recipient, address or client amount is accepted on hold creation.
- `proc_audit_events`: append-only internal events for supplier creation, attestation, requisition, independent review and held snapshot.

**No** stock receipt, movement, sale, reservation, transfer, serial/lot booking, COGS, ledger journal, invoice or supplier payment is triggered in any endpoint.

## Authority / trust boundaries

| Role | Routes | Controls |
|---|---|---|
| OWNER | `GET/POST /api/procurement/suppliers` | Strict supplier schema; creation remains UNVERIFIED; POST requires session+CSRF, privileged MFA policy and recent password step-up |
| REVIEWER | `GET /api/procurement/review/suppliers`, `POST /api/procurement/review/suppliers/:id/attest` | Reviewer must be independent of creator; evidence reference + explicit affirmative check; mutation requires MFA policy + recent step-up |
| OWNER | `GET/POST /api/procurement/requests`, `GET /api/procurement/requests/:id` | Supplier must be REVIEWED_INTERNAL, site must exist, product IDs must be active, 1–25 nonduplicate lines, quoted costs positive/decimal, bounded totals, unique UUID idempotency key; own requests only |
| REVIEWER | `GET /api/procurement/review/requests`, `GET /api/procurement/review/requests/:id`, `POST .../:id/decide` | Cannot be requester; immutable one-time decision, explicit reason, approval demands quote evidence attested, MFA+step-up |
| OWNER | `POST /api/procurement/requests/:id/hold` | Exact empty JSON body; required approved review, same creator, active internal supplier attestation; single held snapshot, idempotent response, dispatch DISABLED |

All routes are authenticated, all mutation routes check same-origin and CSRF. Production `MFA_REQUIRE_PRIVILEGED=true` enforces MFA-verified sessions. `GET` responses are no-store. Unknown endpoints return JSON 404 instead of SPA success. Malformed input, duplicates, stale approvals and unauthorized roles fail closed; SQL details are not returned to browser.

## Frontend

- Owner's **Procurement** tab now includes `LiveProcurementWorkspace`, using actual MySQL products/sites and supplier/requisition APIs. No auto-populated supplier or quote prices.
- Independent `ReviewerWorkspace` includes `ProcurementReviewerPanel`, separated from owner write paths; its decision never triggers external delivery.
- Prior browser-only procurement panel remains collapsed under a clearly labeled **DEMO ONLY** disclosure.
- All write UIs require recent password verification; production MFA remains enforced server-side.

## Migration & testing

Run `bun run db:migrate:procurement` only against disposable CI (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicitly approved isolated TLS staging (`PROCUREMENT_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, **not** NODE_ENV=production). The script fails closed on missing/altered prerequisite checksum entries (0001–0014), uses the existing named MySQL migration lock, hashes immutable SQL bytes, checks repeat runs and does not run legacy schema reset.

CI: `tests/procurement-validation.test.ts` covers strict schemas, decimal/quantity boundaries, idempotency, evidence and migration restrictions. `tests/procurement-mysql.integration.ts` checks role isolation, CSRF/step-up, independent supplier attestation, duplicate prevention, precise request snapshots, rejection, one-time approval, held PO replay, disabled dispatch, absent opening-count mutation and absent receipt API. Baseline TypeScript, tests and build plus existing MySQL/auth/Chromium suites continue to gate the branch.

**No live staging/production data, supplier integration, email, WhatsApp, payments or stock postings were accessed or executed in this milestone.**

## Remaining required engineering phases (open)

1. External supplier KYC/contract/source verification and tax/legal compliance with independent approvals; reconcile supplier quotes against contractual price authority, budgets, forex, freight and GST.
2. Real PO issuance: distinct after-HOLD authorization gate, signed immutable document, protected supplier destination, transactional outbox, idempotent connector, delivery acknowledgments, explicit human review and rollback.
3. Goods receipt in quarantine: match issued PO and approved ordered quantities, physical counting, quality acceptance, serial/lot tracking and warranty IDs; independent receiver approver.
4. Immutable physical stock movement and reservation ledger with transfer/return, no-negative quantities, robust concurrency, reconciliation, stocktake adjustments, and warehouse custody evidence. Only then expose **available-to-sell**.
5. Finance: vendor invoice 3-way match, GST/HSN review, landed costs, inventory valuation, COGS, payables, credit notes, payment integrations and audited general ledger.
6. Real isolated staging TLS, owner/reviewer MFA device tests, private backup/restore, RPO/RTO measured evidence, security and operations sign-offs; no production release until those external gates.

**Issue #2 remains OPEN. Draft PR #1 remains unmerged. `main` is unchanged.**
