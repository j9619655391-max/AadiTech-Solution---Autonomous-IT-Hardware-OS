# Phase 1AB — MySQL product master and controlled inventory opening counts

**Development-only implementation. Release decision: HOLD.**
The canonical product catalog already exists in `crm_products` through owner-scoped CRM APIs; do not duplicate SKU/price masters or import browser fixture inventories. Phase 1AB adds only *owner-attested historical opening count records*, **not** live inventory availability.

## Schema and invariants

- Migration `0014_inventory_opening_counts.sql` is additive: `inventory_sites`, `inventory_opening_counts`, and `inventory_opening_requests`.
- No warehouse or stock records are seeded. Every site is explicitly named by an authenticated owner; site codes are unique and immutable.
- Each active CRM product can have exactly one opening count per registered site. Quantity is integer 0–1,000,000; zero is an explicit count and is distinct from missing data.
- Count requires a non-sensitive evidence/ticket reference. Count rows are append-only and immutable. Retakes or later receipts require a governed movement/adjustment lifecycle; do not edit historical opening counts or import fictitious values.
- Transactional idempotency reservation (`actor_id`, UUID `Idempotency-Key`, SHA-256 of canonical payload) prevents double inserts and rejects replay with changed request content.
- MySQL commit precedes success. No endpoints issue, reserve, sell, dispatch or value stock. The API reports `availableToSell:null`, `reservations:null` and `status:OPENING_COUNTS_ONLY`.
- Owner-only reads. Mutations require session + CSRF, production privileged MFA policy, session-bound recent password step-up. CI cannot replace human physical evidence review.

## API

| Method | Endpoint | Effect |
|---|---|---|
| GET | `/api/inventory/sites` | Owner-only registered locations |
| POST | `/api/inventory/sites` | Immutable site `{code,name}`; MFA policy + password step-up |
| GET | `/api/inventory/opening-counts?page=1&limit=25` | Paginated historical counts, not availability |
| POST | `/api/inventory/opening-counts` | One count per product/site, exact `{productId,siteId,quantity,evidenceRef}`, UUID `Idempotency-Key`, MFA/step-up |

UI is under **Procurement → MySQL Inventory**. The legacy procurement UI is collapsed and marked DEMO; it has no official POs or stock movement authority. Create a product master in live CRM before recording a count.

## Migration controls

`bun run db:migrate:inventory` **refuses** production and arbitrary databases. It accepts only disposable CI (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicitly approved isolated TLS staging (`INVENTORY_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`). The script requires the preceding 13 checksum migrations, uses a named migration lock, then records the SHA-256 of migration 0014. A rerun checks the checksum. If partially applied DDL fails, investigate with the operator; never destroy tables to reset history.

CI tests invalid payloads, authentication, role denial, missing CSRF, password step-up, site duplicates, unique product/site opening count, idempotency mismatch and no live stock claims.

## Required next gates — NOT implemented

1. Approved supplier catalog, RFQ/PO with requester-approver separation, tax, confirmed supplier identity and budget authority.
2. Real goods receipt matched to approved PO, accepted QC and serial/lot tracking, guarded warehouse custody and immutable stock movements.
3. Reservations, picks, issues, returns, transfers, no-negative-stock invariants, reconciliation and audited adjustments. Only then define available-to-sell.
4. Approved purchase-cost valuation, COGS, invoice/payment reconciliation and financial ledger with GST/tax review. Do not derive margin/revenue from counts.
5. Independent physical count witness, real staging TLS/MySQL verification, encrypted backup/restore and disaster recovery measurements.
6. Keep Phase 1Z `productionReleaseAuthorized:false`, Draft PR open, no production schema migration/deployment/outbound dispatch.

**No live Hostinger or production systems were accessed by this milestone.**
