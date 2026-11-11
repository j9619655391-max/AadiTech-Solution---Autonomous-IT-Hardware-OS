# Phase 1AG — Hard-zero stock-ledger foundation, independent release HOLD and no-negative-stock enforcement

**2026-11-12 · Development/isolated CI only · Production release: HOLD**

## Scope and production truth

Phase 1AG is a **ledger foundation**, not a real operational ledger with posted goods. Existing 1AB opening counts are owner-attested historical observations; 1AD custody is internally quarantined; 1AC/1AE supplier purchase orders are HELD and NEVER SENT; 1AF supplier acknowledgments are manually asserted, not authenticated; 1AF GRN reconciliation is internally HELD, not an official GRN. None can create available-to-sell stock. No supplier message, invoice, payment, physical movement, customer reservation or inventory valuation was executed.

**This phase deliberately keeps every actual site/SKU available, reserved, picked, posted quantity at exactly ZERO.** A reviewed stock-release 'approval' only produces an immutable internal HELD evidence outbox with posting DISABLED. A demand plan never allocates inventory, and no actual stock movement journal is activated.

## Additive database migration 0019_stock_release_planning.sql

| Table | Authority and constraint |
|---|---|
| inv_stock_position_gates | One row per site/product, explicit nonnegative CHECK and hard-zero CHECK on available, reserved, picked, posted; MySQL rejects even direct positive or negative quantity mutations |
| inv_stock_release_intents | Immutable source-bound release-review intention, one per 1AF held GRN and observed delivery; statuses PENDING_INTERNAL, REVIEWED_HELD, REJECTED_INTERNAL |
| inv_stock_release_intent_lines | Every source SKU, observed quantity, site, SERIAL/LOT tracking, immutable full serial list and lot evidence; not a sellable serial-ownership ledger |
| inv_stock_release_decisions | Exactly one independent reviewer, written reason/evidence, and source-inspected attestation |
| inv_stock_release_holds | One SHA-256-bound approved evidence snapshot, SQL state HELD and posting_state DISABLED only |
| inv_reservation_planning_intents | Immutable per-release/SKU quantity/case reference, no more than observed internal quantity; SQL state HELD and reservation_state DISABLED, zero allocated units |
| inv_stock_foundation_audit | Actor-bound event digests for release and planning decisions, internal only |

## Role-scoped API and workflow

All GET endpoints are authenticated, no-store and role-scoped. All mutations additionally enforce CSRF, recent password step-up and configured privileged MFA. MySQL transaction locks, unique indexes and one-time approval semantics protect concurrency and duplicate retries.

- OWNER GET /api/stock-foundation/held-grn: own internally reviewed 1AF GRN evidence only, with explicit officialGrnIssued:false.
- OWNER POST /api/stock-foundation/release-intents: exact JSON heldGrnId. Verifies 1AC frozen PO hash; 1AE disabled dispatch outbox and independent decisions; 1AF acknowledged-claim internal inspection, independently reviewed 1AD quarantine and full serial/lot evidence; frozen 1AF GRN pack/held hash and reviewer independence. In one transaction creates hard-zero site/SKU gates, complete release lines and SHA-256-bound immutable release header. Identical retry returns same ID; conflicting source fails.
- REVIEWER GET /api/stock-foundation/review/release-intents and /:id: rechecks source and displays complete held-source SKU, lot, quantity and serial identity.
- REVIEWER POST /api/stock-foundation/review/release-intents/:id/decide: exact decision (REVIEWED_HELD or REJECTED_INTERNAL), 12–1000-char reason, evidenceRef and sourceInspected boolean. Positive HELD review re-evaluates every source hash/line and inserts one HELD/DISABLED outbox. No stock posted.
- OWNER POST /api/stock-foundation/reservation-plans: exact releaseIntentId/productId/quantity/planningRef, only against independently reviewed HELD release and source SKU. Requested 1–1000 and no greater than internally observed quantity. Row-level locks, unique release/SKU, strict replay consistency. Allocated quantity always 0; reservation disabled.
- OWNER GET /api/stock-foundation/positions, /release-intents and /reservation-plans: own MySQL records only, explicit non-posting/zero authority and availableToSell:null.
- OWNER POST /api/stock-foundation/allocation-attempt: explicitly returns 409 for a positive request against zero live availability, even if demand plan is held. No stock writes.
- No POST stock-post, movements, transfers, picking or warehouse-debit endpoint exists. Unknown routes are 404.

## No-negative-stock and concurrency invariants

The noNegativeProjection arithmetic helper permits only nonnegative safe integers, validates conserved available + reserved + picked = posted, and rejects request quantities exceeding available. In 1AG the operational ledger gate is always (0,0,0,0): any positive debit or reservation fails. MySQL CHECK (all four quantities = 0) and explicit application read locks are defense in depth; a database-admin mutation to nonzero fails even without the API. The zero gate is a control flag, **not evidence of true warehouse inventory being zero**.

Unique held-GRN/observation release binding, unique released SKU lines, one reviewer decision/outbox and one plan per release/SKU prevent competing internal evidence. Concurrent identical calls should resolve as one CREATE and one replay; changes to an already captured plan are conflicts. A claimed quantity no larger than quarantine is NOT an allocation limit for real stock; it is only a document planning boundary. No replenishment credit, transfer or reservation authority is inferred from an unverified supplier claim.

## Source evidence verification

Release creation and independent review use recursive JSON comparison for frozen nested SKU/serial arrays (object key order tolerant, strict array identity/order), and reconstruct 1AF GRN HELD snapshot digest, attached pack, claim, 1AE PO manifest/outbox, 1AC original purchase-review hash and independently witnessed 1AD original SKU/quantity/lot/serial identifiers. They reject missing or duplicated custody events, modified serial lists, unexpected sites, non-independent decisions and source hash mismatch. SHA-256 detects unexpected divergence from captured internal bytes; it is NOT an external digital signature or proof of supplier/warehouse authenticity. Direct DB privileges still require independent governance and immutable off-system evidence.

## Verification

- scripts/migrate-stock-foundation.ts refuses production/unapproved DB and allows disposable aaditech_ci test DB or explicit isolated non-production TLS aaditech_staging_* with STOCK_FOUNDATION_MIGRATION_APPROVED=YES and STAGING_DISPOSABLE_CONFIRMED=YES. Requires all previous 18 migration SQL SHA-256 checksums, a shared MySQL migration lock, unknown-migration refusal and idempotent rerun.
- tests/stock-foundation-validation.test.ts: strict exact schema; negative, unsafe, oversubscribed and unconserved no-negative arithmetic; source hash and serial ordering; internal-only review declaration and migration target rejection.
- tests/stock-foundation-mysql.integration.ts: isolated full 1AC/1AD/1AE/1AF source fixtures, role/CSRF/password step-up, upstream GRN hash corruption denial, concurrent release retry, exact source SKU lines, direct MySQL positive/negative CHECK refusal, serial mismatch blocking review, immutable HELD reviewer outcome and rejection, concurrent nonallocating plan replay, exceeded quantity/changed replays/foreign SKU denial, allocation-attempt 409 and absent real stock-post routes.
- CI applies migration 0019 twice and requires real disposable MySQL tests, existing Chromium MFA/role security smoke and read-only staging preflight. Preflight checks all zero quantity columns, reviewed release decisions to HELD outboxes, missing HELD approvals, and planned quantities/disabled allocation state. The 19 migration files remain included in SHA-256 release-candidate inventory.

## Frontend and outstanding blockers

Owner panel: reauthentication, held GRN selection, immutable release preparation, reviewed-HELD intent, nonallocating demand plan and read-only zero site/SKU position table. Reviewer panel: SHA/serial/lot provenance detail, evidence ref, signed-off reason and one-time independent HELD or reject decision. Both explain the no-stock, no-GRN and no-reservation boundary.

Before actual stock can be recognized or reserved: verified supplier identity and authenticated dispatched PO; vendor-signed acknowledgment; shipping evidence; independently witnessed official partial/full warehouse GRN; quarantine-to-sellable release; explicit change-controlled separate actual stock posting ledger with double-entry movement, serial ownership, no-negative atomic concurrency and reversal; valuation, GST/COGS and invoice matching; audited real TLS staging, encrypted independent restore and owner/security/ops production authorization. The 1AG hard-zero CHECK must NOT be silently weakened.

**Release status: HOLD.** Keep Draft PR #1 open, draft, unmerged and main unchanged; Issue #2 OPEN. No production MySQL migration, Hostinger deployment, supplier communication, genuine GRN, live stock posting or reservation was executed.