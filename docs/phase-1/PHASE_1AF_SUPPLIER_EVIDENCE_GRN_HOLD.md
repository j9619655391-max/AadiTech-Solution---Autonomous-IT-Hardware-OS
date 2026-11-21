# Phase 1AF — Unverified supplier acknowledgment claims and GRN-reconciliation HOLD

**2026-11-12 · Development branch only · Production release: HOLD**

## Executive decision and scope

**No real supplier purchase order has been issued.** Phase 1AE permits internal approval of a hash-bound supplier PO dispatch preparation but all outboxes are database-enforced `HELD` / `DISABLED`. Without independently verified supplier identity, delivery authentication, authorized outbound transport and supplier receipt confirmation, neither a human-entered acknowledgment reference nor an offline document hash can establish a genuine vendor acknowledgment.

Phase 1AF delivers an audit-ready, **strictly non-posting evidence chain**: an OWNER records an *unverified* assertion that a supplier acknowledged an order, a distinct REVIEWER inspects independently retained document evidence and internally attests/disputes that claim; after separate internal quarantine observation and witnessing (1AD), OWNER may prepare a full-line reconciliation pack. An independent REVIEWER can approve that pack only into a **HELD internal reconciliation record with stock posting DISABLED**. Every API response and screen discloses that the claim is not externally verified, the HELD PO was not sent, no official goods-receipt note (GRN) was created and inventory is not available.

No email, supplier API call, webhook, network worker, invoice, payment, physical receiving authority, stock booking, reservation, transfer, pick/issue or sellable-stock calculation is provided. The absence of a genuine issued PO also means this is **not certified three-way matching**; it is an internal consistency check across internal evidence sources.

## Database: additive migration 0018

`database/migrations/0018_acknowledgment_grn_holds.sql` adds six checksum-registered InnoDB tables:

| Table | Purpose and database constraint |
|---|---|
| `proc_ack_claims` | One immutable owner-entered supplier ACK **claim** per 1AE dispatch preparation/outbox; source ID, uppercase supplier-reported reference, evidence ticket, **owner-supplied document SHA-256**, server claim digest and review state. Unique preparation/outbox links, no authenticated supplier status |
| `proc_ack_claim_decisions` | One immutable independent internal decision per claim, recorded reviewer, written reason, inspection evidence ticket and explicit `document_inspected`; only `ATTESTED_INTERNAL` or `DISPUTED_INTERNAL` |
| `inv_grn_reconciliation_packs` | Exactly one immutable matched claim/1AD observation pair, recorded owner, canonical digest and JSON with dispatch/ACK/observation/HELD PO SHA-256 pointers, exact SKU line count and internally quarantined quantity. One claim and one observation may each enter at most one pack |
| `inv_grn_reconciliation_decisions` | One irreversible independent review of matched evidence with `custody_inspected`, written reason, ticket and outcome `HELD_INTERNAL` or `REJECTED_INTERNAL` |
| `inv_grn_held_records` | Exactly one HELD proof of approved internal reconciliation per pack, canonical snapshot SHA-256 and **database ENUM** `stock_posting_state='DISABLED'`. Cannot become operational GRN or sellable stock |
| `inv_grn_evidence_audit` | Append-only evidence/action SHA-256 and actor for claim recording/decision and pack preparation/decision |

These tables reference existing authenticated actors, 1AE preparations/outbox and 1AD witnessed observations through foreign keys. No operational stock balance, usable inventory ledger, invoice or outbox dispatch capability is added.

## API and invariant design

**All routes** are authenticated, role scoped, no-store; mutations additionally enforce same-origin CSRF, recent password step-up and configured privileged MFA policy. MySQL transaction locks, unique constraints and atomic commit/rollback protect one-time decisions, claims and held records.

| Authorized actor | Endpoint | Scope |
|---|---|---|
| OWNER | `GET /api/evidence-chain/eligible` | Lists only own internally approved 1AE outboxes, with optional claimed ACK and 1AD observation statuses; no external verification |
| OWNER | `POST /api/evidence-chain/claims` | Strict body `{preparationId,supplierAckRef,evidenceRef,documentSha256}`. One immutable claim per reviewed 1AE held outbox. Exact replays return existing; changed body 409 |
| OWNER | `GET /api/evidence-chain/claims`, `GET /api/evidence-chain/grn-packs`, `GET /api/evidence-chain/readiness` | Own evidence only; readiness always declares `productionGrnReady:false`, `availableToSell:null` and `stockPostingState:'DISABLED'` |
| REVIEWER | `GET /api/evidence-chain/review/claims`, `POST /api/evidence-chain/review/claims/:id/decide` | Independently review another user's claim. Exact body `{decision,reason,reviewEvidenceRef,documentInspected}`; positive internal attestation requires `documentInspected:true` |
| OWNER | `POST /api/evidence-chain/grn-packs` | Strict body `{claimId,observationId}`. Rechecks same held source and original owner, independent attested claim, quarantined 1AD observation, complete original SKU/quantities, serialized/lot custody and audit status before preparing a **non-posting** pack |
| REVIEWER | `GET /api/evidence-chain/review/grn-packs`, `GET .../grn-packs/:id`, `POST .../grn-packs/:id/decide` | Independently re-evaluate complete DB source chain; exact `{decision,reason,reviewEvidenceRef,custodyInspected}`. Internal acceptance requires `custodyInspected:true`, creates only one `HELD` / `DISABLED` record |

### Cross-module consistency checks

1. Validate existing 1AE dispatch preparation is `APPROVED_INTERNAL`, and 1AE outbox stays `HELD` / `DISABLED`, with signed-off independent reviewer decision and matching outbox JSON SHA-256. The 1AE canonical manifest must match the frozen recipient, supplier ID, owner, source held order and its SHA-256; destination and supplier remain `REVIEWED_INTERNAL` only. The original 1AC held purchase SHA-256 is reconstructed from canonical field order to allow MySQL JSON object reordering without false mismatches.
2. Claim is bound to exactly that outbox, owner, SHA-256, offline reference and manually supplied SHA-256 document fingerprint. The supplier is **never authenticated by software**. A changed or second assertion conflicts; an attested claim has a distinct REVIEWER, written evidence reference and `documentInspected:true`.
3. GRN-reconciliation pack requires **the same original purchase/hold**, owner and registered site as the 1AD physical observation. Observation must be `QUARANTINED_INTERNAL`, with an independently attested `ACCEPT_QUARANTINE` decision.
4. For every original ordered SKU line, the observed quantity must match exactly. Every 1AD line must have exactly one independent `QUARANTINE_WITNESS_ATTESTED` custody event of identical product/site/quantity and correct reviewer. Revalidate 1AD canonical payload SHA-256, strict lot/serial format, and exact serialized identities against `inv_quarantine_serials`. Missing/extra/tampered lines, wrong product/site, serial mismatch or partial counts fail closed.
5. Reviewer decision re-runs **all of the above validations in its own transaction**, then compares recorded frozen GRN-pack JSON to canonical values and SHA-256. A forged `officialGrnCreated:true`, `stockPostingState:'ENABLED'`, recipient swap, source hash mismatch or orphaned event cannot be approved.
6. Approval inserts one immutable `inv_grn_held_records` row with `stock_posting_state='DISABLED'`, `officialGrnCreated:false` and `availableToSell:null`; rejected packs add no such row. `/api/evidence-chain/receipts`, `stock-post`, `reservations` or supplier-send operations do not exist.
7. `scripts/lib/stagingPreflight.ts` checks a missing/unsafe HELD GRN record and reviewed supplier-claim/decision mismatches, in addition to prior 1AE outbox invariants. A passing disposable database comparison is **not** real supplier authenticity or warehouse possession verification.

SHA-256 here provides mutation/integrity **detection against captured bytes**, not an externally signed document, trusted timestamp, bank/payables evidence, authentic supplier identity, electronic transport acknowledgment or legal proof. An adversary that can edit both data and the hashes may still forge evidence; a distinct external trust anchor and independently checked original document are prerequisites for production.

## Frontend and negative testing

- `SupplierEvidenceOwnerPanel` provides reauthentication, manual claim ID/ticket/64-hex digest submission, eligible 1AE held-outbox picker, 1AD quarantined-observation matching, one-click internal reconciliation and explicit warnings against interpretation as issued PO/GRN.
- `SupplierEvidenceReviewerPanel` lists role-filtered claims and packs, displays entered document digest and immutable internal source hashes, and captures separate evidence tickets, written reasons, inspection assertions and irreversible decisions. It does not include any send/receipt/stock-release actions.
- `tests/evidence-chain-validation.test.ts` tests strict exact-body parsers; uppercase supplier refs; lowercase SHA-256; independent attestation; canonical HELD JSON and forged issuance rejection; and refusing production migration.
- `tests/evidence-chain-mysql.integration.ts` runs in disposable `aaditech_ci` MySQL with synthetic OWNER/REVIEWER sessions and approved held source fixtures; checks role/CSRF/step-up denials, duplicate/changed claim requests, forged 1AE outbox checksum, missing positive ACK review, cross-PO observation pairing, altered quarantine custody quantity, mismatched serial registry, immutable pack tampering, held-outbox-only approval, disputes/rejections, and absence of stock/receipt operations.
- GitHub push and PR CI must both pass typecheck, unit tests, build, migration 0018 apply + checksum rerun, real MySQL tests, existing Chromium browser MFA smoke and read-only staging preflight on the exact pushed SHA. No tests run against live suppliers or production DB.

## Safe migration policy

`bun run db:migrate:evidence-chain` permits only disposable CI (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`), or explicitly approved isolated TLS staging (`EVIDENCE_CHAIN_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, non-production NODE_ENV). It requires migration registry 0018 as final, SHA-256 matches for prerequisites 0001–0017, a shared MySQL advisory migration lock and recorded SQL checksum for reruns. Do not treat partial DDL as safe to rerun destructively; investigate deviations.

## Unresolved Phase 1AG+ production gates

1. Supplier identity, verified destination/domain ownership, trusted outbound authenticated integration and scoped signed authorization for real PO issuance. Provider dispatch/acknowledgment should use secure, transactional and idempotent workers with independent audit and delivery retry/redrive.
2. Cryptographically authenticated vendor acknowledgment and versioned real supplier-issued order, shipment/delivery documentary evidence, returns/backorders/partial receiving, quality inspection and an authorized legally meaningful goods-receipt note against an **issued** supplier PO.
3. Operational double-entry event/movement inventory ledger, serial ownership, quarantine-to-accepted-stock release authority, strict no-negative-stock check under concurrency, per-site reservations, reconciliation and correction workflows.
4. Inventory/landed-cost valuation, COGS, GST/HSN, accounts payable, authentic supplier invoice matching, payment approvals, plus real browser/warehouse device acceptance.
5. Real isolated Hostinger TLS/proxy staging, privately signed evidence chain, encrypted backup and witnessed restore with measured RTO/RPO, key recovery, security/ops/owner sign-off and final release checklist.

**Release decision: HOLD.** Keep Issue #2 OPEN, Draft PR #1 DRAFT/unmerged, `main` untouched. Production deployment, supplier communication, actual PO issuance, GRN, inventory posting, payments and external verification were **not** executed.
