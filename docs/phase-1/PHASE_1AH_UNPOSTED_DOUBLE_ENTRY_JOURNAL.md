# Phase 1AH — UNPOSTED Double-Entry Evidence Journals, Serial Provenance Candidates & Stock Authority Gates

**2026-11-12 · Development branch only · CI disposable MySQL or separately approved isolated TLS staging · Production release: HOLD.**

## Executive release boundary

This phase creates a double-entry **EVIDENCE PROPOSAL**, not a financial journal, inventory ledger posting or proof of physical stock transfer. Supplier purchase orders in 1AC/1AE are internally approved but NEVER SENT. 1AF supplier acknowledgment references are **operator claims, not authenticated vendor receipts**. A 1AF GRN-reconciliation approval is HELD INTERNAL and not an official GRN. 1AG stock release is HELD and hard-zero SQL CHECK constraints prevent any available, reserved, picked or posted quantity from becoming nonzero.

The proposed QUARANTINE_EVIDENCE → RELEASE_CANDIDATE_EVIDENCE leg pair models how a future warehouse posting would be **reviewed**, not how goods have moved or been owned. No official goods receipt, certified supplier source, warehouse release, saleable-stock recognition, stock issue/debit, customer allocation, financial valuation, invoice or payment is created.

## Additive schema 0020_unposted_double_entry_journals.sql (7 InnoDB tables)

| Table | Invariant |
|---|---|
| inv_unposted_journal_headers | One immutable source-bound proposed journal per 1AG REVIEWED_HELD release intent; release digest, site/owner, canonical manifest JSON/SHA-256; PENDING_INTERNAL, REVIEWED_HELD or REJECTED_INTERNAL, posting_state DISABLED only |
| inv_unposted_journal_legs | Exactly two canonical evidence legs per original quarantined SKU: CREDIT QUARANTINE_EVIDENCE and DEBIT RELEASE_CANDIDATE_EVIDENCE, identical quantity/site/lot/serial list and per-leg SHA-256; SQL posting_state DISABLED only |
| inv_unposted_serial_candidates | One candidate row per original 1AD observed SERIAL identity, unique (product_id,serial_number) across the system; source lineage, provenance_state UNVERIFIED and ownership_state NOT_ESTABLISHED **at SQL enum level**. Not title/ownership inventory |
| inv_unposted_source_blockers | One immutable hard-denial record per journal: external PO verified NO, supplier acknowledgment authenticated NO, official GRN verified NO, warehouse release authorized NO, stock credit DISABLED, all SQL enum-only |
| inv_unposted_journal_reviews | One irreversible independent review per journal; signed-in reviewer, written reason, non-sensitive evidence ticket, balancingInspected attestation and REVIEWED_HELD or REJECTED_INTERNAL |
| inv_unposted_journal_holds | One immutable hash-bound decision/outbox for internally approved journal, state HELD and posting_state DISABLED only, with stockPosted false and availableToSell null |
| inv_unposted_journal_audit | Append-only actor/decision event digests for creation, internal HELD decision and rejection |

The 1AG inv_stock_position_gates hard-zero CHECK constraint remains unchanged. There is intentionally no authoritative inventory source or operational stock ledger, and no migration from an unverified receipt into sellable inventory.

## Canonical model, balancing and identity verification

1. An OWNER may propose a journal only from their own independently reviewed 1AG release intention with a valid 1AG HELD/DISABLED review outbox. The transaction rechecks 1AC held purchase snapshot, 1AE never-sent supplier outbox, 1AF independently reviewed manual ACK claim and internal GRN HELD record, independently witnessed 1AD SKU/serial/lot quarantine custody and the 1AG complete immutable release-intent lines.
2. Every SKU produces exactly two legs with the same positive integer observed quantity, site, product UUID, tracking mode, lot or sorted serial identities. Canonical order is product UUID then account. Exactly one CREDIT QUARANTINE_EVIDENCE and one DEBIT RELEASE_CANDIDATE_EVIDENCE are required for each SKU. Sum of CREDIT evidence quantities equals sum of DEBIT evidence quantities **per SKU**. This is a modeling proof only, not a goods transfer.
3. A canonical v1 manifest includes original release SHA-256, all nested legs, explicit postingState DISABLED, journalPosted false, externalPoVerified false, authenticatedAcknowledgment false, officialGrnVerified false, warehouseReleaseAuthorized false and availableToSell null. Header manifest and each canonical leg are SHA-256 checked. Nested JSON comparison is recursive, object-member-order tolerant and array-order exact; changed serials, duplicate SKUs, extra legs or altered quantity fail.
4. Every serialized candidate must match the source observation serial registry exactly, with database-enforced (product,serial) uniqueness. Two journal sources cannot claim the same product serial as separate candidates. This uniqueness is a **duplication guard on unverified evidence**, never legal title or physical possession proof.
5. The transaction inserts the SOURCE BLOCKER row with every upstream external attestation hard-coded NO, plus exactly-zero stock gate rechecks for every SKU. No UI, worker, API or migration in this phase can turn those NO/DISABLED states into YES/ENABLED.
6. Independent REVIEWER fetches the complete frozen source and all legs, revalidates every upstream digest and serial identity, requires explicit inspected balancing declaration, and records one REVIEWED_HELD or REJECTED_INTERNAL decision. A positive internal decision produces only one HELD/DISABLED snapshot; a rejection produces none.
7. An OWNER's explicitly modeled /debit-attempt validates a reviewed HELD journal and exact product, locks its site/SKU hard-zero gate, then rejects every positive stock debit with a 409 no-negative-stock conflict. No transfer, warehouse receipt, serial title posting, allocation or movement-posting route exists (404). Existing 1AG demand plans remain nonallocating.

Hashes bind internally captured snapshots; they are NOT independent signed supplier documents, trusted warehouse signatures, tamper-proof records against privileged DB edits or legally meaningful proof of title. Supplier and warehouse identity and independent cryptographic evidence sources must be added **before** activation of a separate real ledger.

## API and security

All journal routes use no-store responses, verified login and explicit role scoping. Mutations additionally require CSRF, recent password step-up and configured privileged MFA. Source verification and decisions occur in MySQL transactions with row locks; unique release-to-journal and one-review/one-HELD indices enforce single capture. Identical retry is idempotent when all original hashes and source lines match; different bytes or source tampering cause conflict.

| Actor | Route | Effect |
|---|---|---|
| OWNER | GET /api/journal-foundation/eligible | Own 1AG reviewed HELD release intentions, no sellable-stock implication |
| OWNER | POST /api/journal-foundation/journals {releaseIntentId} | Prepare complete SHA-bound 2-leg-per-SKU UNPOSTED evidence journal and unverified serial candidates, with hard-coded external blockers |
| OWNER | GET /api/journal-foundation/journals, /authority | Own journals and explicit NO/false external trust, stock posting and ownership fields |
| OWNER | POST /api/journal-foundation/debit-attempt {journalId,productId,quantity} | Review-source and zero-stock transaction-lock checks; positive debit always conflict 409; never writes stock |
| REVIEWER | GET /api/journal-foundation/review/journals, /journals/:id | Other owner journal proposal and every balanced leg, serial and checksum |
| REVIEWER | POST /api/journal-foundation/review/journals/:id/decide {decision,reason,evidenceRef,balancingInspected} | Independent one-shot REVIEWED_HELD / REJECTED_INTERNAL, approval never posts; requires inspected flag for positive HELD |

## UI

JournalFoundationOwnerPanel allows password re-verification, 1AG HELD release selection and an UNPOSTED evidence proposal, displays internal status and explicit supplier/GRN/serial/stock authority blockers. JournalFoundationReviewerPanel provides every debit/credit evidence leg (including serial candidate identities and original source SHA), re-verification, written reason, evidence reference, checked balancing attestation and one-time HELD/reject decision. Both show **NO** operational authority.

## Guarded migration, CI and preflight

Migration script scripts/migrate-journal-foundation.ts requires either disposable CI (CRM_TEST_DB=1, DB_NAME=aaditech_ci, NODE_ENV=test) or explicitly approved nonproduction TLS staging (JOURNAL_FOUNDATION_MIGRATION_APPROVED=YES, STAGING_DISPOSABLE_CONFIRMED=YES, DB_NAME=aaditech_staging_*, DB_SSL=true). It validates previous 19 SQL migration SHA-256 records, refuses unknown migration IDs, obtains shared MySQL advisory lock, applies only additive SQL 0020 and verifies checksum-identical idempotent reruns. Never run against production or a live warehouse.

**Previous-phase registry repair:** Phase 1AG files and staging-preflight checks had been pushed, but the previous CI registry was accidentally left at 18 migrations. Phase 1AH fixes it to 20 and fixes the Phase 1AG migration guard to use its stable prerequisite index 19. This is necessary before disposable CI can apply both 0019 and 0020; older Phase 1AG workflows still queued at the time work began.

Unit tests validate strict bodies, two exact balanced leg patterns, per-SKU double-entry conservation, serial uniqueness/lot correctness, nested checksum and tamper refusal, no verified external statuses, and production migration denial.

tests/journal-foundation-mysql.integration.ts runs real disposable aaditech_ci MySQL with synthetic owner/reviewer sessions and complete internal 1AC/1AD/1AE/1AF/1AG source fixtures. It checks role/CSRF/password step-up denial, corrupted upstream HELD hash, concurrent idempotent journal requests, exact pair+quantities, two serial candidates, SQL-level refusal to set verified GRN, serial ownership established or posting ENABLED, cross-journal duplicate serial prevention, altered leg quantity and serial candidate review refusal, one-time independent positive HELD review, negative rejection without outbox, explicit debit 409 and absent posting/transfer endpoints.

GitHub workflows apply migration 0020, rerun it for checksum/idempotency, run all prior MySQL tests, mandatory Chrome MFA/role browser smoke, deployment configuration gate, dependency baseline, build, release-candidate hash checks and read-only isolated preflight. scripts/lib/stagingPreflight.ts flags missing blocker/hold/decision, unsafe external authority flags, unbalanced or missing journal legs, candidate states, candidate count mismatch and any nonzero site/SKU position. The checksum registry now includes 20 SQL files; release candidate integrity includes that schema. **Only actual CI success on final SHA counts as a passing validation.**

## Production gates for Phase 1AI and beyond

1. Independently verified supplier KYC, destination/domain control, signed and idempotent PO dispatch with authentic supplier receipt, vendor acknowledgment and returns/change handling.
2. Authenticated issued warehouse GRN with independently checked packing/shipping, partial receipt, SKU/serial/lot QC, chain of custody, financial invoice control, legal evidence retention and authorized physical stock release.
3. New change-controlled **operational** stock journal migration with immutable posted financial/quantity ledger, signed trusted GRN credits, site/product/serial ownership, effective-date and correction/reversal policy, global multi-site transaction isolation and deterministic lock ordering, atomic no-negative debit/reservation against verified available balances, idempotency, stocktake variance workflow, strict ACL and reconciling assertions. Preserve current 1AG/1AH zero-only controls until independently audited replacement is explicitly authorized.
4. Valuation, FIFO/weighted-average/COGS policy, landed costs, AP and GST, customer order/reservation fulfillment, automated security tests, TLS proxy staging, encrypted backup/restore rehearsal, measured RTO/RPO, supplier/ops/legal approval and owner release sign-off.

**Production release HOLD.** Issue #2 OPEN, Draft PR #1 open/draft/unmerged, main unchanged. No production migration, Hostinger deploy, real supplier contact, official GRN, warehouse stock posting, live stock reservation or payment is performed.