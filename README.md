# AadiTech Solution — Autonomous IT Hardware OS

**Status: DEVELOPMENT / RELEASE HOLD. Not production certified.**

This repository is a modular Express + React + MySQL platform for hardware sales, CRM and internal quote review. Phase 1AA removed several fabricated business claims and unsafe browser-only actions, but legacy dashboards and workflows remain demonstration software and should never be represented as authoritative financial, warehouse or customer records.

## What is implemented in the current development branch

- Server-backed role-scoped authentication, CSRF, MFA/recovery, reviewer lifecycle and internal session controls.
- MySQL-backed CRM and internal quotation draft/revision/review with held, **DISABLED** dispatch outbox. A held draft is **not** customer-issued.
- Phase 1AB owner-entered inventory sites and immutable MySQL **opening counts only**. No available-to-sell stock, procurement receipt, reservation, issue or cost-of-goods is asserted.
- Phase 1AC internal MySQL supplier registry, independent identity attestation, owner purchase requisitions, separate reviewer decisions and **HELD** PO snapshots; supplier dispatch is permanently disabled. Neither a real PO nor a receipt is issued.
- Phase 1AD owner-entered **unverified inbound observations**, independent quarantine witness, append-only quarantine custody evidence and serial/lot registry. This is NOT goods receipt, real stock, stock reservation, available-to-sell, valuation or logistics authorization.
- Phase 1AE supplier destination provenance and independent INTERNAL verification, HELD PO dispatch review and immutable, DISABLED outbox preparations. **No external supplier order or acknowledgment has been sent or established.**
- Phase 1AF manual and **UNVERIFIED** supplier acknowledgment claims with offline document checksum, independent internal claim review and full-SKU/serial/lot reconciliation to Phase 1AD quarantine, resulting only in immutable **HELD / stock posting DISABLED** evidence packs. No issued supplier PO, externally authenticated acknowledgment, official GRN or saleable inventory exists.
- Phase 1AG inventory ledger *foundation*, with hard-zero authoritative site/SKU position gates, immutable non-posting stock-release intentions, independent reviewer HELD decision and nonallocating demand plans. SQL enforces zero sellable/reserved/posted units; no real movement, available stock, customer reservation or stock issue is possible.
- Phase 1AH **UNPOSTED** double-entry inventory evidence model: balanced debit/credit pairs by original quarantined SKU, SQL-unique serial candidates marked ownership NOT_ESTABLISHED, explicit supplier/GRN/warehouse authority blockers, and independently reviewed HELD/DISABLED journals. Operational financial or inventory posting, transfer, actual serial title and reservation remain unavailable.
- Hardened HTTPS/proxy production preflight, dependency/security CI, disposable MySQL integration tests and Chromium smoke.
- AI BOM and marketing **drafts only**, requiring provider credentials and human verification. No trustworthy AI business dashboards, autonomous negotiations or customer dispatch.
- Fresh browser starts with no seeded business records. Legacy browser-local demo screens are marked explicitly, destructive "production reset" is blocked, and existing stored records are not silently erased.
- Held release build-hash manifest on a verified **development branch push** only, without deployment authority.

## Local development (isolated only)

Prerequisites: Bun-compatible runtime, Node.js compatible toolchain, and an isolated development MySQL database if exercising server-backed features.

```bash
cp .env.example .env
bun install --frozen-lockfile
bun run lint
bun run test
bun run build
bun run dev
```

Set environment variables explicitly for **non-production** use; do not commit `.env`, keys, token manifests or database exports. The development server defaults to `127.0.0.1:3000` (configurable validated `PORT`). Migration and owner bootstrap scripts require additional isolated DB setup and authorization. Do **not** run any production migration, reset, outbound workflow or network staging probe based on these local instructions.

Disposable MySQL/Chromium integration tests run in GitHub CI; passing local unit tests does not establish live infrastructure health.

## Operational truth boundary

| Surface | Authority |
|---|---|
| Real `/api/auth`, `/api/crm`, `/api/quotes`, `/api/security` | Server + MySQL, still subject to independent staging acceptance |
| Phase 1AB `/api/inventory` | Authenticated owner-entered sites and historical opening-count records ONLY; no live stock availability |
| Phase 1AC `/api/procurement` | Owner/reviewer supplier identity evidence, quote-backed requisitions, immutable decisions and HELD PO hash; no supplier dispatch, goods receipt, reservation or payment |
| Phase 1AD `/api/intake` | Owner-observed inbound count and independent reviewer quarantine evidence; no true GRN, movement authority, available stock, reservations or COGS |
| Phase 1AE `/api/po-dispatch` | Server-backed internal supplier destination evidence, independent PO dispatch-review records, DISABLED held outbox only; no actual sending, acknowledgment, real goods receipt or stock issue |
| Phase 1AF `/api/evidence-chain` | Unverified offline supplier ACK claim, independent internal review and quarantined GRN-reconciliation HOLD; official GRN, stock postings and available-to-sell disabled |
| Phase 1AG `/api/stock-foundation` | Hard-zero stock positions, independent non-posting release review and HELD demand planning; stock release, reservation and movement posting disabled |
| Phase 1AH `/api/journal-foundation` | Immutable balanced UNPOSTED debit/credit evidence journals, independently reviewed HELD outbox and unverified serial candidates; no operational ledger, supplier authority, stock credit or debit |
| Legacy `src/data/mockData.ts`, browser storage and old dashboards | DEMO / BROWSER ONLY; no verified stock, finance, telemetry or approval authority |
| `/api/ai/command` and `/api/ai/negotiate` | Explicitly unavailable until verified backend facts and approval workflow |
| `/api/ai/bom` and `/api/ai/campaign` | Unverified AI drafts; no verified prices, HSN/GST, performance, compatibility or dispatch |
| Release candidate manifest | Build hash inventory only; **productionReleaseAuthorized=false** |

## Engineering and security references

- [Phase 1AA cross-module code audit](docs/security/PHASE_1AA_CODE_AUDIT.md)
- [Phase 1AB MySQL inventory opening-count boundary](docs/phase-1/PHASE_1AB_INVENTORY_OPENING_COUNTS.md)
- [Phase 1AC internal procurement and held PO boundary](docs/phase-1/PHASE_1AC_PROCUREMENT_REVIEW_HOLD.md)
- [Phase 1AD quarantine observation and serial-custody evidence](docs/phase-1/PHASE_1AD_QUARANTINE_INTAKE.md)
- [Phase 1AE supplier destination and PO dispatch HOLD boundary](docs/phase-1/PHASE_1AE_SUPPLIER_DISPATCH_HOLDS.md)
- [Phase 1AF unverified supplier evidence and GRN-reconciliation HOLD](docs/phase-1/PHASE_1AF_SUPPLIER_EVIDENCE_GRN_HOLD.md)
- [Phase 1AG hard-zero stock ledger foundation and release-intent controls](docs/phase-1/PHASE_1AG_ZERO_STOCK_LEDGER_FOUNDATION.md)
- [Phase 1AH balanced unposted journal and serial provenance gate](docs/phase-1/PHASE_1AH_UNPOSTED_DOUBLE_ENTRY_JOURNAL.md)
- [Phase 1Z held release candidate and real staging checklist](docs/phase-1/PHASE_1Z_HELD_RELEASE_CANDIDATE.md)
- [Production deployment guide (hold-gated)](HOSTINGER_DEPLOYMENT_GUIDE.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Remaining release-blocking work (Issue #2)](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/issues/2)

## Release governance

Never deploy from a green screenshot, fabricated fixture or hashed manifest alone. Require independently approved staging host/IP, verified HTTPS/CA, signed evidence, backup/restore with measured objectives, real-device MFA, secure migrations, customer data reconciliation and explicit owner/operations sign-off. Maintain Draft PR and `main` untouched until these gates are met. No quote/customer message, invoice, stock movement, payment or production promotion is authorized by this document.
