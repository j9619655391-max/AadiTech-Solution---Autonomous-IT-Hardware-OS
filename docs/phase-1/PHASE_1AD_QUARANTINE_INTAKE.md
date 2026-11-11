# Phase 1AD — Quarantined inbound observation and internal serial custody

**11 November 2026 · Development branch only. Production release: HOLD.**

## Trust boundary and intentionally limited authority

Phase 1AC produces internal HELD PO snapshots with `dispatch_state=DISABLED`. Such a snapshot **is not a supplier-issued purchase order** and cannot prove real delivery. Phase 1AD therefore implements only **unverified operator observations**, **independent internal quarantine witness**, and **append-only evidence of quarantined custody**, not certified goods-receipt notes (GRNs), sellable/reserved inventory, supplier settlement, financial posting or tax compliance. The backend never sends messages, books receipts into operational stock, reserves goods, authorizes issues or values inventory.

Only the server's existing `crm_products`, registered `inventory_sites`, approved `proc_requests`, immutable `proc_request_items`, reviewer decision and matching `proc_po_holds` provide internal source context. Operator-supplied evidence references require external verification before any real stock integration.

## Migration 0016 and durable controls

New additive, non-destructive `database/migrations/0016_quarantine_intake.sql` defines:
- `inv_inbound_observations`: one immutable inbound observation per HELD PO, original owner's ID, site, independent delivery-document/count ticket refs, payload SHA-256, review state (`AWAITING_WITNESS`, `QUARANTINED_INTERNAL`, `REJECTED_INTERNAL`), recorded/witnessed timestamps.
- `inv_inbound_lines`: per-product exact observed count and explicit `SERIAL` or `LOT` tracking; serial numbers stored as JSON. Unique (observation, product) constraint; immutable for this phase.
- `inv_inbound_request_keys`: transactionally locked (owner, UUID request key) with SHA-256 payload and committed observation ID; exact replay versus changed-payload conflict.
- `inv_inbound_decisions`: one-time immutable reviewer decision and inspection evidence reference/reason. Approval requires explicit physical inspection declaration.
- `inv_quarantine_serials`: uppercase serial registration only on independent quarantine acceptance; DB `UNIQUE(product_id,serial_number)` prevents previously attested duplicate units across observations. A conflict rolls back all custody/decision events.
- `inv_quarantine_custody_events`: append-only `QUARANTINE_WITNESS_ATTESTED` events per accepted line; unique (line,event). **This is internal custody evidence, NOT a physical stock/availability/valuation ledger.** No outbound/negative movement, reservation or release event exists.
- `inv_inbound_audit`: append-only witness/rejection/observation hashes and server actor identity.

## Server authority & API

All endpoints require authenticated role-scoped sessions, no-store caching; all writes additionally need CSRF, enabled privileged MFA policy in production and recent password step-up. No browser-only self-review or stock mutation.

| Owner API | Behavior |
|---|---|
| `GET /api/intake/eligible` | Own internal HELD PO records; explicitly `externalPoIssued:false` |
| `POST /api/intake/observations` | Owner submits `{holdId,deliveryEvidenceRef,physicalCountRef,items}` plus UUID `Idempotency-Key`; 1–25 exact full-quantity PO lines with distinct products and valid serial/lot evidence; internal `AWAITING_WITNESS` only |
| `GET /api/intake/observations`, `GET /api/intake/observations/:id` | Own immutable observation records |
| `GET /api/intake/quarantine-summary` | Aggregated internal quarantined custody and **database-only** reconciliation; returns `availableToSell:null`, `reservedQuantity:null`, `financialValue:null`, `externalReceiptVerified:false` |

| Reviewer API | Behavior |
|---|---|
| `GET /api/intake/review/observations`, `GET .../observations/:id` | Independently review another actor's observation and serial/lot evidence |
| `POST /api/intake/review/observations/:id/witness` | Exact body `{outcome,reason,inspectionEvidenceRef,physicallyInspected}`. Only `ACCEPT_QUARANTINE` or `REJECT_INTERNAL`. Cannot accept without explicit independent physical inspection; locks observation, re-hashes DB evidence, commits audit+decision+serial registry+quarantine events atomically |

### Fail-closed invariants

- Intake creation checks HELD + DISABLED state, approved requisition/independent review, same original owner, matching supplier/site/reviewer IDs, validated Phase 1AC SHA-256 of reconstructed held JSON and every expected item/qty/cost/description snapshot. MySQL JSON may reorder object keys; hash comparison reconstructs Phase 1AC's field order. Partial intake/overcounts, extra SKU, missing SKU or tampered holds return conflicts.
- Incoming payload is strict and finite: 1–25 lines, integer quantity 1–1000 each; `SERIAL` mode requires exactly one unique normalized uppercase serial per unit (6–80 chars) and null lot; `LOT` requires uppercase lot ID (4–80 chars) and zero serials. The canonical idempotency/evidence hash is order-independent across line order by sorting product IDs before hashing.
- One observation per HELD PO. Observations are append-only, cannot be edited or deleted. Invalid/colliding replay cannot reserve a half-finished record because the entire transaction rolls back.
- Independent REVIEWER must not be original owner; one immutable decision per observation. Reviewer rechecks canonical payload SHA-256 using persisted lines and must confirm physical inspection to accept. Serial uniqueness is enforced **by the DB** in the same transaction as all custody events. Rejected observations add no custody or serial records.
- Quarantine summary is **read-only** and detects orphaned/mismatched events and serialized-unit count mismatch. A clean internal DB comparison cannot verify physical goods, real supplier delivery or available stock.
- `/api/intake/receipts`, `/api/intake/reservations` and issue/release/sale/financial endpoints are **not implemented**; unknown API routes return JSON 404. There is no external dispatch, posting to opening counts or stock balance inference.

## Frontend & validation

The OWNER procurement tab includes `InboundObservationWorkspace`, requiring a deliberate HELD selection, existing MySQL PO-line reading, explicit serial/lot and evidence refs, reauthentication and confirmation. REVIEWER restricted dashboard includes `InboundWitnessPanel` with read-only observation detail, exact serial/lot evidence, independent inspection attestation and fail-closed decisions. Legacy procurement UI remains collapsed and marked demo.

`bun run db:migrate:intake` refuses all non-disposable production or unapproved DB targets. Accepted only:
- CI: `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`.
- Explicit isolated TLS staging: `INTAKE_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, non-production NODE_ENV.

Migration lock, prerequisite checksums 0001–0015, exact SQL checksum, rerun idempotence, unknown migration rejection and release-build hash registry must be enforced by CI. A partially applied DDL must be investigated, not destructively reset.

CI tests strict serial/lot/quantity/evidence validators, source hold hash, migration guard and disposable MySQL HTTP/role/CSRF/step-up/idempotency/tamper/duplicate-serial/approval/rejection/reconciliation. All production/release gates remain pending independent validation.

## Remaining blocking Phase 1AE+ work

1. Independent externally authenticated supplier identity and real PO issuance using protected destination, authorization roles, supplier acknowledgment, safe transactional outbox.
2. 3-way matched **issued** PO + accepted delivery + independent QC/receiver; partial deliveries/backorders, disputed or replacement shipments, returns/RMA, custody-chain signatures and physical count witness.
3. **Operational** stock movement and reservation ledger (inbound accepted into owned stock only on verified receipt, no negative balances, transfer/pick/issue/return, serial ownership, separate maker/checker and physical reconciliation).
4. Real stock availability and landed-cost valuation/COGS, GST/HSN tax sign-off, vendor invoicing, payables and payments; no browser-produced revenue/inventory claims.
5. Real Hostinger TLS staging, backup and restore/RPO/RTO, MFA real-device recovery, privacy/security reviews, verified customer/supplier dataset migration and signed release decision.

**Phase 1AD is a controlled quarantine evidence slice, not completion of all inventory workflows. Issue #2 stays OPEN, Draft PR #1 unmerged, `main` unchanged, production release HOLD.**
