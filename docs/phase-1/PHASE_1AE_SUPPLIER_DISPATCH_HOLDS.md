# Phase 1AE — Supplier destination provenance and PO dispatch authorization HOLD

**Date:** 2026-11-11 · **Scope:** development branch only · **Production release: HOLD.**

## Decision boundary

Phase 1AE addresses supplier PO issuance **control preparation**, not actual issuance. No trusted supplier outbound transport, third-party account ownership, verified supplier acknowledgment, bank/finance integration or approved external delivery target exists. Therefore the code **does not issue any external PO**, send an email/WhatsApp message, acknowledge a vendor order or authorize any physical goods receipts or stock movements. An internal reviewer decision creates only a **HELD, DISABLED** outbox record. Phase 1AD quarantine evidence is not converted to stock availability.

Earlier source references remain:
- `crm_products` (MySQL product master);
- `proc_suppliers` and identity attestation (internal only);
- independently approved `proc_requests` and immutable line snapshots;
- `proc_po_holds` containing the original SHA-256-captured `aaditech-internal-po-hold-v1` manifest;
- `inv_inbound_observations` (blocked as dispatch input once an observation exists).

## Additive database migration `0017_supplier_dispatch_holds.sql`

1. `proc_delivery_destinations`: owner proposes one normalized lowercase ASCII email destination per supplier with a source evidence ticket. Initial state `PENDING_INTERNAL`, independent reviewer can set `REVIEWED_INTERNAL` or `REJECTED_INTERNAL`; no updates, sends or automatic supplier-inbox verification. Unique supplier constraint prevents silent recipient substitution. Editing/replacement requires future versioned workflow.
2. `proc_dispatch_preparations`: one owner-submitted, checksum-bound internal dispatch request per HELD PO, prepared only against reviewed supplier and reviewed destination. Records `authorization_evidence_ref`, original hold hash, immutable manifest JSON, SHA-256, original actor, and status `PENDING_INTERNAL` / `APPROVED_INTERNAL` / `REJECTED_INTERNAL`.
3. `proc_dispatch_review_decisions`: exactly one independent REVIEWER decision with written reason, evidence ticket and explicit recipient attestation. Approval is only internal.
4. `proc_dispatch_outbox_holds`: a single immutable hash-bound outbox entry after internal approval, `state='HELD'` and `dispatch_state='DISABLED'` restricted **at the SQL ENUM level**. No recipient message is emitted or attempted, and no ACTIVE/ENABLED state exists.
5. `proc_dispatch_audit`: internal append-only SHA-256 of immutable events (destination proposal/review, PO preparation/approval/rejection) bound to actor and entity.

## API and independent authorization

| Role | API | Security and durable effect |
|---|---|---|
| OWNER | `GET/POST /api/po-dispatch/destinations` | Create one supplier-bound recipient proposal with strict lowercase ASCII email and evidence ticket; remains unverified |
| REVIEWER | `GET /api/po-dispatch/review/destinations`, `POST /api/po-dispatch/review/destinations/:id/decide` | Independent actor, explicit destination evidence, one immutable decision; no external inbox verification |
| OWNER | `GET /api/po-dispatch/holds`, `GET/POST /api/po-dispatch/requests` | Original HELD PO checksum checked, same owner, approved source, reviewed destination matched to supplier, no Phase 1AD inbound observation. Single immutable preparation; exact retry returns existing, changed request conflicts |
| REVIEWER | `GET /api/po-dispatch/review/requests`, `GET .../requests/:id`, `POST .../requests/:id/decide` | Rechecks immutable PO checksum/owner, recipient, manifest SHA, review status and no inbound observation **under transaction lock**. One decision and, for internal approval only, atomic held outbox record |

Mutations require authenticated roles, same-origin CSRF, 5-minute password verification, and privileged MFA policy where enabled. Responses are no-store. Source entities and hashes are checked by MySQL, never trusted from UI. Unknown `send`, `acknowledgments`, `issue`, `goods receipt`, `reservation` routes are JSON 404. No route can change the outbox's SQL-defined DISABLED state. Dangerous or unknown client input is rejected. Duplicate submissions are recognized only if source, immutable destination and authorization evidence yield the same manifest SHA-256; otherwise 409.

**Hash limitation:** SHA-256 detects unexpected storage changes if checked against the recorded canonical payload; it is not a digital signature, nonrepudiation, identity verification or independently validated external document. The approved recipient is never contacted or proved to control the claimed inbox.

## Frontend

The OWNER procurement view now includes `SupplierDispatchOwnerPanel` to propose supplier destination and request a review against a selected HELD PO. The REVIEWER restricted workspace includes `SupplierDispatchReviewerPanel` to inspect recipient provenance and complete independent one-time decisions. Both display explicit no-send warnings, use MySQL authenticated API, require current-password step-up before writes and never claim real PO issuance.

## Migration and verification

`bun run db:migrate:dispatch-holds` applies the additive migration **only** on disposable CI (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicit isolated non-production TLS staging (`DISPATCH_HOLDS_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`). Prerequisite migrations 0001–0016 must have matching SHA-256 checksums. Named migration lock, unknown-migration refusal, checksum-rerun consistency and no destructive reset are enforced.

`tests/dispatch-validation.test.ts`: strict email/evidence/body contract, attestation rules, immutable manifest digest and migration target denials. `tests/dispatch-mysql.integration.ts`: synthetic OWNER/REVIEWER session role isolation, CSRF, step-up, supplier destination independence, held SHA tampering, duplicate/changed retry, rejection/no outbox, approved HELD/DISABLED outbox, inbound-conflicting request refusal, missing send/ack endpoints and zero stock events.

GitHub Actions still mandates actual Chromium MFA/role smoke. Previous Phase 1AD run failed **outside product code** when Ubuntu apt package DNS resolution on hosted runner failed. Phase 1AE replaces only the browser dependency installer with preinstalled runner system Google Chrome; the **real browser smoke remains required and gating**. If the runner lacks Chrome, CI should fail rather than silently skip. Treat CI results as verified only at the exact pushed SHA.

## Remaining release blockers

- Trusted, independently validated supplier contact and KYC, signed electronic PO with versioning, signer authorization, time-bound dispatch enablement under separate change-control, transactional outbox worker with provider authentication/acknowledgment, retries, deduplication and safe incident rollback.
- Real issued PO / vendor acceptance proof, partial/shipment/backorder handling, independent signed GRN and QC, 3-way supplier invoice matching, serial custody chain.
- Operational stock movement/reservation/transfer/return ledger with no-negative-stock invariants, inventory valuation and COGS; only then may `availableToSell` be computed.
- Genuine staging TLS and isolated restore drill with measured RPO/RTO, real MFA device verification, security/ops/owner sign-off, finance/GST/legal verification.

**No production DB migration, supplier delivery, payment, real stock issue or Hostinger deployment was executed by Phase 1AE.** Draft PR #1 remains unmerged, `main` unchanged, Issue #2 remains OPEN.
