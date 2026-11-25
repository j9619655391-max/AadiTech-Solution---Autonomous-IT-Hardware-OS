# Phase 1FR — M16 snapshot-consistent ticket audit reads and event-chain guard (PRODUCTION HARD HOLD)

Date: 24 November 2026 IST. Development-only change on `chore/phase0-foundation-20261106`. Original Issue #2 and M01–M30 external acceptance gates remain OPEN.

## Defect and threat model

Previous 1FQ detail and keyset-history GETs ran eligibility lookup and audit query as separate `pool.query()` calls. They could run on different MySQL sessions and different committed snapshots. If an authenticated OWNER or another authorized writer committed a ticket transition between reads, the response might claim a newer ticket version/status but return an earlier audit page. History-window checks also enforced ascending version order but not **contiguous numbers, valid transition sequence, genesis, current-state anchor or complete 101st sentinel semantics**. Missing or edited internal audit material could be mislabeled as successful readback.

## Implementation (bounded engineering)

- `readInternalTicketSnapshot()` in `server/serviceDesk/router.ts` checks out **one** MySQL connection, applies `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`, and starts `START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`. Both the owner-scoped ticket row and scoped audit SELECT execute on that same session. It commits only after bounded reads; any SQL, validation or connection error rolls back where possible and releases the connection. No table DML, new routine/definer privilege, migration or protected `auth_users` read is added to these read endpoints.
- Both `GET /api/service-desk/internal-tickets/:id` and `GET /api/service-desk/internal-tickets/:id/history?beforeVersion=N` use this snapshot. Missing or foreign owner/customer provenance returns 404. A cursor beyond `ticket.version + 1` is rejected. Existing `requireOwner`, session checks, source-scoped active CRM provenance, no-store and externalDispatchEnabled:false remain mandatory.
- `verifyInternalTicketAuditWindow()` in `server/serviceDesk/validation.ts` validates version bounds, exact current ticket-version and latest `toStatus` for first-page reads, expected keyset page top `beforeVersion - 1`, contiguous monotonically ascending versions, correct terminal oldest CREATE at version 1, valid `OPEN_INTERNAL → TRIAGED_INTERNAL ↔ WAITING_INTERNAL` and `TRIAGED_INTERNAL → RESOLVED_HELD` transitions, adjacent `fromStatus`/`toStatus` continuity, and complete 101st-sentinel version/state/genesis behavior. Missing, corrupted or implausible application audit records cause generic HTTP 503, not a falsely complete 200 response. Empty page is valid only for `beforeVersion=1`.
- Existing keyset page size stays hard-capped at 100 with the 101st sentinel, zero OFFSET, bounded client rendering and read-only internal history semantics. No customer contact, official repair, SLA, AMC, remote device action or signed audit attestation is enabled.

## Verification

- Adversarial pure unit tests cover missing CREATE, missing latest audit, wrong latest status, cursor beyond ticket anchor, event version gap/duplicate/reordering, invalid transition or `fromStatus`, sentinel gap and sentinel mutation.
- New disposable `aaditech_ci` MySQL integration creates an internal synthetic ticket and uses two independent SQL connections. Inside the read-only consistent snapshot, it reads version 1; another connection commits version 2 and the matching audit event; the snapshot must still read version 1 and audit 1, and a **new** request must see version 2. Synthetic deliberate audit/status/anchor tampering must produce 503 and recover to 200 after restoring the original rows; no production data is touched. Existing 1FQ 103-version keyset test covers multiple history pages.
- Do not claim the change **CI verified** until both exact-source GitHub Push and Draft PR workflows finish COMPLETED/SUCCESS. Preserve intermediate failure logs.

## Important limitations (not independent acceptance)

This validates **internal application ledger consistency** at one database snapshot, not cryptographic authenticity, permanent immutability, non-repudiation, external legally verified customer consent or an independently authorized system-of-record. A privileged DBA could still rewrite both ticket and audit consistently, and older pages across separate requests are not one immutable historical snapshot. Real external signed WORM/DR, least-privileged authenticated staging, independent DBA/Security/Business/Legal approvals, true customer consent, SLA/technician/vendor evidence, provider-authorized eMudhra/CCA/RCAI/MCA trust and live CRL/OCSP are still required. No synthetic fixture is production evidence.

**M16 remains `SERVER_INTERNAL_HELD`. All M01–M30 external acceptance gates remain OPEN.** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`; `main` unchanged, PR #1 Draft/unmerged, Issue #2 open. Do not deploy/migrate production, merge main, contact actual customers/suppliers, activate providers or post stock, financial/tax documents, official quote/PO/GRN or repair status.

Related: [Phase 1FN internal tickets](PHASE_1FN_M16_INTERNAL_SERVICE_TICKETS_HARD_HOLD.md), [1FP first bounded history](PHASE_1FP_SERVICE_TICKET_AUDIT_BOUNDS_HARD_HOLD.md), [1FQ keyset history](PHASE_1FQ_INTERNAL_TICKET_KEYSET_AUDIT_PAGINATION_HARD_HOLD.md), [M01–M30 master](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
