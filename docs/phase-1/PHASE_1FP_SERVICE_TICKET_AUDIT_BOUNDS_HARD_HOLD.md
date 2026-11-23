# Phase 1FP — Internal service-ticket audit read bounds and controlled acquisition errors (HARD HOLD)

Date: 24 November 2026 IST. Engineering-only improvement to M16's Phase 1FN internal service desk. **No external customer support, technician dispatch, AMC or production authority is established.**

## Identified and bounded risk

The initial internal ticket detail API read the entire `service_ticket_audit_internal` history with no upper bound. Because the internally permitted `TRIAGED_INTERNAL` ↔ `WAITING_INTERNAL` transitions can repeat, a single authorized GET could eventually materialize an unbounded set of audit records and return an oversized payload. Additionally, the two internal ticket mutation routes acquired a MySQL pool connection before entering their transaction catch/finally; a pool acquisition exception could become an unhandled Express 4 async rejection instead of a controlled unavailable response.

## Narrow change

- `GET /api/service-desk/internal-tickets/:id` now reads `ORDER BY version_after DESC LIMIT 101` **only after the owner-scoped ticket existence check**. The server returns the newest 100 entries in chronological order, `historyLimit:100`, and `historyHasMore:true` when there is an older entry. The response never claims a full history when truncated; no new outward data is exposed.
- The pure `boundedInternalTicketHistory` helper rejects unexpectedly oversized input and makes the 100/101 boundary explicit. It does not delete, archive, alter or rewrite the full database audit ledger. Full independently authenticated historical reconstruction and safe pagination remain future work.
- Service ticket CREATE and status-PATCH pool connection acquisition failures now return the same generic 503 unavailable response, before any transaction begins. This avoids unhandled async promise rejection or leaking SQL error details.
- The Internal Service Desk UI indicates the bounded window and warns when older history exists. No customer notifications, customer-accepted closure, external incident creation, technician assignments, remote Windows commands or invoice/stock changes are introduced.
- `tests/fn-service-tickets.test.ts` validates newest-100 cap, chronological ordering, 101st sentinel, empty history and rejection of oversized input. `tests/fn-service-tickets-mysql.integration.ts` checks version chronology and explicit nontruncated 100-entry metadata on a disposable real MySQL ticket. Full-page boundary (>100) is pure-function coverage, not a simulated claim that 101 genuinely accepted customer events exist.

## Limitations and release acceptance

The API does not yet offer authenticated older-history paging, cryptographic audit immutability, independent WORM custody or cross-source event reconciliation. A database admin can still modify histories; internal app audit rows are not independent legal evidence. In particular, Phase 1FO uses synthetic restricted-principal CI for CRM, quotes and internal tickets, but still lacks independently authorized, provisioned TLS staging, DBA-signed installed routine body and complete real-world operator acceptance. Old failed GitHub Actions attempts must stay visible and may only be superseded by separately verified **exact-head completed success** for internal engineering.

M16 remains `SERVER_INTERNAL_HELD` and M01–M30 external acceptance remains OPEN. `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 Draft/unmerged; `main` unchanged; Issue #2 open. No production migration/deploy, official quote/PO/GRN, customer/supplier messages, technician dispatch, stock/finance/tax posting or provider activation.

References: [1FN M16 internal ticket foundation](PHASE_1FN_M16_INTERNAL_SERVICE_TICKETS_HARD_HOLD.md), [1FO principal boundary](PHASE_1FO_TRANSACTIONAL_OWNER_DEFINER_GUARD_CANDIDATE_HARD_HOLD.md), [M01–M30 completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
