# Phase 1FQ — M16 owner-scoped keyset pagination of internal ticket audit (PRODUCTION HARD HOLD)

Date: 24 November 2026 IST. Source: `chore/phase0-foundation-20261106` (Draft PR #1); Issue #2 remains the external-acceptance register.

## Addressed internal gap

Phase 1FP bounded the *latest* 100 audit history records, but an authorized operator had no bounded API path to inspect older internal events. That could hide legitimate internal troubleshooting history and encourage unsafe use of unbounded SQL reports. This increment adds limited, authenticated, deterministic pagination. It **does not** provide independent legal evidence, immutable history, customer acceptance, SLA attestation or actual repair.

## Bounded technical implementation

1. `server/serviceDesk/validation.ts` adds `parseInternalTicketHistoryCursor()`: exact `beforeVersion` string only; positive canonical decimal `1..2147483647`. Arrays/duplicate query keys, nested parameters, negative/zero/fractional/oversized values, unexpected `limit`/`offset` are all rejected. No browser-selected unbounded page size or OFFSET.
2. `boundedInternalTicketHistory()` checks returned event version integrity, retains a page of up to 100 in ascending version order, detects the 101st sentinel, and returns `nextBeforeVersion` (the lowest returned version when an earlier page exists) or null. Corrupted, duplicate or reverse-ordered audit versions fail closed.
3. `GET /api/service-desk/internal-tickets/:id/history?beforeVersion=N` remains behind `requireOwner`, source-scoped CRM customer `CREATE` audit provenance, non-deleted customer, and matching internal-ticket owner. Both the eligible ticket lookup and the **actual audit SQL** re-apply this scope; unauthorized tenant/user/ticket history returns 404. Exact keyset SQL uses `a.version_after < ? ORDER BY a.version_after DESC LIMIT 101`. The first detail GET also re-applies actor ownership in its audit SQL instead of relying only on the earlier ticket row lookup.
4. Response is `INTERNAL_HELD`, `externalDispatchEnabled:false`, and bounded `history`, `historyLimit:100`, `historyHasMore`, `nextBeforeVersion`. Historical rows remain stored; no data is deleted, archived or rewritten by pagination.
5. `src/components/LiveServiceDeskWorkspace.tsx` offers **Load older 100 entries** and **Return to latest**; it replaces one displayed window rather than accumulating unbounded history in browser state. It rejects inconsistent mode/ticket ID/out-of-range cursor responses and does not treat a page as independent immutable or full-history proof.
6. Unit and real **disposable** MySQL HTTP tests cover 100/101 boundaries, malformed query parameters, incorrect version ordering, exactly 103 consecutively versioned internal audit entries created via legitimate authenticated status updates, no overlap between pages, 401 anonymous, 403 reviewer, 404 foreign owner and unchanged no-store/disabled dispatch. Synthetic fixtures are strictly `NODE_ENV=test, CRM_TEST_DB=1, DB_NAME=aaditech_ci, DB_SSL=false`.

## Remaining obligations / risks

- No independently signed WORM ledger, secure older-history archival or global retention policy, immutable read snapshot across pages, change-data capture, legal/tenant identity proof or customer-facing incident signoff. These are **application-generated internal audit events only** and mutable by privileged database administrators. Pagination does not prove completeness of external historical evidence.
- The `beforeVersion` keyset excludes concurrent newer records without an OFFSET shift, but older pages are not an externally anchored immutable snapshot. Permission checks are repeated per request and existing role/session middleware remains mandatory.
- All real separate database runtime/auth users, security-definer OWNER-guard install/privileges, live effective-grant graph, approved TLS staging, DBA/Security/Operations signoff, signed provider eMudhra/CCA/RCAI/MCA authority, independently verified live CRL/OCSP, protected `main` and independent reviewers, signed provenance, WORM and DR restore remain unapproved. The related Phase 1FO stored-procedure CI fixture does not confer authority in a real environment.
- M16 remains `SERVER_INTERNAL_HELD`; all original external M01–M30 acceptance gates remain OPEN. Do not claim customer consent, on-site repair, RMA, AMC renewal, contractual SLA or external dispatch from these pages.

**Governance:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Leave PR #1 Draft/unmerged, Issue #2 open and `main` unchanged. Do not deploy/migrate production, issue official quote/PO/GRN, send customers/suppliers, activate providers or post stock/finance/tax.

Related: [Phase 1FN M16 internal tickets](PHASE_1FN_M16_INTERNAL_SERVICE_TICKETS_HARD_HOLD.md), [Phase 1FP first bounded read](PHASE_1FP_SERVICE_TICKET_AUDIT_BOUNDS_HARD_HOLD.md), [M01–M30 completion register](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
