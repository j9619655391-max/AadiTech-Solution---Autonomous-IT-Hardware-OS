# Phase 1F — Quotation create request idempotency

## Implemented
- The POST `/api/quotes/drafts` endpoint requires a UUID `Idempotency-Key` request header.
- Owner + key are unique in MySQL. A transactional reservation is inserted before catalog lookups, and the mapping to the final draft is committed atomically with the draft/items.
- The same owner/key/payload returns the already-created draft (HTTP 200), without recalculating it after catalog changes.
- Reusing a key with a different canonical request returns HTTP 409.
- Each draft has an unambiguous internal reference `ADQ-<full UUID>` (not a legally issued quotation or invoice number).
- The React client holds a key for the current form across network failures. It resets the key after an intentional form change or confirmed success.
- This is single-create idempotency, not quote revision history or business approval.

## Follow-up safety requirements
- Never send, approve, place orders or reserve stock from this endpoint.
- Add draft revision entities and change history, server-side margin approval policies, and explicit owner approval workflows in subsequent increments.
- Retain idempotency records for the operational retry horizon, with a documented archiving policy (never delete until associated draft is reconciled).
- Production MySQL migrations, backup/restore, HTTPS, real browser E2E and security review remain pending.
