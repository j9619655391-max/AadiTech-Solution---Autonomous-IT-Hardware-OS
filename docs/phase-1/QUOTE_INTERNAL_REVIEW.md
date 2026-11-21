# Phase 1G — Internal owner quote review

This milestone introduces an **internal review decision**, not a legally approved quotation or customer release.

- POST `/api/quotes/reviews/:draftId`: owner-authenticated decision bound to exact latest revision number, a written reason, optional explicit below-margin override.
- GET `/api/quotes/reviews/:draftId`: all immutable review decisions and latest effective decision (only when its revision equals the latest draft revision).
- Every decision is append-only; no revision can receive two decisions, and competing decisions are serialized by locking the parent draft.
- Revision 0 is the original quote; each new revision automatically makes the earlier approval *stale*, not transferable.
- Margin is recalculated using the saved snapshot of prices and costs; browser-submitted margin or policy values are ignored.
- Default threshold: `QUOTE_MIN_MARGIN_BPS=1500` (15%). An internal approval below threshold requires an explicit override flag and a written reason of at least 20 characters; rejection always requires a reason.
- **No send, order, inventory reservation, invoice, external provider calls, or third-party approval notifications.**
- Single-owner setup does NOT provide dual control or segregation of duties. Introduce distinct reviewer and author roles, stronger identity verification and audit/notification controls before enabling any commercial release.

Run non-destructive migrations 0001–0006 in order, ending with `bun run db:migrate:quote-reviews`. CI verifies operation with a disposable MySQL instance; production migration, backup/restore and browser end-to-end tests remain outstanding.
