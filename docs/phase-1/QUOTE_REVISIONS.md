# Phase 1F Part 2 — Internal draft revision history and margin review

This increment adds **append-only quote revisions**, not live customer approvals.

- `GET /api/quotes/drafts/:id/revisions` returns revision history for the authenticated owner.
- `POST /api/quotes/drafts/:id/revisions` accepts `expectedRevision`, a nonempty reason and the **original snapshot product IDs with revised quantities**.
- Product unit cost, sell price, HSN and GST are read from the saved draft snapshot, not browser values or potentially changed catalog data.
- The base draft is revision zero. Every POST appends revision 1, 2, etc.; no earlier draft price or row is overwritten.
- Server calculates exact integer-paise totals, gross-margin basis points, and MARGIN_REVIEW_REQUIRED when below `QUOTE_MIN_MARGIN_BPS` (default 1500 = 15%).
- A required expectedRevision and transactional row lock reject competing edits with HTTP 409.
- **Review status is advisory only.** No approval endpoint, sending, order, invoice or stock reservation is enabled.

Revision POST is **not idempotent** by request key; after a network error, retrieve the revision list before retrying. Production policy configuration and separated decision-makers remain to be designed and tested.

Database bootstrap order: migrate auth, CRM, quote drafts, quote idempotency, then `bun run db:migrate:quote-revisions`. Never run the legacy destructive schema on live data.

No production migration, tenant roles, host deployment or browser E2E is implied by CI success.
