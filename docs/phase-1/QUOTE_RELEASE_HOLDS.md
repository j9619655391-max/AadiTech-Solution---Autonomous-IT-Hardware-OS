# Phase 1H — Fail-closed quotation release preparation

This implementation is **NOT an outbound-sending pipeline**. There are no provider transports, delivery workers, scheduling, email/WhatsApp/Telegram contacts, or final release APIs.

1. `POST /api/quotes/release-preparations/:id` requires an authenticated owner session + CSRF token and `expectedRevision`.
2. Server locks the original quotation draft and verifies the currently effective `APPROVED_INTERNAL` review for the **same revision**.
3. A canonical, immutable internal snapshot is captured from already-saved MySQL draft/revision rows, not from browser-provided amounts or recipients. A SHA-256 checksum tracks the snapshot.
4. A release-preparation row is inserted with status `HELD` and an outbox-hold event with `DISABLED` dispatch state, atomically. Unique database keys ensure at most one preparation/event per quote revision, even under concurrent requests.
5. `GET /api/quotes/release-preparations/:id` reports the current revision and whether existing held preparations are stale. A revision after preparation automatically makes an old preparation ineligible: the API never treats an older revision as current.
6. A repeat POST for the same quote+revision returns the existing held record; it never schedules delivery.
7. An internal approval is **not independently authorized** because the system has only an OWNER role. The held status cannot be promoted by any endpoint in this increment.

## Explicitly outside scope
- Distinct author/reviewer identity and separation-of-duties enforcement.
- Recipient verification, marketing consent, quote document generation, taxes and quote numbering.
- Queue consumers, retries, dispatch reconciliation or external provider credentials.
- Real commercial approval, inventory reservation, invoicing, order placement, billing or release.

## Guardrails
- No dispatch transition or worker exists in code. The database event type is deliberately named `QUOTE_RELEASE_PREPARATION_HELD` rather than `SEND_QUOTE`.
- Do not create a consumer which changes `DISABLED` to another state without a separate audited security and business review.
- If a network response fails, GET the preparation before retrying. Same revision cannot create another record.
- Data retention, backup, encrypted storage, privacy review, staging restoration and HTTPS end-to-end must be completed before any production deployment.

## Migration
Apply auth, CRM, draft, idempotency, revisions, reviews, then `bun run db:migrate:release-holds`. This is additive/non-destructive and CI uses a disposable MySQL 8 service.
