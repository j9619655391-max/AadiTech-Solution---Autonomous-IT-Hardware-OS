# Phase 1D increment 2 — Manual legacy CRM record reconciliation

## What has been delivered
- The Live MySQL CRM workspace now accepts a **previously exported legacy JSON backup** for local, read-only review.
- Strict versioned envelope, JSON structure, maximum 2 MB file and 300 record limits.
- Field allowlist, required fields, source ID and within-file duplicate detection; a scan of live MySQL records for existing matching email or SKU (up to 2,000 per entity).
- Explicit warnings for placeholder email addresses and obvious demo-like records. Records with warnings cannot proceed via the one-record review action.
- A human must open each warning-free record in an editable form, inspect/correct details, explicitly check confirmation, then click Save to MySQL.
- Before each such create, the UI rechecks existing database records for matching email/SKU. Server validation and audit logging remain authoritative.
- The original browser backup and localStorage remain untouched. No silent mass import, overwrite or deletion.

## Trust and limitations
This is **a supervised one-record-at-a-time intake workflow, not an automated migration tool**.
- Client-side duplicate scans are not race-safe. Customer/lead email is not unique in the CRM schema; an API-side transactional deduplication/import registry is still required for robust idempotent bulk imports.
- Demo classifiers are heuristics, not proof that any record is real.
- Old IDs are *not* retained in new CRM records, and cross-module references remain unmigrated. Review the originating record in the backup before approving.
- Values such as customer credit limits, outstanding payments, total orders, stock, margins and related financial metrics are intentionally excluded.
- Import runs in browser memory; filenames/JSON contents are not sent to the server for preview, but each explicitly approved record is submitted through the normal authenticated CRM create endpoint.
- Large datasets and concurrent edits require a server-side staging/reconciliation workflow.
- Production MySQL schema migration, secure owner provisioning and browser E2E tests remain outstanding.

## Acceptance
1. Load a correctly exported file; review error and warning counts.
2. Confirm duplicate emails/SKUs cannot proceed automatically.
3. Approve a single genuine record; ensure it is persisted with server-assigned UUID and audit event.
4. Reject or correct missing fields. Never fabricate email addresses, GSTIN or inventory.
5. Keep browser backup until owners independently reconcile all records.

Do not merge or deploy as a production data migration feature until full reconciliation and live-host tests are completed.
