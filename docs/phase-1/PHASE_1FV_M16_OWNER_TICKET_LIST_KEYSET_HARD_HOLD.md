# Phase 1FV — M16 OWNER-scoped internal ticket list keyset pagination (HARD HOLD)

Date: 24 November 2026 IST. Development-only changes on `chore/phase0-foundation-20261106` in open Draft PR #1; Issue #2 tracks all unverified independent release gates.

## Gap closed

M16 ticket *audit history* was paged in 1FQ, but the top-level ticket index was still `ORDER BY created_at DESC,id DESC LIMIT 100` with **no way for an authorized owner to inspect the 101st or older ticket**. This hides legitimate internal records after the first 100 and makes bounded GUI review incomplete. This increment adds a strictly bounded keyset cursor, not external operations.

## Server and UI implementation

- `GET /api/service-desk/internal-tickets` without query continues returning newest 100 owner-scoped internal tickets. It now returns `limit:100`, `hasMore`, `nextBeforeCreatedAt`, `nextBeforeId` alongside existing `mode:'INTERNAL_HELD'` and `externalDispatchEnabled:false`. Keyset pages use **both** `beforeCreatedAt` and `beforeId` as an exact pair, never raw SQL identifiers or an arbitrary `limit`/`offset`.
- `parseInternalTicketListCursor()` rejects partial, duplicate/array, nested, unexpected or malformed cursor fields, invalid calendar/times, non-UUID ticket IDs and timezone-dependent timestamp formats. `beforeCreatedAt` is the database's canonical `YYYY-MM-DD HH:MM:SS.ffffff` textual representation obtained from `DATE_FORMAT(t.created_at,...)`; it does not derive from local/browser timezone. `beforeId` is a valid ticket UUID.
- Owner/creator-provenance SQL is re-applied **on every page**: `t.owner_user_id=?`, non-deleted CRM customer, original `crm_audit_events` customer CREATE actor equal to that ticket OWNER. The strict seek condition `(t.created_at < ? OR (t.created_at = ? AND t.id < ?))` respects a stable `ORDER BY t.created_at DESC,t.id DESC`, including equal timestamp ties. The SQL fetch is `LIMIT 101`; the 101st sentinel sets `hasMore` while returned rows remain at most 100. `boundedInternalTicketList()` checks every row has a correctly ordered UUID+canonical timestamp, enforcing exclusive cursor progress. No unbounded `OFFSET`, no full table export, no database migration or mutation.
- The response retains **1FU full-field legacy credential masking** for subject/description, with `subjectRedacted` and `descriptionRedacted` flags. No stored ticket/audit rows are rewritten. Existing `requireOwner`, `Cache-Control:no-store`, provenance and CRUD scope remain.
- M16 workspace offers **Load older 100 tickets** / **Return to latest tickets**. It replaces the current list page rather than indefinitely accumulating sensitive ticket records in browser memory. The API response has an explicit bounded page contract. Status mutations, the 1FR per-ticket audit snapshot and 1FS unsigned fingerprint remain held-only and unchanged.

## Tests and non-claims

- Unit tests cover 100/101 result boundary, same-timestamp UUID tie breaking, non-decreasing or duplicate cursor denial, invalid date/array/duplicate query pollution and fixed owner-scoped SQL source contract.
- Real **disposable** MySQL HTTP tests create 102 additional synthetic tickets via authenticated owner POST with version-one CREATE audit records. They verify more than 100 tickets across multiple pages, no overlap/gap, exact sorted timestamps/UUID tie-break, 401/403 actor denials, absence of foreign OWNER tickets, unverified consent, disabled dispatch, no-store and rejected partial/oversized/malicious cursor parameters. Synthetic test fixtures remain `NODE_ENV=test`, `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `DB_SSL=false`. None are real customer service records.
- A keyset reduces duplicates under concurrent insertion but does **not** establish a global immutable multi-request snapshot. Older rows modified or deleted between page requests may change the result. It does not prove full legal audit completeness or signed external custody.
- Mark integrated engineering VERIFIED only when **both push and Draft-PR CI workflows** report `COMPLETED/SUCCESS` against the exact latest dev commit. Do not rewrite failed interim CI evidence as green.

## External production blockers unchanged

M16 remains `SERVER_INTERNAL_HELD`; no original customer consent, real technician/AMC/SLA authorization, actual hardware repair, customer communications, legal/Business/Security/DBA approval, independently provisioned TLS staging, signed immutable WORM/DR or live authorized eMudhra/CCA/RCAI/MCA certificate chain and CRL/OCSP. Synthetic application ticket records do not convey those rights. All other M01–M30 externally accepted modules remain OPEN.

**No release promotion:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep `main` unchanged, PR #1 Draft/unmerged and Issue #2 open. No production deployment/migration, real customer/supplier sends, official quotes/PO/GRN, tax/finance/stock posting, external-provider activation or remote Windows execution.

Related: [Phase 1FQ audit history pages](PHASE_1FQ_INTERNAL_TICKET_KEYSET_AUDIT_PAGINATION_HARD_HOLD.md), [Phase 1FU masking](PHASE_1FU_M16_LEGACY_SECRET_READ_MASKING_HARD_HOLD.md), [master completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
