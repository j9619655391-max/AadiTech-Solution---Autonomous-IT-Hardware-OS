# Phase 1D — Live CRM workspace (increment 1)

## Implemented
- New React Live CRM workspace with Customers, Leads and Product Catalog tabs.
- Authenticated paginated GET, POST, PATCH and soft DELETE through the Phase 1C APIs.
- Explicit user-entered verified fields; no generated email, GSTIN, credit limit or stock figures.
- Server-generated IDs, optimistic `expectedVersion` and HTTP 409 conflict surfaces.
- Loading, empty, success and error states. Server confirms writes before success is shown.
- A manual one-click **export** of explicitly stored browser CRM data, without changing it.
- Existing CRM & Lead Hunter UI preserved under **Legacy Demo Workspace** and labelled accordingly.
- Global banner warns that remaining business modules continue to use browser/demo data.

## Migration status
The exported backup is **not imported automatically**. It may include fabricated/demo contacts, old identifiers and stale financial fields. Before import:
1. Review and classify real vs sample records.
2. Map UUIDs and customer/lead relationships, reject malformed/missing values and deduplicate.
3. Preview a dry-run diff and validate per-row errors.
4. Import through an owner-approved, idempotent, auditable server-side transaction/batch mechanism.
5. Verify counts, links, sample records and audit history.
6. Only after owner reconciliation, disable legacy storage for these business objects.

## Remaining work before production
- Real browser E2E on a configured DB and role/CSRF integration.
- Full data reconciliation/import process; no data overwritten.
- React CRM read consistency after auth/session expiry testing.
- Integrate verified products/leads into BOM, quotations, analytics and order workflows rather than mixing sources.
- Protect sensitive code-seeded/demo data from browser bundles.
- Replace unreliable or unverified business confirmations throughout prototype modules.
