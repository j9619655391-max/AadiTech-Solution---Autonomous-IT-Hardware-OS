# Phase 1C — MySQL CRM master-data API (backend-only)

## Scope
New non-destructive tables: `crm_customers`, `crm_leads`, `crm_products`, and `crm_audit_events`.
A versioned migration is provided; legacy `database/schema.sql` is destructive and MUST NOT be used on real data.

All routes under `/api/crm` require an authenticated OWNER session; writes also require `x-csrf-token`.

| Method | Path | Meaning |
|---|---|---|
| GET | /api/crm/customers, /leads, /products | Paginated listing, query: page=1&limit=25 (max 100) |
| GET | /api/crm/:entity/:uuid | Read a single record |
| POST | /api/crm/:entity | Create server-generated UUID record |
| PATCH | /api/crm/:entity/:uuid | Partial update, body includes expectedVersion |
| DELETE | /api/crm/:entity/:uuid | Soft-delete, If-Match header contains integer record version |

Use exact whitelisted business fields as defined in `server/crm/validation.ts`; unknown fields are rejected. Money values are DECIMAL strings (example: `"1234.50"`), never floats. IDs and audit actors are assigned by server. Successful updates advance `version` and conflicting updates return HTTP 409. Soft-deleted records are excluded from reads and retained in the audit log.

## Commands
1. Configure MySQL in a protected environment.
2. `bun run db:migrate:auth` (one-time predecessor).
3. `bun run db:migrate:crm`.
4. `bun run owner:bootstrap` if owner was not already provisioned.
5. Log in through browser and test the API with valid cookie/CSRF header.

## Deliberate exclusions
- The old frontend still loads leads/customers/products from `localStorage`; no automatic live cut-over or upload has happened.
- Legacy data import must have dry-run validation and owner approval before migration.
- Customer financial balances and product stock MUST be calculated from future ledger modules; no arbitrary write of those fields is permitted.
- No supplier, order, inventory or revenue endpoints included here.
- API field shapes currently differ from the legacy UI's aggregate types. Do not interpret missing financial/stock fields as zero.
- Running CI without an actual MySQL server validates code but not SQL execution, locking, audit atomicity or backup/restore. A real disposable MySQL integration suite is required before production.
- Product pricing and tax fields are master-data values, not tax or pricing compliance verification.
