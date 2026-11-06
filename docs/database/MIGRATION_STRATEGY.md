# Database Migration & Legacy Storage Plan (Design Only)

## Rules
- **Never run** the existing `database/schema.sql` against live data; it has `DROP TABLE` statements and placeholder seed values.
- Create sequential, versioned, forward-only migrations for the new schema; do not edit applied migrations.
- Take a verified backup and record current schema version before deploying.
- Protect sensitive fields; no real customer data in demo seed files.
- The existing `storageService.ts` is a legacy transitional source, not production authority.

## Suggested migration phases
1. Inventory all TypeScript business types and storage keys, assign stable database IDs and normalized reference tables.
2. Design owner/employee accounts, roles and sessions (server-side, secure password setup).
3. Introduce `schema_migrations` metadata and transaction-safe migration runner with backups, locking and repeatability.
4. Add company, customer, lead, product and supplier core tables plus constraints and indexes.
5. Create import tool for **explicitly exported** legacy JSON; validate payload versions, duplicates, foreign references, PII, dates and currency values. Offer dry-run report and rollback plan.
6. Migrate quotations, sales orders, POs, stock movements, serial tracking, approvals and payments in dependency order.
7. Integrate frontend API clients; preserve current data in read-only/export mode until owner verifies reconciliation.
8. Cut over per module behind owner-controlled feature flags, verify multi-user consistency and eliminate localStorage as authoritative source.

## Accounting and stock invariants
- Currency stored as fixed-precision decimals or integer paise, never floating point.
- One serialized asset cannot be allocated to two live orders.
- Every inventory movement has a source document and actor.
- Quotation cost and tax policies are versioned and snapshot on approval.
- Invoice and payment records are immutable after posting, with compensating corrections rather than silent overwrite.
- Business dates and source time zones are preserved; reports use explicitly configured timezone.

## Required migration acceptance
- Empty DB bootstrap passes.
- Rerun is idempotent and non-destructive.
- Failure leaves consistent schema and retains verified backup.
- Import dry run reports duplicates and invalid source records.
- Restored backup reproduces order, customer, serial, and audit record counts.
- Concurrent stock allocation transaction test passes.
- Unauthorized API access is denied.
