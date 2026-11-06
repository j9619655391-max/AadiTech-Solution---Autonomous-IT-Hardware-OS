# Phase 1E — Live MySQL quotation draft backend

This increment adds **internal drafts only**:
- `GET /api/quotes/drafts` (latest 100 drafts for signed-in owner).
- `POST /api/quotes/drafts` (existing customer, optional lead, 1–40 catalog product IDs and quantities only).
- `GET /api/quotes/drafts/:id` (snapshot lines and totals).

Server-side source of truth: MySQL customer and product records, not the browser BOM or AI output. The server locks referenced rows, validates active records, takes a snapshot of SKU/HSN/price/cost/GST, calculates exact integer-paise totals, creates a DRAFT in one transaction and returns an explicit *not sent/approved* confirmation.

**Never call this a final quotation, accepted order, invoice, automated approval or tax-verified document.** It has no external sending, PDF/invoice numbering, margin exception approvals, stock reservation or tax compliance sign-off.

## Database
Run `bun run db:migrate:auth`, `bun run db:migrate:crm`, then `bun run db:migrate:quotes`. The migration is separate, idempotent and non-destructive, but must be tested on a backup/restored staging database before production.

## Work remaining
- Connect a dedicated real BOM draft UI with explicit customer/product selection.
- Document workflow to show real draft snapshots, taxes as estimates and warnings.
- Idempotency keys for HTTP retry after uncertain network outcomes.
- Multi-owner roles, approval policy, quote numbering, RFQ vendor checks and transactional inventory availability.
- End-to-end HTTPS/MySQL tests and owner launch sign-off.
