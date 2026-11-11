# Phase 1AA — cross-module code-truth audit and remediation register

**Date:** 2026-11-11
**Branch:** `chore/phase0-foundation-20261106`
**Scope:** static repository/code-path audit, tests, typecheck, build and disposable CI MySQL where available.
**Decision:** **RELEASE HOLD**. No claims of production certification, real external approvals or a complete penetration test.

## Verified code-path fixes (CI validation required for latest head)

| Severity | Finding | Remediation |
|---|---|---|
| CRITICAL | AI business command returned fabricated sales, revenue, inventory, order and approval facts | `/api/ai/command` returns HTTP 501 without verified server data |
| CRITICAL | Client-supplied prices produced autonomous negotiation acceptance/Telegram claim | `/api/ai/negotiate` returns HTTP 501; UI never creates approval card |
| CRITICAL | Local Telegram approval marked quote APPROVED, fabricated immutable audit and stock/orders | Blocked browser-local mutation and sent truthful no-action result |
| HIGH | AI BOM used preset equipment/prices/HSN and marked hardware checks PASS | Strict draft schema, zero unverified monetary/tax fields, compatibility FLAGGED, quote button disabled on missing verified fields |
| HIGH | Campaign copy and analytics included fake conversion/pipeline and claimed dispatch | Draft-only, `NOT_MEASURED`, no sending; UI disables dispatch action |
| HIGH | Incomplete AI provider requests fell back to bogus success | Explicit 400/502/503 errors, bounded input and response schema |
| HIGH | Fresh browser auto-loaded large demo catalog, leads, stock and transactions as live | 32 first-load business collection fallbacks now empty; stored user data preserved |
| HIGH | Local "reset into production" could wipe local data and fabricate production approval | Reset throws with no side effects, mode forced TESTING, UI button disabled |
| HIGH | Unverified default company banking/tax identifiers appeared like facts | Fresh profile identifiers blank; existing owner-stored values preserved |
| MEDIUM | Demo import had no independent overwrite acknowledgement | Explicit confirm action; backend storage helper demands confirmation token |
| MEDIUM | Browser quote could be shared as official commercial WhatsApp order | Disabled local sharing; labels changed to preview |
| MEDIUM | Campaign launcher claimed messages sent and agents activated | Browser message now discloses no dispatch |
| MEDIUM | Runtime hard-coded port and development bind 0.0.0.0 | Validated `PORT`, loopback default, test coverage |
| MEDIUM | DB connection details exposed raw exception in status response | Generic browser-safe error |
| MEDIUM | Production candidate hashes could include ephemeral PR merge SHA | Prior Phase 1Z fix restricts candidate artifact to exact branch push and rejects unregistered SQL migrations |

## Module-by-module production gaps (OPEN, not silently marked fixed)

| Module | Current authority | Required completion gate |
|---|---|---|
| Auth, MFA, staff review | Server-backed MySQL; CI simulated/staging only | Independent real TLS/CA/MFA/restore test, approved roles and production controls |
| CRM | Server-backed API exists, legacy demo also present | Data migration, reconciliation, access review and isolated staging E2E |
| Quotations/reviews | Durable drafts and held release-preparation outbox | Governed owner-reviewed issuance with verified prices, tax and real operational sign-off |
| Inventory, procurement, supplier quotes | Browser-local demo portions | Server-authoritative stock, ledger, idempotency, actual supplier contracts |
| Sales orders, GST/invoices, payments | Browser-local or non-integrated previews | Real tax and financial authority, approved integration, audit and reconciliation |
| ITSM, AMC, service, field operations | Unverified browser-local previews | Durable tickets/asset/service lifecycle, SLA and access-control tests |
| Marketing/WhatsApp/Telegram | Draft and preview only | Verified opt-in, official connector, idempotent dispatch, delivery receipts and opt-out |
| Autonomous agents, forecasts, analytics | Static fixtures in legacy components | Measured event sources, jobs, monitoring, provenance, uncertainty and real telemetry |
| Hosting/deployment | CI and local development branch | Approved staging DNS/IP/TLS, network isolation, DB trust, private evidence and real backup/restore |
| Backup/restore | Browser JSON export and synthetic CI rehearsal | Encrypted authoritative MySQL backup with witnessed isolated restore and measured RPO/RTO |

## Outstanding unverified dependencies

- Real staging hostname/IP approval, HTTPS proxy inspection, independent security evidence, MySQL TLS CA, real backup restoration and verified MFA key recovery.
- Actual supplier pricing, stock, tax applicability and operating policies; human approvals for external communications and orders.
- Full security threat modeling / adversarial testing of every legacy component, production workloads and target Hostinger plan.
- The old `database/schema.sql` is not a valid production migration pathway. Use additive checksum migrations with verified backups.
- Existing browser-local records may contain demo data from older versions. They are preserved, not silently converted to authoritative data. Manual reconciliation/export is required.
- A static source audit and green CI **cannot** establish the absence of all defects or complete production readiness.

## Executed and required evidence

- New unit tests: `tests/ai-safety.test.ts`, `tests/ai-business-truth.test.ts`, `tests/browser-data-integrity.test.ts`.
- Existing integration gates: `bun run lint`, `bun run test`, `bun run build`, CI MySQL migrations / review / MFA / browser smoke.
- Release candidate manifest remains `productionReleaseAuthorized:false`; no production deployment or customer dispatch occurred.

**Next:** prioritize authoritative per-module server migration over adding more simulated UI. Request independent real staging and operator sign-offs before leaving HOLD.
