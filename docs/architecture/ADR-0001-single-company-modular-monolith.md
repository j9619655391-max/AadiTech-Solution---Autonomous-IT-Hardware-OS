# ADR-0001 — AadiTech single-company modular monolith

Status: Proposed (Phase 0). Date: 2026-11-06.

## Context
The existing React/TypeScript + Express application uses browser localStorage as primary business persistence while a MySQL schema and limited status endpoints exist. The app is for internal AadiTech operations, not SaaS.

## Decision
- Preserve the existing UI and modules while migrating incrementally to versioned, authenticated server APIs.
- Use a single-company modular monolith backed by MySQL with transactional inventory, quotation, order, and payment records.
- Separate durable scheduled/background workers from request handling. Every external effect is idempotent where possible and reconciled after uncertain outcomes.
- Keep all sensitive business validations and approvals server-side; a UI role matrix is not enforcement.
- Three modes: RESEARCH_ONLY, APPROVAL_REQUIRED and POLICY_CONTROLLED_AUTO; global outbound kill switch checked at send time.
- Use Docker Compose for portable deployments; secrets only through protected configuration.
- Distinguish demo data, unconfigured integrations, pending provider acceptance, and confirmed results.

## Rejected
Immediate microservices, a multi-tenant SaaS data model, browser-only production persistence, unrestricted agent database writes.

## Acceptance
Authentication, API contracts, migrations, worker recovery, tests, backup/restore and documented deployment are mandatory before production launch.
