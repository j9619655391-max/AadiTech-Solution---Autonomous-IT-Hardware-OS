# Phase 1FM — 20-topic Windows troubleshooting first-response catalog (internal guidance only)

Date: 24 November 2026 IST. Branch `chore/phase0-foundation-20261106`; Draft PR #1 remains unmerged. This is an **in-product knowledge-base increment**, not a remotely managed diagnostics capability, repair automation, customer-facing support portal, ticketing system, service SLA or production deployment approval.

## User-requested coverage — 20 first-response topics

- PC slow, Wi-Fi connected/no internet, Windows Update failure, disk almost full
- Blue screen/stop error, no sound, Bluetooth pairing, printer won't print
- Flickering/black screen, slow boot, suspected virus/malware, Outlook crashes
- Start/taskbar frozen, laptop battery drain, VPN connected/no internet
- Windows Copilot controls, unwanted pre-installed apps, Windows diagnostic/privacy data
- Driver update broke something, Windows 11 right-click menu

The actual guide identifiers, risk cautions and search terms are in `server/troubleshooting/guides.ts`. Each guide has category, issue summary, at least two non-destructive first checks, at least two escalation signals and explicit warnings (e.g. no destructive data deletions, firmware flashing, disabling endpoint protection or unmanaged network-policy changes). Security/injury cases, battery damage and suspected compromise emphasize specialist escalation.

## Implemented surface

- `server/troubleshooting/guides.ts`: deterministic, versioned source list of **exactly 20** Windows 10/11 troubleshooting topics. Input validation rejects malformed, duplicate-array/structured query input, unrecognized categories, control characters and strings over 120 characters. Query matching is local string comparison, not generative AI or arbitrary command evaluation.
- `server/troubleshooting/router.ts`: `GET /api/help/troubleshooting` and `GET /api/help/troubleshooting/:id` only. Both require the existing authenticated OWNER/REVIEWER session, set `Cache-Control: no-store` and return explicit `mode: GUIDANCE_ONLY`, `deviceInspected:false`, `actionsExecuted:false`. Invalid searches return 400; non-existing guide returns 404; no POST/PATCH/DELETE, no MySQL business writes.
- `server.ts`: mounts the protected router; no new public diagnostic route.
- `src/components/WindowsTroubleshootingWorkspace.tsx`: real application search/category filter, topic accordion, safe first checks, escalation criteria and cautions. Uses `authenticatedFetch` with session handling and abort cancellation. No client-side pretending to detect device health, no background scanner or auto-fix action.
- `src/App.tsx` and `src/components/Header.tsx`: **Windows Troubleshooting** navigation tab separate from legacy Finance/AMC/Service Tickets view. The tab distinctly labels that guides are not customer tickets, operator findings or repair claims.
- `tests/fm-troubleshooting.test.ts`: exact 20 ID coverage, safe non-command instructions, deterministic filtering, category/query abuse, unauthorized HTTP denial, no mutating router handlers and UI/source wiring checks.
- `tests/crm-mysql.integration.ts`: real disposable `aaditech_ci` OWNER/REVIEWER sessions obtain the catalog over Express HTTP, test search/filter/404/400/anonymous access and deny POST; `mode` flags remain false. Already included in existing `bun run test:mysql` CI path.
- 1BV source build inventory and 1BW review-input manifest include the new server, UI and test paths, in addition to the already tracked CI/main server inputs.

## Scope and security limits

This is **not** M16 AMC/service ticket implementation. No customer record matching, consent or tenant authorization, work order, inventory reservations, service-level timers, technician assignment, RMA/warranty validation, ticket attachments, evidence uploads, telemetry, endpoint agent, Windows command invocation, remote PC access, repair action, disk cleanup, Windows Update rollback, registry edits or automatic notifications. Guides are general checklists, may not fit every Windows version and should not override vendor or organizational policy. No new Windows administrator privileges requested.

The existing restricted runtime/auth SQL architecture still requires actual independently provisioned account separation and real staging functional acceptance (Phase 1FL). No change here attempts to override staging `HOLD`.

## Acceptance and test evidence policy

The branch's exact final GitHub source SHA must have both push and Draft PR workflows **COMPLETED/SUCCESS** before unit, TypeScript, bundle, real MySQL and custody checks can be reported as green. CI synthetic/loopback tests cannot certify a field device repair or real technician/customer consent. Any failed prior commit remains visible and is not counted as success.

**Unresolved:** M16 server-authoritative customer-scoped ticket DB schema, RBAC, SLA contract approval, audited ticket transitions, tenant/consent boundaries, support agent identity, incident evidence retention, malware escalation playbooks, Windows installer signing and actual supported Windows installations. M01–M30 legal/business/provider/security/DR acceptance remains open.

**PRODUCTION HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 Draft/unmerged; `main` unchanged; Issue #2 OPEN. No production deployment/migrations, endpoint control, customer contact, official quote/PO/GRN, stock/finance/tax posting, provider activation or support ticket dispatch.

Related: [M01–M30 master completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md), [hold acceptance ledger](../completion/REMAINING_M01_M30_ACCEPTANCE_LEDGER.json), [Phase 1FL account candidate](PHASE_1FL_AUTH_RUNTIME_CREDENTIAL_SPLIT_CANDIDATE_HARD_HOLD.md).
