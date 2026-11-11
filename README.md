# AadiTech Solution — Autonomous IT Hardware OS

**Status: DEVELOPMENT / RELEASE HOLD. Not production certified.**

This repository is a modular Express + React + MySQL platform for hardware sales, CRM and internal quote review. Phase 1AA removed several fabricated business claims and unsafe browser-only actions, but legacy dashboards and workflows remain demonstration software and should never be represented as authoritative financial, warehouse or customer records.

## What is implemented in the current development branch

- Server-backed role-scoped authentication, CSRF, MFA/recovery, reviewer lifecycle and internal session controls.
- MySQL-backed CRM and internal quotation draft/revision/review with held, **DISABLED** dispatch outbox. A held draft is **not** customer-issued.
- Phase 1AB owner-entered inventory sites and immutable MySQL **opening counts only**. No available-to-sell stock, procurement receipt, reservation, issue or cost-of-goods is asserted.
- Hardened HTTPS/proxy production preflight, dependency/security CI, disposable MySQL integration tests and Chromium smoke.
- AI BOM and marketing **drafts only**, requiring provider credentials and human verification. No trustworthy AI business dashboards, autonomous negotiations or customer dispatch.
- Fresh browser starts with no seeded business records. Legacy browser-local demo screens are marked explicitly, destructive "production reset" is blocked, and existing stored records are not silently erased.
- Held release build-hash manifest on a verified **development branch push** only, without deployment authority.

## Local development (isolated only)

Prerequisites: Bun-compatible runtime, Node.js compatible toolchain, and an isolated development MySQL database if exercising server-backed features.

```bash
cp .env.example .env
bun install --frozen-lockfile
bun run lint
bun run test
bun run build
bun run dev
```

Set environment variables explicitly for **non-production** use; do not commit `.env`, keys, token manifests or database exports. The development server defaults to `127.0.0.1:3000` (configurable validated `PORT`). Migration and owner bootstrap scripts require additional isolated DB setup and authorization. Do **not** run any production migration, reset, outbound workflow or network staging probe based on these local instructions.

Disposable MySQL/Chromium integration tests run in GitHub CI; passing local unit tests does not establish live infrastructure health.

## Operational truth boundary

| Surface | Authority |
|---|---|
| Real `/api/auth`, `/api/crm`, `/api/quotes`, `/api/security` | Server + MySQL, still subject to independent staging acceptance |
| Phase 1AB `/api/inventory` | Authenticated owner-entered sites and historical opening-count records ONLY; no live stock availability |
| Legacy `src/data/mockData.ts`, browser storage and old dashboards | DEMO / BROWSER ONLY; no verified stock, finance, telemetry or approval authority |
| `/api/ai/command` and `/api/ai/negotiate` | Explicitly unavailable until verified backend facts and approval workflow |
| `/api/ai/bom` and `/api/ai/campaign` | Unverified AI drafts; no verified prices, HSN/GST, performance, compatibility or dispatch |
| Release candidate manifest | Build hash inventory only; **productionReleaseAuthorized=false** |

## Engineering and security references

- [Phase 1AA cross-module code audit](docs/security/PHASE_1AA_CODE_AUDIT.md)
- [Phase 1AB MySQL inventory opening-count boundary](docs/phase-1/PHASE_1AB_INVENTORY_OPENING_COUNTS.md)
- [Phase 1Z held release candidate and real staging checklist](docs/phase-1/PHASE_1Z_HELD_RELEASE_CANDIDATE.md)
- [Production deployment guide (hold-gated)](HOSTINGER_DEPLOYMENT_GUIDE.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Remaining release-blocking work (Issue #2)](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/issues/2)

## Release governance

Never deploy from a green screenshot, fabricated fixture or hashed manifest alone. Require independently approved staging host/IP, verified HTTPS/CA, signed evidence, backup/restore with measured objectives, real-device MFA, secure migrations, customer data reconciliation and explicit owner/operations sign-off. Maintain Draft PR and `main` untouched until these gates are met. No quote/customer message, invoice, stock movement, payment or production promotion is authorized by this document.
