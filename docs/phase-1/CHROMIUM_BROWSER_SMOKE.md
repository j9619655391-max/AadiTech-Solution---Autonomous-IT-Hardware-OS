# Phase 1P — Chromium UI smoke in disposable CI

This increment tests the **actual rendered React login and reviewer UI** in Chromium, complementing the pre-existing HTTP/MySQL integration tests. The test is not a production deployment, Hostinger connectivity, hardware-authenticator test or comprehensive accessibility/performance audit.

## What runs

- After migrations and existing MySQL/HTTP smoke, GitHub Actions starts the Vite/Express dev server on **127.0.0.1:3000 only from the test runner's browser client**, and installs pinned Playwright + headless Chromium in the disposable CI job.
- `scripts/browser-smoke.mjs` creates randomly identified synthetic OWNER and REVIEWER accounts with enabled encrypted TOTP credentials in `aaditech_ci` only.
- Browser opens the real UI, verifies password-only login does not create a session, completes the authenticator code step, verifies owner/reviewer UI separation and API access denial, logs out and verifies session revocation for each identity.
- Browser routing rejects non-loopback requests; no real provider/integration interaction is allowed. No credentials/screenshots/traces are uploaded.
- The script requires `BROWSER_E2E_CI=1`, `CRM_TEST_DB=1`, `NODE_ENV=test`, exact `DB_NAME=aaditech_ci` and exact `BROWSER_E2E_BASE_URL=http://127.0.0.1:3000`. It does not run on production/staging databases.
- Playwright is installed **in CI only** at a pinned version, without changing application production dependencies or lockfile. Production build retains its existing toolchain.

## Recovery acceptance workflow

Continue using `scripts/lib/restoreEvidence.ts` for independent RTO/RPO acceptance using verifiable UTC timestamps, checksum match, data reconciliation, key recovery and reviewer signoff. Suggested RTO ≤60 minutes and RPO ≤5 minutes remain *planning objectives only*, never measured outcomes. Actual encrypted backup export, isolated restore, privacy-safe reconciliation and signed evidence **have not occurred**. CI tests synthetic evidence and cannot attest that an operator really restored anything.

## Remaining release gates

Real HTTPS staging with verified CA, real authenticator devices and recovery-code workflow, real backup/restore with key recovery, security review and a documented incident-response signoff are required. Outbox remains `HELD`/`DISABLED`; no external messages, invoices, orders or inventory mutations are authorized. Draft PR and production must remain untouched until explicit release acceptance.
