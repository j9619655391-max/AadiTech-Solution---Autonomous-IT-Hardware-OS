# Phase 1Z — Held release-candidate provenance and controlled staging acceptance

**Scope:** Development branch and Draft PR only. Phase 1Z prepares auditable **build-hash inventory** and a safe, manual staging-release checklist. It does not create an approved production release, deploy to Hostinger, migrate production MySQL, send quotations or run real external staging checks.

## CI deliverables

The baseline CI job installs the frozen Bun lock, typechecks, executes unit/security tests, builds the React frontend and Node server, and validates the dependency advisory gate. Only after those gates pass, the `release:candidate` script runs on a **direct push** to the approved development branch in GitHub Actions, with a repository identity check and explicit opt-in `RELEASE_CANDIDATE_CI=1`. The runner's `GITHUB_SHA` must match `git rev-parse HEAD`. Pull-request checks still build and test, but **cannot emit or upload a release candidate** because their checkout may be an ephemeral merge commit.

The script hashes every regular file under `dist/` (including `dist/index.html`, `dist/server.cjs` and generated frontend assets), `package.json`, `bun.lock` and all 21 registered SQL migrations (and rejects any additional unregistered `.sql` migration). Sorted filename/byte-count/SHA-256 entries form a deterministic `artifactSetSha256` fingerprint. Empty/missing build output, missing frontend assets, missing migrations, symbolic links, oversized files and unsupported CI metadata fail closed. No private evidence, environment variables, credentials or customer records are included.

**Artifact:** `held-phase1z-release-candidate` contains only `release-candidate-manifest.json`, an inventory of filenames, sizes and hashes. The actual compiled artifacts are **not** published as a release or attached as a deployable bundle. The manifest is not cryptographically signed; GitHub CI success does not substitute for independently signed software supply-chain provenance. A release-candidate manifest is permitted only for a branch-push SHA, not a pull-request merge SHA; this reduces provenance ambiguity but does **not** authorize promotion or independently attest to build origin.

## Explicit hold states

Every report includes `productionReleaseBlocked:true` and `productionReleaseAuthorized:false`, even if no vulnerable packages are detected. The report also leaves the following **NOT VERIFIED**:

- Independent real TLS certificate and reverse-proxy header inspection on an approved isolated staging hostname/IP inventory
- Operator-witnessed encrypted backup and restore into a **new** isolated `aaditech_staging_*` database, verified MFA key recovery and actual RTO/RPO timings
- Authenticity and independence of security/engineering/operations signers and underlying private evidence
- Staging browser/device MFA acceptance, verified MySQL CA, network isolation and rollback readiness
- Explicit production change authorization and business approval for any external messaging or order workflow

A complete synthetic CI file is **not** sufficient to satisfy operational release gates.

## Manual release-candidate acceptance workflow (NOT EXECUTED)

1. Identify the reviewed **push-event** source SHA (not a PR merge SHA), CI run URLs, dependency advisories, branch protection state and exact hash inventory. Confirm the manifest's `gitCommitSha` is the reviewed source and `artifactSetSha256` matches its file entries. Independent engineer must reconcile build outputs with the intended approved source commit and verify any actual release artifact from that commit.
2. Obtain written scoped authorization for an isolated staging target, exact DNS/IP inventory and TLS/proxy test. Run `staging:https-probe` only with the operator-approved hostname, explicit flags and change ticket; never probe an assumed live endpoint.
3. Independently verify provider TLS CA, direct-listener isolation, forwarded-header overwrite, rate-limit client-IP behavior, real-device MFA and one-time recovery, role/CSRF/session revocation, and security event delivery.
4. Conduct a separately authorized encrypted backup/restore drill into a **fresh disposable** staging database, reconcile data, recover encrypted MFA secrets with documented key escrow and measure RTO/RPO against independently approved objectives.
5. Review **private** evidence using the existing 12-category SHA-256 manifest and staging evidence reviewer. Independently verify witness signatures and actual event authenticity outside the repo.
6. Produce an independent security/operations/owner decision record, rollback steps, staging-only release disposition and limited rollout conditions. No command in this repo promotes a candidate or authorizes production.

## Negative controls and incident rollback

- Never import legacy `database/schema.sql`, drop production tables, reset MFA keys, enable outbound workers, create real users or merge Draft PR as an automatic next step.
- The quote preparation outbox must remain **HELD / DISABLED**; dispatch, invoices, stock movements and orders are not part of this milestone.
- Record release artifact hashes and approved infrastructure state before change; if any control fails, stop without changing production. An authorized rollback restores reviewed application/config artifacts, not destructive schema changes.
- Keep RTO <=60 min / RPO <=5 min as **planning targets** pending witnessed real measurements, not achieved service guarantees.

**Release decision: HOLD.** No approved real Hostinger staging hostname, IPs, private evidence or independently witnessed restore has been provided for this turn.

## Phase 1Z continuation — push-only provenance and migration coverage

- The CI-held manifest step and its upload now run on an exact approved-branch **push event only**, never a `pull_request`, other branch, fork or manual workflow invocation. This must be verified with real workflow conclusions after push.
- A unit-tested context validator rejects mismatched `GITHUB_SHA` / checked-out SHA, unapproved repository and ambiguous PR head information.
- Inventory collection rejects unregistered SQL migration files, rather than silently hashing only the known registry; source migration updates must also update `MIGRATIONS` and relevant tests.
- CI and all source tests provide **synthetic validation only**. Full release authority, production deployment, private signing, witnessed restore, live TLS checks and owner approval remain **HOLD / NOT VERIFIED**.
