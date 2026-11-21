# Phase 1CQ — Actual completed-run, exact app-bound GitHub Checks receipt (read-only, UNSIGNED, HARD HOLD)

**Date:** 19 November 2026 (Asia/Kolkata). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`. **`main` unchanged**, PR #1 Draft/Open/Unmerged and Issue #2 OPEN.

## Why a second, finished-run verification step is necessary

Phase 1CP's live read-only GitHub job genuinely correlated the current PR source SHA, GitHub Actions app ID **15368**, exact workflow run ID and check-suite ID. But this job necessarily runs *before* the entire workflow is complete; it observed 8 current-suite checks as **pending** while recording them correctly as **not yet passed**. The actual previous completed final-run check must therefore take place **after** all jobs finish, and must not mix job results from an earlier check suite on the same SHA.

For the real final Phase 1CP development HEAD `c6ae133e48bed4a931fffc22711d7b1a9ab8c25b`, the official GitHub REST API returned **16 checks across two different suites**: successful current run [#44391228447](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44391228447) in suite `120167734015` with eight successful GitHub Actions-app checks, plus a prior failed/skipped suite `120167696390`. The runner checkout was a separate synthetic PR test-merge SHA, not the source HEAD used by the GitHub Checks API. GitHub check-run identity and green status are first-party API observations, **not signed SLSA/OIDC CI attestation, independent Security/Business signoff or production approval**.

## Practical completed-run operator command

New `scripts/phase1cq-postrun-github-check-receipt.mjs` uses the existing Phase 1CP bounded read-only API client and Phase 1CM strict app-pinned, **UNINSTALLED** main-ruleset proposal. It accepts only a numeric workflow run ID:

```bash
# Supply only an approved least-privileged token from a secrets manager.
# GitHub repository PR read, Actions read and Checks read permissions are
# necessary. No GitHub write permissions or private signatory keys needed.
node scripts/phase1cq-postrun-github-check-receipt.mjs --verify-completed-run 44391228447
```

It reads `GITHUB_READ_TOKEN` from the operator environment, not the command line, repo files, PR comments or stdout. The numeric run ID is only a locator for a **fixed** official GitHub GET endpoint. It does not use the GitHub PR author's text or a remote response to change host, path, method, redirect behavior or required check names. The script refuses invocation **inside GitHub Actions** to avoid claiming a running workflow is post-run confirmed.

**Actual fixed API reads:**

1. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/pulls/1` — current PR before observation.
2. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/{numeric_run_id}` — exact workflow metadata.
3. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/commits/{run.head_sha}/check-runs?per_page=100` — all check suites for that **exact source HEAD** (not synthetic test-merge SHA).
4. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/pulls/1` again — detect head/base/merge/update races before accepting the snapshot.

The existing trusted client caps response JSON to 512 KiB, denies redirects, uses exact GitHub API host and fixed GET endpoints, and enforces a 6.5-second deadline per fetch. Missing token, 403/404/rate-limit, malformed response or 100+ result pagination becomes **UNKNOWN/HOLD**, not “all green”. No secrets are printed.

**Exact checks before technical success:**

- PR #1 still Draft/open/unmerged, author `j9619655391-max`, correct development/source repo, base `main` in correct repo, stable HEAD, base, test-merge SHA and updated timestamp before/after reads.
- Workflow run's actual `id` numeric; official `name=Phase 0 baseline`, `workflow_id=408632517`, `path=.github/workflows/ci.yml`, `event=pull_request`, expected source repo/branch, stable current PR HEAD/base, `status=completed`, `conclusion=success`, real `check_suite_id` and `run_attempt`.
- Check response bounded and complete, **eight unique required job names in this exact suite**; rejects missing, duplicated or unexpected suite-local contexts. Every required check must have the same source HEAD, exact selected suite ID, official `app.id=15368`, `app.slug=github-actions`, match `https://github.com/{repo}/actions/runs/{run_id}/job/{check_id}`, and be `status=completed`, `conclusion=success`.
- A success or failure from any *other* suite is recorded as ignored and can **never substitute** for an expected result. Rejects stale workflow, prior HEAD, workflow ID/path spoofing, unknown app, non-success/skipped/neutral conclusion, check-list pagination risk or PR concurrent changes.
- Returns `completedExactEightAppBoundChecksTechnicallyVerified=true` **only for the checked completed run**, plus a local SHA-256 checksum of the unsigned technical observation. Returns **`productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD` unconditionally**. Neither the SHA-256 nor an HTTPS API response is an independent signature, WORM record, externally authenticated workload provenance or authorized nonauthor role certification.

**Adversarial tests:** `tests/phase1cq-postrun-github-check-receipt.test.mjs` has **17** new adversarial Node groups covering multi-suite false success, pending/cancelled runs, PR head/base/race/fork/author mismatch, wrong workflow path/ID/name, missing/duplicate/extra checks, GitHub App and job URL spoofing, failed/neutral/skipped checks, unbounded API response, denied sources and attempts to promote uninstalled ruleset/unsigned receipts. The verifier source and test are now in both Phase 1BV selected build-source custody hashes and Phase 1BW governed vendor-review source lists. The existing **eight CI jobs remain unchanged**, and no extra GitHub permissions, writes, reviewer actions or secrets are added to CI.

## Independent external actions still required

Even when the completed-run technical check succeeds, actual production release requires distinct independently authenticated, consented, nonauthor **Security** and **Business** reviewer approvals for the exact current PR HEAD, verified GitHub write access and corporate mandates; an authorized administrator must really install and independently verify no-bypass effective **base-`main` CODEOWNERS/ruleset** with app-pinned checks; genuine eMudhra/CCA/RCAI provider approval and signed live CRL/OCSP/certificate hierarchy; MCA/GST legal company/signatory evidence; independently signed source-bound CI OIDC/SLSA workload provenance, WORM Object Lock with retention/delete denial/offsite DR recovery/witness, and Owner/Security/Legal/Ops staging acceptances. Withdrawn Picomatch advisory still requires independent Security technical adjudication despite fresh full-lock Bun audit reporting no current Critical/High/Unknown advisories.

**This phase does not install a ruleset, modify `main`, request a review, merge PR #1, close Issue #2, send live provider/supplier/customer messages or deploy.**

`productionReleaseAuthorized=false` • `productionReleaseBlocked=true` • `releaseDecision=HOLD`.
