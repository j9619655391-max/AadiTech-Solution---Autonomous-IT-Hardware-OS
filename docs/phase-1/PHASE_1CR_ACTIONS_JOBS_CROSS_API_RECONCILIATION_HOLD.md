# Phase 1CR — Completed GitHub Checks / Actions Jobs cross-API reconciliation (UNSIGNED HARD HOLD)

**Date:** 19 November 2026 IST. **Repository:** j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS. **Engineering branch:** chore/phase0-foundation-20261106. PR #1 remains Draft/unmerged, Issue #2 open, main unchanged and production release blocked.

## Precise problem and observed first-party source shape

Phase 1CQ inspects official GitHub Check Runs and confirms eight successes in the completed selected suite; this does **not** independently reconcile matching GitHub **Actions Jobs** records. An app-bound completed check with a correct-looking URL is not proof that the job run attempt, execution ID, source SHA and completion conclusion also match.

On previous completed first-party GitHub run [44395467981](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44395467981), REST GET /actions/runs/44395467981/jobs?per_page=100 returned exactly eight success jobs. Each returned id, name, run_id, run_attempt, head_sha, status, conclusion, workflow_name, url, check_run_url and html_url, making exact correlation possible. This observation precedes Phase 1CR and does **not** prove that the new code passed hosted tests.

## Read-only operator command

Run:

    node scripts/phase1cr-actions-jobs-reconciliation.mjs --verify-run-jobs NUMERIC_RUN_ID

Only **after the workflow has finished**. Load a narrowly scoped GITHUB_READ_TOKEN from an approved operator secrets manager; never paste it into chat, command arguments, a PR, a tracked file, or logs. The tool rejects GitHub Actions execution to avoid certifying itself while running.

The five exact official GitHub API GETs occur in this order:

1. GET /pulls/1 — current PR before observation.
2. GET /actions/runs/{numeric_run_id} — exact completed workflow.
3. GET /commits/{run.head_sha}/check-runs?per_page=100 — selected current source HEAD.
4. GET /actions/runs/{numeric_run_id}/jobs?per_page=100&filter=latest — latest-attempt Jobs API (not another run).
5. GET /pulls/1 — final PR observation *after* checking both API families.

The existing CP client strictly fixes the official GitHub host and GET routes, rejects redirects, and limits JSON to 512 KiB with 6.5-second deadlines. The existing CQ assessor checks Draft/current-head/base/author/repo/merge/update time stability, exact successful app ID and selected suite. CR then requires **eight and only eight** Actions jobs with the same IDs as those eight CQ check runs; names, numeric run ID, run attempt, source HEAD, workflow name, API job and check-run URLs, browser job URL, completed status and success conclusion must all match. Duplicate, extra, missing, stale, failed and skipped records, pagination risk and API denials are fail-closed. A rerun whose jobs have mixed run-attempt IDs is held rather than falsely promoted.

## Independent evidence still NOT supplied

The result is an **unsigned local technical observation**, not an externally signed workload/SLSA/OIDC provenance, signed check archive, installed code-owner/main ruleset, independently appointed Security and Business reviewer evidence, authorized MCA/eMudhra/CCA certificate trust, real encrypted Object Lock/DR/restore or approved staging. A successful CR observation can never be a production release authorization.

Thirteen local adversarial Node tests cover valid same-run linking, ID/attempt/SHA mismatch, status, forged URLs, unknown and duplicate Jobs, report races, API errors and no-token denial. Phase 1BV/BW selected-source custody inventories hash the new source and test files. This adds **no GitHub job, workflow event or write permission**. Hosted push/PR CI results on the final pushed source HEAD must be verified separately and are not claimed until observed.

**Immutable release flags:** productionReleaseAuthorized=false, productionReleaseBlocked=true, releaseDecision=HOLD. Do not deploy, merge into main, send customer/supplier messages, issue live quotes, post stock/finance/tax or enroll real credentials.
