# Phase 1CP — GitHub Actions required-check app pinning and exact workflow check-suite provenance HOLD

**Date:** 19 November 2026 (Asia/Kolkata). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; engineering branch `chore/phase0-foundation-20261106`. `main` **unchanged**; PR #1 **DRAFT/OPEN/UNMERGED**; Issue #2 OPEN. There is **no** released production authority.

## Independently observed genuine GitHub source, not invented provenance

GitHub's [official ruleset documentation](https://docs.github.com/en/rest/repos/rules) permits an integer **`integration_id`** in each required status check. GitHub's [available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) explain that status check names can otherwise be set by several people/integrations with repository write permissions, and selecting an expected GitHub App prevents some status-source substitution.

On the **real GitHub API for previous final Phase 1CO dev HEAD `c9a5fbe9280553f0f29479aed52be1dadc5cf267`**, `GET /commits/{head}/check-runs?per_page=100` returned **16 check runs from TWO suites** on the *same* source commit:

- [GitHub Actions successful #44387631034](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44387631034): suite `120157952500`, **8/8 named jobs completed SUCCESS**, all GitHub `app.id=15368`, `app.slug=github-actions`, and actual required check job `details_url` binding to that exact workflow run/job.
- [Earlier same-head #44387617016](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44387617016): suite `120157914600`, including a **failed** live GitHub governance job and **skipped** source-merge-lineage job (other jobs succeeded). A simple “find a success for each name on the same SHA” search could combine unrelated runs and falsely report a suite green. **Never silently replace a failed/unfinished required check in an exact run with a successful check from an older/later run or different suite.**
- The PR synthetic test-merge checkout SHA `f17ee45fb08ce7eca1dca0f1e85d04dac631a0bf` is **different from the real source head**. GitHub Actions check-runs for these PR workflows are associated with the *source* `head_sha`, while the runner executes the test-merge tree; the source/checkout/base relation is authenticated at the API/local envelope boundary, not by claiming the SHAs are equal.
- This is **GitHub API attribution and local-source custody**, not independent cryptographic signed OIDC/SLSA provenance, external WORM/witness, authenticated corporate signatories or production acceptance.

## Engineering hardening

### 1. Proposed, still **UNINSTALLED** protected-`main` ruleset

Existing `docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` now pins **all eight required contexts** with GitHub Actions **`integration_id: 15368`**. The same proposed `main` ruleset still requires two PR approvals, stale-review dismissal, latest-push approval, Code Owner review, resolved conversations, strict required checks, no force-push/deletion and an empty configured bypass list. Its `enforcement: active` is only a *proposed future REST payload*, not an installed live ruleset or verified admin-bypass exclusion.

`scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs` now rejects any required status with missing/changed app `integration_id`. Actual installed-ruleset matching in `scripts/phase1cn-ruleset-bypass-reconciliation.mjs` independently requires the same app ID. Existing Phase 1CM adversarial suite adds one group denying app ID spoof/missing fields. **No actual ruleset POST, `main` CODEOWNERS commit, admin permission change, PR review request or production write happened**.

### 2. Actual source-bound GitHub App / exact run+suite observation

New `scripts/phase1cp-github-actions-check-app-source.mjs --ci-hold` runs **after Phase 1BY, CL, CN, CO** in the same eight-job `live-github-governance-hold` workflow. It accepts zero user-supplied run IDs, paths, reviewers or write actions. Two fixed official read-only GitHub GETs (max 512 KiB each, 6.5-second request deadline, redirects denied):

1. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/{GITHUB_RUN_ID}` (runner-provided numeric ID, not a user-supplied destination).
2. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/commits/{actual_source_head_sha}/check-runs?per_page=100` (source SHA from the preceding genuine Phase 1BY official GitHub PR observation / workflow run). Unexpected status, invalid head or pagination reaching 100 results is **UNKNOWN** rather than “all eight passed”.

It verifies official run ID, source branch and PR #1 head/base, current PR event and the exact `check_suite_id`, cross-checks the synthetic PR checkout SHA through the actual Phase 1BY custody report, rejects mismatching or duplicate **current-suite** job contexts, requires each observed required check to originate from `app.id=15368` / `app.slug=github-actions`, have the correct source `head_sha`, and link to the **exact current workflow-run/job URL**. All check names must match the eight reviewed contexts; a different suite on the same commit is counted as ignored, never used to make this one green.

**Important timing caveat:** this observer runs *inside* the live workflow. Other jobs may not have started or finished, including this job itself; it will accurately record **missing/pending** checks and `currentExactRunAllEightAppBoundChecksPassed=false` **while running**, even if the overall workflow later completes successfully. Its CI test fails only on structurally tampered sources or unreviewed app/proposal, not on a normal pending job. A final **post-run exact-head GitHub API re-check** is still necessary to prove all eight named checks completed SUCCESS in the selected run. Neither check-run completeness nor a post-run successful suite is independently signed CI workload provenance or a production release vote.

Scoped workflow permissions are now **`contents:read`, `pull-requests:read`, `actions:read`, `checks:read`** exclusively for the already existing `live-github-governance-hold` job. These two *additional READ-only* permissions enable genuine Actions run and check-run queries; root `permissions:contents:read` and all other job boundaries unchanged. Phase 1BZ/1CA immutable-workflow allowlist now explicitly pins these exact job scopes and the one new Github token interpolation in the fixed Phase1CP step. No id-token, admin, contents write, actions write or checks write permissions introduced.

New `tests/phase1cp-github-actions-check-app-source.test.mjs` adds **19 adversarial cases** against app spoofing, duplicate checks, stale/failing second suite, missing/unbounded source, in-progress results, run/head/ref/sha mismatch, wrong API URL, 403/404/429, redirect, malicious check-status content and signed-approval false GO. One Phase1CM ruleset test and **two** Phase1BZ/CA workflow permission/step injection cases are also added. Phase1BV/BW selected-source inventories include the new script and test. Current governance artifact will hold **five UNSIGNED read-only reports**: BY, CL, CN, CO and `phase1cp-github-actions-app-check-source-hold.json`.

## Actually required external human authority

- [ ] Two genuine distinct nonauthor Security and Business reviewers nominated, consented, corporate role/written mandate independently authenticated and technical GitHub write permissions proven; actual latest-HEAD reviews submitted `APPROVED` and checked under Phase1CO's real read-only operator mode.
- [ ] Separately authorized administrator actually installs and verifies base-`main` CODEOWNERS and the now **app-pinned** review/status-check ruleset after approved change-control; independent admin checks effective enforcement and bypass actors with proper privileges. There are still **zero** installed rulesets/reviews and no verified no-bypass authority as of starting this phase.
- [ ] Independent Security technical adjudication of withdrawn Picomatch GHSA/CVE: latest whole-lock audit presently clean but `picomatch@4.0.7` unchanged and no external signed maintainer release/technical verdict accepted.
- [ ] Genuine approved eMudhra/CCA/RCAI provider contract/credentials in **approved secrets manager only**, signed live CRL/OCSP/trust chain/certificate policy, independently verified MCA/GST legal corporate/signatory, signed OIDC CI workload provenance, offsite WORM/Object Lock/denied delete & DR restore/witness proof, and independent Owner/Security/Legal/Ops staging release sign-offs.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 Draft/Open/Unmerged, Issue #2 OPEN, `main` unchanged; no production deploy, actual supplier/customer contact, stock/quote/PO/GRN, tax/finance, provider operations or real evidence fabrication.
