# Phase 1CS — Push/PR event-scoped GitHub source custody (UNSIGNED HARD HOLD)

**Date:** 19 November 2026 IST. **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; development branch `chore/phase0-foundation-20261106`. **State:** PR #1 Draft/unmerged, Issue #2 OPEN, main unchanged, production release HARD HOLD.

## Reproduced event mismatch and correction

On prior source `f76fa515571247fd116c4f66a8352f219318362a`, GitHub-hosted PR run [44401170726](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44401170726) completed **8/8 SUCCESS**. Contemporaneous [push run 44401156474](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44401156474) completed FAILURE specifically because the live governance job required a PR-only synthetic merge ref for a genuine `push` event. That failure remains a true historical failure; do not relabel it green.

Phase 1CS **does not skip the live governance job**. All eight original jobs, read-only GitHub permissions, triggers, and the UNINSTALLED proposed main required-check names remain. Existing source-bound BY/CL/CN/CO/CP steps execute only on `pull_request`; the new CS step executes only on `push`. Each event has an appropriate mandatory source-custody validation step, with separate unsigned artifacts and event guards. No `continue-on-error`, special push exception or bypass to a release decision is introduced.

## Push-only source check and constraints

`node scripts/phase1cs-push-head-governance.mjs --ci-hold` is an **in-run**, GET-only technical verifier and accepts only an exact GitHub Actions push job context on `chore/phase0-foundation-20261106`. It reads the official API, in order:

1. `GET /repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/pulls/1` — current Draft/open/unmerged PR before inspection.
2. `GET /repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/git/ref/heads/chore/phase0-foundation-20261106` — exact development ref and commit object.
3. `GET /repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/{GITHUB_RUN_ID}` — exact current, not previously completed, push workflow.
4. `GET /repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/pulls/1` — PR source/merge SHA/base/updated_at consistency recheck.

The verifier requires the actual `GITHUB_SHA` to equal official branch ref, PR HEAD and the current Actions run `head_sha`, the expected runner event/ref/job/repository, author and base-main identity, stable PR before and after reads, bound run ID, workflow ID `408632517`, path `.github/workflows/ci.yml`, `Phase 0 baseline` name, a real positive attempt/check suite, and an attached PR #1 with the same source/base. For transient API denial, missing data, refs moved by another push, any identity divergence or malformed run it **fails closed**. This is intentionally stricter than a mere `push` event condition.

The existing Phase 1CP API client now admits **only one new literal** official Git ref GET. Its 6.5-second timeout, streamed 512-KiB maximum, redirect denial, no-cache and official hostname restriction remain intact. Token scope stays `contents:read`, `pull-requests:read`, `actions:read`, `checks:read`; no write/OIDC privileges. Phase 1BZ/CA pins every new step guard and the new artifact receipt path, and source-custody BV/BW inventories cover the new verifier and tests. Adversarial tests cover ref/PR/run mismatch, event confusion, races, denied source, invalid token and path injection.

## Authority boundaries and acceptance

An in-run CS report does **not** demonstrate completed check success, independent signature, Github branch protection or external governance approval. The run must complete before reporting actual push and PR job conclusions; selected check suites must not be combined across attempts. CS findings are always `externallySigned=false`, `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

Independent signed SLSA/OIDC, named nonauthor Security/Business mandates, actual main CODEOWNERS/ruleset admin enforcement, genuine CCA/RCAI/eMudhra/MCA signed/authorized evidence, off-platform immutable WORM/DR and independent staging signoffs remain unresolved. No merge, live supplier/customer/provider effects, quote/stock/finance postings, credential enrollment or production deployment are authorized.

## Initial hosted Phase 1CS CI failure and exact-count fixture repair

First Phase 1CS development commit `92ff1c877648f5507b44072c2bc609f180b6298e` triggered push run [44404916623](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44404916623) and PR run [44404926737](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44404926737). **Both completed FAILURE**: baseline had seven failed tests among 570 JS tests and build-input-provenance rejected a stale exact 20-use Phase 1CC custody count after one more SHA-pinned action was added. The follow-up correction pins the new exact count to **21** (not a lower bound) and updates the five read-only token fixture and anchored event-guard adversarial edits. This does not waive security, authorization or production restrictions. Future CI results are valid only for their own final exact HEAD.
