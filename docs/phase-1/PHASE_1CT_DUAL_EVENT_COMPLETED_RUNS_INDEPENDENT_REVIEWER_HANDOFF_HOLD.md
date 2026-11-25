# Phase 1CT — Exact completed push/PR dual-event reconciliation and independent governance handoff (HARD HOLD)

**Date:** 19 November 2026 IST  
**Repo:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Branch:** `chore/phase0-foundation-20261106`  
**Immutable state:** PR #1 Draft/open/unmerged, main unchanged, Issue #2 OPEN, `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Why this phase exists

Phase 1CQ/CR checked completed **PR-only** successful GitHub Actions checks/jobs. Phase 1CS corrected actual **push-only** governance source context. A green PR suite cannot be used to cover a failed push suite; conversely, a correctly skipped PR-only lineage job on a push must not be treated as a bypass of mandatory governance. Both actual workflow events require **separately completed and source-matched** first-party evidence.

The new `scripts/phase1ct-dual-event-postrun-governance.mjs` proves *only* exact technical source identity and cross-API job conclusions for a specific pair of **completed** GitHub workflow runs. It must never sign, attest, authorize, merge, deploy, enroll identities or mutate GitHub resources.

## Human operator command, approved read-only token only

Run only after both target GitHub workflows have completed:

    node scripts/phase1ct-dual-event-postrun-governance.mjs --verify-dual-runs PUSH_RUN_ID PR_RUN_ID

Load `GITHUB_READ_TOKEN` from an approved operator secrets manager with only necessary read permissions to the repo, PR, Checks and Actions APIs. Do not paste tokens in chat, GitHub comments, source code, CLI argument strings, environment dumps or artifacts. The command refuses `GITHUB_ACTIONS=true` and rejects nonpositive, ambiguous or nonnumeric run IDs.

The strict existing Phase 1CP HTTP client permits only fixed official `api.github.com` GET routes, refuses redirects, and limits each JSON response to 512 KiB and 6.5 seconds. All reads are sequential in this order:

1. `GET /repos/<repo>/pulls/1` — current source, base, author, Draft state and merge SHA.
2. `GET /repos/<repo>/git/ref/heads/chore/phase0-foundation-20261106` — current authoritative branch commit ref.
3. `GET /repos/<repo>/actions/runs/PUSH_RUN_ID` — *completed successful* genuine push run.
4. `GET /repos/<repo>/actions/runs/PR_RUN_ID` — *completed successful* genuine pull_request run.
5. `GET /repos/<repo>/commits/CURRENT_SOURCE_HEAD/check-runs?per_page=100` — all check suites for exact current source.
6. `GET /repos/<repo>/actions/runs/PUSH_RUN_ID/jobs?per_page=100&filter=latest`.
7. `GET /repos/<repo>/actions/runs/PR_RUN_ID/jobs?per_page=100&filter=latest`.
8. `GET /repos/<repo>/pulls/1` — repeat after all checks/jobs to reject any PR/merge/source race.

The checker never substitutes a prior green commit, another check suite or another attempt. It demands both runs share the current source HEAD and PR base; have different positive numeric IDs and distinct suites; exactly eight unique required app-ID `15368` checks and matching latest-attempt Actions jobs per suite; matching job names, IDs, SHA, numeric run IDs, app identity, immutable workflow name/path/ID, exact API+browser URLs, and terminal conclusions.

**PR expected:** all eight required jobs `completed/success` including the synthetic test-merge lineage control.

**Push expected:** the same seven other jobs `completed/success`, *especially* `live-github-governance-hold`; the eighth `source-merge-lineage-hold` must be `completed/skipped`, and only there. Any other skipped, neutral, pending, cancelled or failed job is a HARD HOLD; a non-skipped push lineage job is also rejected. Distinct job IDs are mandatory across both suites. Missing/403/unreadable/paginated results, source races and duplicate/unknown contexts fail closed.

## External independent governance acceptance remains blocked

The receipt's success field is a narrow **UNSIGNED read-only technical observation**, **NOT** an authorization of production. A local SHA-256 digest is merely an integrity checksum of locally observed metadata, not GitHub-certified SLSA/OIDC or an off-platform signed record.

At the 19 November 2026 review, the actual GitHub APIs report **zero submitted PR reviews** and **zero installed rulesets**; no effective `main` `.github/CODEOWNERS` was returned. The GitHub read-only view also cannot independently prove all possible ruleset bypass actors. This must remain **NOT VERIFIED**, even if a future two-event technical receipt passes.

A real authorized Owner/Security/Business/Legal/Ops handoff requires, in order:

- **Mandate and authority:** documented corporate appointment of separate nonauthor Security and Business reviewers; independently authenticated corporate/legal signatories and out-of-band key custody. No applicant-authored reviewer names or synthetic self-signatures.
- **Protected base branch:** approved admin installation and independent read-after-write of an active exact-`main`, no-admin-bypass ruleset; main CODEOWNERS with effective owner enforcement; two distinct genuine latest-HEAD reviews; explicit no-bypass visibility and app-pinned required status checks (GitHub Actions App ID 15368). Review-requested, PR-comment, proposed JSON or empty API source does not count.
- **External signers:** actual signed workload/OIDC/SLSA statement with verified issuer/audience/subject/nonce, Rekor/witness consistency as applicable, authentic key/source trust and expiry/revocation; off-platform immutable retention with denied delete, restore drill and independently measured RTO/RPO. A local Actions artifact or self-signed digest is not proof.
- **Provider and legal evidence:** approved eMudhra agreement/credentials via secret manager, authenticated RCAI/CCA issuing chain/CPS, signed live CRL/OCSP with replay/freshness protection, independently verified MCA/GST corporate identity and signatory authority.
- **Independent acceptance:** staged end-to-end security assessment with named Security, Operations, Legal and Owner signatures, test evidence and rollback decision. No live supplier/customer communication, quote/PO/GRN/stock/finance posting, secret enrollment, merge or deployment beforehand.

None of these steps is executable from fixture-based CI or an assistant-authored document. They require authorized external actors and evidence that this repository does not currently possess.

## Local tests and CI evidence

New `tests/phase1ct-dual-event-postrun-governance.test.mjs` has 16 focused Node adversarial groups for the matching pair, suite/attempt ID swaps, missing/extra/duplicate Checks or Jobs, source/PR races, push skip substitution, denied data, fixed API call order, missing token and no synthetic release GO. Phase 1BV and BW input custody includes the exact script and test. The *existing eight* workflow jobs, review permissions, workflow event triggers and vulnerability rules are unchanged.

Only report a Phase 1CT hosted test result after verifying a new final source HEAD in **both** actual GitHub Actions push and PR workflow runs. Past Phase 1CS runs (push `44405969840`, PR `44405979015`) are historical and do **not** attest Phase 1CT code.

**Never conflate:** `completedTwoEventTechnicalReceiptVerified` is not `productionReleaseAuthorized`. Release remains **HARD HOLD**.
