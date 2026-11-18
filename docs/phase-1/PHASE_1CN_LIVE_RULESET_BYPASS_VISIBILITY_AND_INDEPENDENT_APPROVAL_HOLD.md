# Phase 1CN — Official live ruleset inventory, bypass-actor visibility and independent approval HARD HOLD

**Date:** 19 November 2026 (India, IST). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Engineering branch:** `chore/phase0-foundation-20261106`. **Governance:** `main` unchanged; PR #1 DRAFT/OPEN/UNMERGED; Issue #2 OPEN.

## Critical external API fact requiring a real source check

GitHub's official [Get a repository ruleset](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#get-a-repository-ruleset) documentation expressly says: to avoid disclosing sensitive data, the `bypass_actors` field is returned **only if the caller has ruleset write access**. The existing GitHub Actions observation uses limited `contents:read` and `pull-requests:read` permissions (no ruleset/administration write). Therefore a missing `bypass_actors` field **is not evidence that no administrator or app can bypass a rule**. The previous Phase 1BY `GET /rules/branches/main` returns the *applied rules*, not all source ruleset configuration, bypass privileges, creation history, effective admin grants or the external human authority to approve them.

Observed starting point at Phase 1CM exact-head GitHub-hosted workflow:
- Authenticated connected GitHub repo: public, personal `User` owner `j9619655391-max`, current owner `admin=true` (being admin does not make a separate Security or Business independent reviewer).
- Actual `main` applied rules: **zero**, official submitted PR reviews: **zero**, independently approved latest-HEAD reviewers: **zero**; requested users/teams: **zero**.
- Real base-`main` `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`: **HTTP 404**. Legacy protection read denied; no applicable branch protection or admin bypass absence verified.
- Phase 1CM `docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` is a structurally reviewed **UNINSTALLED** GitHub REST API proposal. `enforcement=active` inside an unposted file is not a live rule. **Do not claim installed protection based on its presence.**
- No verified real Security+Business reviewer names/mandates, no genuine authorized provider evidence, independent OIDC CI signature, WORM/DR, legal signatory or staging release permission.

## Practical engineering implemented

`scripts/phase1cn-ruleset-bypass-reconciliation.mjs --ci-hold` runs after Phase 1BY and Phase 1CL in the existing **`live-github-governance-hold`** CI job, with **the same existing read-only GitHub token and permissions**. It performs only these externally visible official GET operations:

1. `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/rulesets?per_page=100&page=1&includes_parents=true&targets=branch` (plus only literal page `2` if page 1 has exactly 100 entries).
2. For each **server-listed, bounded, validated positive numeric id**, `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/rulesets/{id}?includes_parents=true`. It refuses lists larger than **12** rulesets, duplicate/invalid IDs, incomplete pagination and malformed detail record. No arbitrary repository name, arbitrary URL or redirect accepted.
3. The observer correlates its real live source with prior Phase 1BY PR/test-merge SHA/current-head and applied-rule summary, Phase 1CL base-branch CODEOWNERS/PR requested-reviewer state, and the Phase 1CM **uninstalled** JSON ruleset proposal (revalidated with its same strict proposal validator).

Limits: bounded JSON GET (128 KiB per response), 6-second per-request deadline, no redirect, fixed GitHub API hostname and source routes, no credential logging. Summary artifacts contain counts, source IDs, status and **whether bypass fields were visible**—never dump raw GitHub token or actor IDs into the report. Actual GitHub response 403/404/429, pagination exhaustion, missing detail or missing bypass field becomes **UNKNOWN / HOLD**, never “no bypass”.

For each matching branch ruleset, the comparison checks that the **observed REST details** (if actually readable) have the exact `main` ref, are active, include denial of delete and force-push, two PR approvals, stale approval dismissal, Code Owner/latest-push approval, resolved review threads, and all eight required job contexts with strict latest-source revalidation. An unexpected or weakened ruleset is recorded as drift. Even an apparently exact match, and even an **observed empty bypass array**, is **not independently authenticated admin inability to change/bypass protections**, current human Security/Business role evidence, or production approval.

**Two layers are deliberately separate:**
- **CI source integrity:** Is this run genuinely bound to the current PR/test-merge and real official GETs, and is the local proposed policy unchanged? Tampering is a CI structural failure.
- **Actual external authority readiness:** Are the rules live, externally verified bypass-free, CODEOWNERS installed on base `main`, and are two consented, authorized non-author Security and Business reviewers both independently approving exact HEAD? Failure or missing data is an actionable **release HOLD**, even when CI's observation job succeeds.

New `tests/phase1cn-ruleset-bypass-reconciliation.test.mjs` contributes **18 adversarial Node groups**: real no-rules list, false exact match with no effective main rules, hidden vs visible bypass, observed bypass actor, disabled/stale/missing approvals, wrong SHA/source custody, 403/404/429, response size/MIME/redirect/URL injection, more than 12 or duplicate IDs, and authenticated reviewer role false-GO. Two regression groups in `tests/phase1bz-actions-pin.test.mjs` narrowly pin the new named source-observation step and the third **read-only** GitHub token expression; unreviewed token/shell substitution remains forbidden.

The unchanged eight-job CI's existing `live-github-governance-hold` uploads three **UNSIGNED** real-source observation files: `phase1by-github-readonly-governance-hold.json`, `phase1cl-live-codeowners-reviewer-onboarding-hold.json`, and `phase1cn-official-ruleset-bypass-reconciliation-hold.json`. Phase 1BV/BW selected-source custody hashes new verifier and tests. No new job, write permission, ruleset POST, CODEOWNERS commit, new reviewer request, real approval, production transaction, external provider call or signing key.

## Concrete external owner / administrator acceptance steps

| Real accountable party | Independent source/action actually necessary | Status |
| --- | --- | --- |
| Authorized GitHub repo admin | Under approved change-control, appoint actual two non-author Security and Business reviewers, verify corporate mandates + consent + MFA, grant genuine explicit write permission, put legitimate CODEOWNERS on **base `main`** | **PENDING** |
| Authorized repository admin plus separate verifier | Review Phase 1CM uninstalled main ruleset JSON, use GitHub-supported installation flow, verify exact required checks and last-push/stale-dismiss/codeowner/no-force-push/no-delete controls, get ruleset bypass-actor list through a genuinely authorized read channel and independently review admin/application exemption configuration | **PENDING** |
| Separate Security + Business reviewers | Authenticate real approved identities and externally signed role mandate, independently inspect latest source, submit **two distinct real latest-HEAD GitHub approvals**; verify resulting review IDs and no self-approval. CODEOWNERS with two names by itself does **not** guarantee both role signoffs | **PENDING** |
| Independent Security | Adjudicate withdrawn Picomatch GHSA/CVE with publisher technical evidence and whole frozen-lock audit; separate source-level technical acceptance from advisory feed's current zero Critical/High result | **PENDING** |
| Approved provider/Legal/Ops | Real eMudhra/RCAI/CCA contract/sandbox and independently signed live CRL/OCSP, MCA/GST authorized corporate signatory verification, offsite WORM/Object Lock retained + denied-delete and DR recovery, signed OIDC workload/witness, Security/Legal/Ops/Owner staging authority | **PENDING** |

Do not perform admin mutations, nominate a GitHub login, request actual reviews, install rulesets, merge the PR or approve production without real corresponding human authorization. All provider secrets, signing private keys and approval credentials must remain in an approved secrets manager, never Git/CI artifact/chat.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. `main` unchanged, Draft PR #1 open and unmerged, Issue #2 open; no live customer/supplier/provider contact, quotes, PO/GRN, finance/tax/stock posting or production deployment.
