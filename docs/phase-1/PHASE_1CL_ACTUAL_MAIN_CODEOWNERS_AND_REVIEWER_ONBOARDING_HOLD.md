# Phase 1CL — Actual GitHub main CODEOWNERS, requested reviewers and real Security/Business onboarding HARD HOLD

**Date:** 18 November 2026 (Asia/Kolkata).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Protected base:** `main` (must remain unchanged).  
**Workflow:** Draft PR #1 OPEN/UNMERGED; blocker Issue #2 OPEN.

## Verified current blockers from *real GitHub sources*, not fixture claims

At the start of Phase 1CL:
- Live connector `get_pr_info` confirmed author `j9619655391-max`, PR #1 Draft/OPEN/UNMERGED, with no submitted independent reviewer approvals in the official pull-request review list (`list_pull_request_reviews`: **0 reviews**, review threads **0**). A read-only PR result is not itself proof of a Security/business employee's corporate authorization.
- Previous Phase 1CK final-HEAD hosted GitHub Actions `live-github-governance-hold` **actually observed** PR/reviews/applied branch rules: official `pulls/1/reviews` endpoint **read**, **0 submitted reviews / 0 independent latest-head approvals**; `rules/branches/main` endpoint **read**, **0 applicable rules**; legacy `branches/main/protection` endpoint **access_denied**. Zero observed rules + denied legacy access must not be described as independently enforced required PR reviews, protected `main` or no-admin-bypass.
- Direct official connector reads on the **base branch `main`** returned 404 for `.github/CODEOWNERS`, `CODEOWNERS`, and `docs/CODEOWNERS`. The same three paths were absent in the development branch. A 404 is conservatively `absent_or_hidden` in an automated observer rather than asserting an authenticated administrator-installed policy.
- The final Phase 1CK whole-lock `bun audit --json` returned **0 Critical / 0 High / 0 Unknown** and the eight-job PR synthetic test-merge was green. This does **not** provide Security/Business reviewer identity, a live branch ruleset, offsite WORM signoff, independent provider authority, or external corporate/legal proof.

## Phase 1CL engineering: official source of truth / fail-closed access status

New `scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs --ci-hold` runs **after existing Phase 1BY official read-only governance observer** in the same `live-github-governance-hold` GitHub Actions job. It gets the existing job's `github.token` with **`contents: read` and `pull-requests: read` only**, and performs four literal, bounded, redirect-denied GitHub REST GETs:

- `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/contents/.github/CODEOWNERS?ref=main`
- `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/contents/CODEOWNERS?ref=main`
- `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/contents/docs/CODEOWNERS?ref=main`
- `GET https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/pulls/1/requested_reviewers`

**Important:** GitHub selects CODEOWNERS from the pull request's **base branch**; a CODEOWNERS file committed only to the development branch would **not** activate the existing PR's code-owner request policy. This phase **does not** write a fake or unapproved CODEOWNERS file to either branch. GitHub docs: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

**Defenses:** fixed URL and exact read-only HTTP method, no redirects; 6.5-second individual timeouts, 128 KiB streamed JSON limit, no secrets logged; canonical base64 re-encoding, SHA/path/type/size/UTF-8 checks when GitHub supplies an actual CODEOWNERS file; conservative precedence (`.github/CODEOWNERS` then root then `docs/CODEOWNERS`) with unknown if any higher-precedence location is unreadable. A file's owner tokens are *syntactic only*, not verified Github Write permissions or legally approved reviewer authority. Requested-reviewers endpoint validates user/team schema, counts author/non-author and teams, and **never converts a request to submitted approval**. Preceding Phase 1BY's exact PR SHA/merge/head, real applied branch rules and submitted review summary are correlated with current GitHub Actions repo/ref/job identity.

The output `phase1cl-live-codeowners-reviewer-onboarding-hold.json` is a local **UNSIGNED**, **non-WORM** observation with `productionReleaseAuthorized=false` and `releaseDecision=HOLD`. Missing owner files, missing reviewers or weak rules are expected real-world readiness findings, **not a fabricated failed codebase test**. Malformed actual inputs or source context fail the structural check. Failure to read any official API produces `unavailable/access_denied/absent_or_hidden/invalid`, never “approved” or “safe”. The new observer and **16 adversarial groups** `tests/phase1cl-live-codeowners-reviewer-onboarding.test.mjs` are included in Phase 1BV/BW selected-source integrity inventories. The existing **eight-job** CI structure and GitHub permissions remain unchanged; the current governance artifact now includes both Phase 1BY and 1CL **UNSIGNED** reports.

## Exact authorized next actions by a real admin (not simulated)

1. **Appoint two distinct real humans or independent administrative principals:** one independent **Security** reviewer and one independently authorized **Business/Owner** reviewer, each separate from the PR author `j9619655391-max`. Validate actual employment/mandate/organizational authorization **out of band**; obtain written consent and enforce enterprise MFA. GitHub display usernames and GitHub review requests do not prove corporate authority or key custody. Do not invent or auto-assign specific GitHub accounts.
2. **Verify actual write access and base-branch CODEOWNERS:** GitHub repository administrator, **after genuine approval**, must commit a legitimate `.github/CODEOWNERS` file to `main` by a separately reviewed approved administrative process (not via this assistant and **not** by merging unreviewed PR #1). Define explicit owners for security-sensitive config and the CODEOWNERS file itself, and an accountable global ownership fallback. GitHub requires user/team **explicit write access** for ownership assignment. Do not enter private keys or corporate legal identifiers into CODEOWNERS.
3. **Enforce server-side `main` protection/rulesets:** require PR, at least 2 independent current-HEAD approvals, stale review dismissal and last-push approval, Code Owner review, resolved review threads, protected delete/force push, all eight required named CI checks, independently verified no-admin/app bypass, and effective policy on `main`. Confirm ruleset settings via official GitHub read endpoint and independent authorized admin audit rather than code fixtures. For personal user-owned repos, some organization-team rules are not available; the admin should select supported real GitHub user owners or move governance to a properly managed organization, without claiming a plan entitlement they do not have. See https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
4. **Request real PR reviews only after authorization** from those actual identities. Draft PR #1 stays Draft until independently authorized release governance approves transition; nobody may self-approve. Reviewers must inspect exact final HEAD, real data flow, Picomatch withdrawal and full audit, provider/legal/WORM evidence, and file a GitHub `APPROVED` state bound to the latest source commit, with role evidence independently verified. **No request messages or reviewer nominations are sent in Phase 1CL.**
5. **Recheck independent authorities**: actual eMudhra/CCA/RCAI sandbox provider agreement, trust roots and live signed CRL/OCSP; MCA/GST verified company and authorized signatories; offsite immutable WORM/Object Lock retention/deletion denial and independently operated DR restore, revocable witness keys, actual signed CI OIDC workload provenance and OWNER/SECURITY/LEGAL/OPS staging acceptances. Supply credentials only to approved secrets manager, **never GitHub/chat**.

**No release despite last green CI:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Do not merge PR #1, modify `main`, close Issue #2, deploy, send live customer/provider/supplier communications, or post quotes/PO/GRN/stock/finance/tax.

## Actual evidence acceptance matrix

| Real independent evidence | Current observed reality | Release decision |
| --- | --- | --- |
| Effective `main` rules and no-bypass | 0 applied rules read by Phase 1BY; legacy protection endpoint access denied | **HOLD** |
| Authenticated Security and Business GitHub reviewers | 0 submitted PR reviews; roles not authenticated | **HOLD** |
| Valid main-branch CODEOWNERS with explicit approved owners | All three supported paths absent/not independently authenticated | **HOLD** |
| Current-head GitHub reviews and signed source provenance | No current-head reviews; unsigned source custody artifact only | **HOLD** |
| Strict full frozen-lock Bun dependency audit | Phase 1CK **0 Critical / High / Unknown** in that exact audited CI run; frozen Picomatch 4.0.7 unchanged | **Insufficient alone** |
| Genuine external provider/legal and WORM/DR approval | Actual independently authenticated evidence and signoffs missing | **HOLD** |
