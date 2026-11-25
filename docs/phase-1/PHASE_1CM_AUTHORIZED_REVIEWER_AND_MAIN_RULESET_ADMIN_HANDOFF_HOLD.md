# Phase 1CM — Actual reviewer permission onboarding and GitHub `main` protection proposal (NOT INSTALLED)

**Date:** 19 November 2026 (Asia/Kolkata).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`.  
**Engineering branch:** `chore/phase0-foundation-20261106`.  
**GitHub base:** `main` unchanged; PR #1 Draft, OPEN, unmerged; Issue #2 OPEN.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Real, verified current administrative facts

The connected official GitHub repository API confirms `visibility=public`, owner type `User`, current owner account `j9619655391-max` has `admin=true`, and default branch `main`. Current merge/squash/rebase methods are all enabled; auto-merge is disabled. The same owner's GitHub administrative permission **does not count as an independent Security or Business reviewer, a no-bypass configuration or a signed business release approval**.

Earlier Phase 1CL final-head official GitHub workflow reported: `main` applied rules **0**, legacy branch-protection endpoint **access_denied**, all three GitHub-eligible CODEOWNERS locations under base `main` **HTTP 404**, PR #1 requested reviewers **0** users / **0** teams, actual submitted independent approvals **0**. The last validated Phase 1CL PR test-merge CI run **passed eight of eight jobs**, including the strict whole-lock audit (0 Critical/High/Unknown), real disposable MySQL and Chromium MFA browser checks. These are facts about that exact run, **not current admin ruleset enforcement**. No actual external reviewer signatory, written mandate, independent CI signing, WORM/DR acceptance, eMudhra sandbox or MCA evidence has been supplied.

GitHub official references (public docs):
- https://docs.github.com/en/rest/repos/rules — official **Create a repository ruleset** REST JSON fields, including `pull_request`, `required_status_checks`, `deletion`, `non_fast_forward` and `bypass_actors`.
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets — rulesets supported for public repos including GitHub Free.
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners — GitHub reads CODEOWNERS from the **base branch**, and named owners must have actual `write` access. An owner token is not an authenticated employee identity or guaranteed request.
- https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user — actual repository collaborator permission read.

## Directly usable engineering deliverables

**1. GitHub-API-compatible, UNINSTALLED ruleset proposal**

`docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` is a valid proposed **Create repository ruleset** body, not an existing rule, signed authority or mutation. Its semantics are constrained to `refs/heads/main`: `target=branch`, `enforcement=active` **only if an authorized admin later installs it**, `bypass_actors=[]`, deny ref deletion and non-fast-forward, require PR, 2 approvals, dismiss stale review, last-push approval, code-owner review, resolve code conversations, and strict fresh source checks for all eight currently named hosted CI jobs:

`baseline`, `mysql-integration`, `production-runtime-scope`, `build-input-provenance`, `review-vendor-intake-hold`, `independent-evidence-hold`, `live-github-governance-hold`, `source-merge-lineage-hold`.

The proposal matches the observed repo-enabled merge/squash/rebase methods. Future authorized admin must **verify the GitHub API-version/plan-specific schema and actual available checks against the current `main` repo**, review unintended lockouts, and have a separately authorized administrative change approval **before** any installation. The recipe contains no user identity, private key, PAT, fabricated signoff or bypass account. Merely `enforcement=active` in an uninstalled JSON file does not enforce anything. **Do not POST this body, configure branch rules, or merge the PR until legitimate authority exists.**

**2. Real nominee permission and CODEOWNERS helper, with no GitHub writes**

`scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs` has only three explicit commands:

```bash
# Safe, zero-secret deterministic local CI structural review:
node scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs --ci-hold

# AFTER written appointment, two real named people and explicit consent:
node scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs --prepare-codeowners SECURITY_GITHUB_LOGIN BUSINESS_GITHUB_LOGIN

# Run ONLY by a separately authorized operator with a READ token
# supplied via a supported approved secrets manager as GITHUB_READ_TOKEN:
node scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs --verify-reviewer-permissions SECURITY_GITHUB_LOGIN BUSINESS_GITHUB_LOGIN
```

The preparation command **does not write to `main` or any file**. It validates two distinct GitHub logins and excludes PR author `j9619655391-max` in both roles, then prints a proposed CODEOWNERS text + SHA-256 for manual admin review. It covers the repo, `.github/CODEOWNERS`, workflows, security docs, server security, scripts and tests. Proposed owner names are **never committed or invented by Phase 1CM**; operator invocation should use real consented GitHub accounts, not placeholder names.

The permission command performs **two bounded, read-only official GitHub REST GETs**: `/repos/{owner}/{repo}/collaborators/{login}/permission`, validating each returned GitHub login and one of GitHub's known permission levels. It requires `write`, `maintain` or `admin` as a **technical write-permission precondition**. It returns `access_denied`, `not_found_or_hidden` or `unavailable` rather than treating missing permission data as authorized, and never retrieves private keys or updates reviewer assignments/branch rules. A GitHub token may need specific repository administration READ permissions for this endpoint; do **not** broaden CI's current GitHub token. If source access is denied, use an authorized operator separately with the least privileges that work.

**CRITICAL role separation:** Two names on one CODEOWNERS pattern do **not** guarantee that both named people must approve; GitHub may accept one owner approval on that pattern. The proposed `required_approving_review_count=2` demands two approvals overall, but does not independently authenticate those reviewers as the separately mandated Security and Business signatories. No personal-repo CODEOWNERS text can honestly be promoted to enterprise identity, legal mandate or independent signed role evidence. An authorized Security/Business owner must verify appointments, corporate role and actual distinct review authors out of band and sign current-HEAD acceptance before proceeding. If verified team-specific review enforcement is necessary, an organization-managed repository with appropriate GitHub features may be required; transfer of ownership is **not authorized by this phase**.

**3. CI and adversarial testing**

`tests/phase1cm-admin-ruleset-reviewer-handoff.test.mjs` adds **17 adversarial Node test groups**, including a real-repo-spec ruleset validation, spoofed bypass actors, relaxed review policy, tampered required status checks, substituted `main` refs, malicious reviewer-login strings, same-person or self-reviewer impersonation, bounded GitHub GET source validation, inaccessible or forged collaborator permissions, false signed-role assertions, and no-production-GO even when two technical write grants are observed.

The existing eight-job GitHub workflow adds `--ci-hold` to **`review-vendor-intake-hold`**, producing one additional **unsigned, uninstalled-proposal** report alongside other held vendor/reviewer reports. Phase 1BV/BW source custody hashes the new script, tests and proposed JSON. No new GitHub permissions, job, secrets, status-check names, token, webhook, independent signature, org admin action or `main` mutation. This check can only validate that the reviewed, manually usable proposed ruleset is structurally safe and the release remains explicitly held.

## Accountable human handoff checklist

| Sequence | Authoritative human/account requirement | Actual result of Phase 1CM |
| --- | --- | --- |
| 1 | Real authorized corporate owner appoints **two distinct independent nonauthor** Security and Business signatories, confirms consent, MFA and organization-wide duties | **PENDING**; no nominees assumed |
| 2 | Authorized operator queries real GitHub collaborator permissions with individually scoped token, captures independent role approval and checks repo owner separation | **Tool prepared**, no nominee permissions asserted |
| 3 | Two nominees verify codeowner ownership and proposed source patterns; admin creates approved CODEOWNERS on base `main` via separate authorized review/change process | **Proposal prepared, not installed** |
| 4 | Admin verifies no bypass and applies reviewed `main` ruleset under recorded approval; confirms checks and Code Owner/last-push enforcement using GitHub current read-only endpoint | **Proposed REST body prepared, not applied** |
| 5 | Official GitHub review requests and two independent latest-HEAD, nonauthor approved reviews, signed Security + Business mandate evidence | **PENDING** |
| 6 | Real eMudhra/CCA/RCAI approved provider contracts, signed live CRL/OCSP and chain; MCA/GST legal signatory, independent WORM/Object Lock/DR/witness, signed CI OIDC and staging OWNER/SECURITY/LEGAL/OPS | **PENDING** |

**Never submit any private keys, tokens, passwords, legal identification or provider credentials to chat, GitHub issues, PRs or committed files.** No production deploy, customer/supplier notifications, quotes, POs, GRN, stock, finance, tax or live provider calls. Maintain `main` unchanged, PR #1 Draft/open/unmerged, Issue #2 open.

`productionReleaseAuthorized=false` • `productionReleaseBlocked=true` • `releaseDecision=HOLD`.
