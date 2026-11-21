# Phase 1CO — Real latest-HEAD nonauthor Security/Business GitHub review verification (HARD HOLD)

**Date:** 19 November 2026 (IST). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`; **`main` unchanged**. Draft/unmerged/open PR #1 and OPEN Issue #2. **No production authorization.**

## What is actually present

The official connected GitHub API still shows **0 submitted PR #1 reviews**, no installed GitHub rulesets, base-`main` CODEOWNERS not found, and no authenticated separate Security/Business reviewer role. A real repository-owner admin account is not a substitute for two independently authorized reviewers. Phase 1CM's bypass-free `main` ruleset remains **proposed and UNINSTALLED**, and Phase 1CN's official read-only ruleset inventory established zero actual installed rulesets. GitHub ruleset bypass actors may be hidden from read-only callers; the absence of `bypass_actors` is not proof of no-admin-bypass.

GitHub's [official pull-request review API](https://docs.github.com/en/rest/pulls/reviews) provides `id`, `user.login`, `state`, `submitted_at`, and `commit_id`. Its [branch review rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) may dismiss stale approvals after a push, require a person other than the latest pusher to approve, and require Code Owner approval. No GitHub review record, collaborator write permission or CODEOWNERS owner token authenticates a corporate employee's Security or Business legal mandate or a detached signing key.

## New useful operator capability (no names invented)

`scripts/phase1co-live-exact-head-reviewer-quorum.mjs` supports exactly two scopes:

```bash
# CI is source-bound; no nominated identities, secrets or external changes:
node scripts/phase1co-live-exact-head-reviewer-quorum.mjs --ci-hold

# Only AFTER two separate real humans have been nominated, consented and
# independently authorized for the distinct Security + Business roles:
# Provide GITHUB_READ_TOKEN only from the approved local secrets manager.
node scripts/phase1co-live-exact-head-reviewer-quorum.mjs \
  --verify-actual-reviewers SECURITY_GITHUB_LOGIN BUSINESS_GITHUB_LOGIN
```

**Do not enter real logins, approval credentials, private signing keys or PATs into chat/committed files, Github Issue comments, scripts, log captures or CI environment.** The operator-supplied token must be scoped only for the authorized read actions, not administrator writes. The user/account must hold the necessary GitHub repository read permissions (reviews) and collaborator-permissions read entitlement; if denied, the result is **UNKNOWN/HOLD**. The command refuses this human-nomination mode in GitHub Actions.

The human-invoked command makes fixed, official **read-only** GitHub GET requests for this repo: PR #1 before and after collection; bounded PR reviews (up to three hardcoded 100-review pages; full pagination required); separately authorized `GET /collaborators/{login}/permission` for each of **two explicitly nominated, distinct, nonauthor GitHub accounts**. The endpoints and token are not modified, no POST/PATCH/PUT/DELETE, no reviewer requests/assignments, and no repository permissions changed.

It distinguishes **technical observations** from external acceptance:
- Validates PR #1 remains DRAFT/Open/unmerged with correct author, fixed engineering branch, `main` base, exact current source SHA, and same head/base/merge/updated timestamp before and after review collection; any concurrent PR update causes rejection.
- For each nominated actual GitHub login, requires a **latest submitted review** with `state=APPROVED` and `commit_id` equal to the live PR head. A stale approval for an older commit, a later COMMENTED/CHANGES_REQUESTED/DISMISSED review, PENDING draft review, duplicate review ID, unknown state, forged timestamp, incomplete pagination, self-review or same-person alias does not qualify.
- Separately verifies each nominated user's actual GitHub `write`, `maintain` or `admin` repository permission from the official read-only collaborator-permission endpoint. A public `read` / `triage` role, hidden or denied API cannot qualify.
- Returns an **actual technical latest-HEAD two-person GitHub approval receipt** only if all sources match. Its result explicitly continues `realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated=false`, `latestHeadApprovalSignaturesIndependentlyCryptographicallyVerified=false`, `mainCodeownersAndBypassFreeRulesetIndependentlyVerified=false`, `productionReleaseAuthorized=false` and `releaseDecision=HOLD`. A future positive technical receipt can support a genuine authorized security review—but cannot by itself authorize merge or production.

The current Actions job uses `--ci-hold` **without nominated identities or additional token**, *after* existing Phase 1BY actual PR/reviews/rules, 1CL actual `main` CODEOWNERS/reviewer requests, and Phase 1CN actual ruleset/bypass visibility. It correlates real GitHub checkout/merge SHA and prior source reports and explicitly captures zero actual current-head approvals/missing `main` protection. New **UNSIGNED** report `phase1co-live-exact-head-independent-reviewer-hold.json` joins those existing reports in the current `live-github-governance-hold` artifact. New `tests/phase1co-live-exact-head-reviewer-quorum.test.mjs` contributes **19 adversarial Node groups** and Phase 1BZ/1CA protects the exact newly named zero-input CI step with one additional immutable-workflow regression group. Phase 1BV/BW source custody inventories hash both added files. Same eight jobs, existing read-only token, no authority promotion.

## True human sign-off and administrative installation gates

1. An actual corporate owner must **appoint and independently authenticate** two distinct nonauthor Security and Business signatories, verify mandate and consent/MFA, and document role accountability **outside GitHub proposal text**. No real identities have been supplied or assigned; the operator CLI cannot be meaningfully executed without them.
2. Authorized GitHub admin must **separately approve** installation of genuinely reviewed `main` CODEOWNERS and live ruleset (Phase 1CM proposal, currently uninstalled); independent privileged verifier must confirm actual bypass actors and effective no-bypass enforcement. Two CODEOWNERS names in one pattern **do not guarantee both roles sign**.
3. Human reviewers inspect the exact PR source HEAD, independently adjudicate withdrawn Picomatch GHSA and frozen whole-lock audit, then submit actual GitHub reviews (and separate corporate-role signing attestations); re-run the operator read-only command from the approved account after the last push. The current PR should remain Draft/unmerged until all independent gates are satisfied.
4. Separate external authorities must provide genuine eMudhra/CCA/RCAI approved sandbox and authenticated signed CRL/OCSP/certificate policy, MCA/GST legal-signatory records, signed CI OIDC provenance, independent remote WORM Object Lock/retention/denied deletion/offsite DR restore/witness evidence, and independently authenticated OWNER/SECURITY/LEGAL/OPS staging acceptance. These are not provided by GitHub reviewers or local tests.

**No side effects:** no main branch change, CODEOWNERS installation, ruleset POST, reviewer invitation, actual approval, external provider/supplier/customer contact, procurement/finance/tax posting or production deployment.

`productionReleaseAuthorized=false` · `productionReleaseBlocked=true` · `releaseDecision=HOLD`.
