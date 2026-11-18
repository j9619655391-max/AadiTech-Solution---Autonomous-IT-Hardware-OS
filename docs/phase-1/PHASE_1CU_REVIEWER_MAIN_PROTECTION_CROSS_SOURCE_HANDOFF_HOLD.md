# Phase 1CU — Independent reviewer × main-protection cross-source operator handoff (HARD HOLD)

**Date:** 19 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`; `main` remains unchanged; PR #1 Draft/unmerged, Issue #2 OPEN.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Purpose and threat model

Earlier Phase 1CO independently verifies two explicitly *human-nominated* GitHub reviewer accounts' current-HEAD approvals and collaborator write permissions, Phase 1CN observes installed ruleset sources with limited privilege, Phase 1CL observes actual base-main CODEOWNERS, and Phase 1CT binds two finished current-head push/PR suites to first-party GitHub check/job IDs. **None alone proves** that the reviewers are the corporate Security/Business officers, that the branch has enforceable non-bypass protection, or that an independent production authorization exists.

Phase 1CU combines these source observations in an **operator-only, read-only** handoff and hard-denies stale source SHA, any changed PR/base-main ref, nomination mismatch, incomplete official read, future/pending/old CI suites, hidden bypass actors, invalid base-main CODEOWNERS bytes, and weakened required check/reviewer policy. It is intentionally *strict*: an admin may need to validate an exact proposed CODEOWNERS format and exact active named main ruleset. The tool **cannot** install either policy, submit reviews, appoint officers, grant permissions, sign attestations, authenticate a company, merge or deploy.

## Authorized operator command

After authorized Security and Business officers have been *independently* appointed, and both exact-head GitHub push/PR runs are complete, use approved read-only GitHub API credentials from a secrets manager:

```sh
node scripts/phase1cu-independent-governance-handoff.mjs \
  --verify-handoff PUSH_RUN_ID PR_RUN_ID AUTHORIZED_SECURITY_GITHUB_LOGIN AUTHORIZED_BUSINESS_GITHUB_LOGIN
```

Supply the token only as `GITHUB_READ_TOKEN` via approved secret injection. Never paste a token, reviewer key, corporate ID, legal signature or sensitive evidence into chat, GitHub source/comments, scripts or screenshots. Do **not** invent usernames; never run the named reviewer command in CI. The program refuses `GITHUB_ACTIONS=true`, self/duplicate nominees and nonnumeric/ambiguous run IDs; does not emit nominee names or secrets in its verdict. Failed/missing token results in a **nonzero exit** and a HOLD receipt.

### Explicit, fixed GitHub REST read order

1. PR `/pulls/1` before; actual `/git/ref/heads/main` before.
2. Phase 1CT: Draft PR, development branch ref, specific completed push/PR runs, exact-HEAD Check Runs, latest-attempt Actions Jobs for each run, Draft PR after.
3. Phase 1CO: read Draft PR, bounded (max 3 pages) submitted reviews, both actual nominated account collaborator permission records, Draft PR after.
4. Phase 1CN: bounded official branch ruleset page(s), exact IDs of each official ruleset and complete detail records, including any readable bypass actor arrays.
5. Phase 1CL: actual `/contents/.github/CODEOWNERS?ref=main` read (the *PR target base* branch, not development).
6. Official `main` ref again and Draft PR again; reject any HEAD/base/merge SHA, `updated_at`, or main ref movement across the complete read sequence.

Every reader is restricted to fixed official `api.github.com` GET routes, bounded JSON and no redirects. The additional Phase 1CU main-ref reader permits **only** `/git/ref/heads/main` with fixed path, 6.5-second network abort and max 128 KiB response. It never trusts arbitrary URLs or follows response-provided links.

### Acceptance constraints (technical observations only)

- Source repository/author/branch/PR #1 remain exact. PR remains Draft, unmerged and unchanged before/after every observation. Official `main` ref SHA must equal the actual PR target base SHA on both reads.
- Phase 1CT must independently verify both **finished** current-source GitHub Actions runs, separate suites/check/job IDs, seven successes plus the uniquely PR-only skipped job on push, and eight successes on PR. All Checks and Actions Jobs must be same run, attempt, SHA and GitHub Actions app identity `15368`.
- Actual nominated GitHub Security and Business **different nonauthor accounts** must both individually show current-head `APPROVED` *latest submitted review*, full bounded official review pagination and actual repository write/maintain/admin permission, not merely review-requested.
- A real, **active, precisely `main`-targeted** named ruleset with all four required rule types must match the reviewed Phase 1CM proposal: no deletion or force push, two approvers, stale approvals dismissed, CODEOWNERS approval, last-push approval, resolved threads, strictly exact eight required contexts pinned to GitHub Actions app ID `15368`.
- `bypass_actors` on that applied active ruleset **must be present as an explicit empty array**. GitHub may conceal this field from readers without rights to inspect the ruleset. Hidden, denied, partial, malformed or nonempty is **not evidence of no bypass** and fails closed. This is an operator hard-stop, not an invitation to grant admin credentials or bypass security.
- Actual base-`main` `.github/CODEOWNERS` must be a normal file with canonical base64 bytes, UTF-8 integrity and Git blob SHA-1 matching the official content metadata. Its bytes must match the **exact safe Phase 1CM nominated two-person proposal**, covering `*`, workflow/CODEOWNERS, scripts, tests and security paths with both named people. A near match, later override, valid-looking single-owner file, symlink or development-only proposal is not accepted.
- No local SHA-256 checksum, synthetic positive fixtures, GitHub API read or successful CI check constitutes legally signed reviewer appointment, signed OIDC/SLSA provenance, trusted CA certificate, external WORM/witness retention or production GO.

## Known actual blockers before authorized operator review

The official connected GitHub repository check on 19 November 2026 returned **0 submitted PR reviews**, **0 installed rulesets**, and HTTP 404 for actual `main` `.github/CODEOWNERS`. No independently nominated officers, legal role mandates, actual corporate signatory authority, approved provider sandbox credentials, cross-signed eMudhra/RCAI/CCA trust anchors, MCA verification, independent live CRL/OCSP, signed OIDC/SLSA attestations, external WORM/DR or completed independent staging approvals are available in this engineering context. These can be solved only by authorized external actors and verified evidence. We do not manufacture appointments or use fixtures as external authority.

## Implementation and checks

- **Implementation:** `scripts/phase1cu-independent-governance-handoff.mjs` with `assessExactAppliedMainRuleset`, `assessNominatedMainCodeowners`, `assessIndependentGovernanceHandoff`, `readMainRefOnly`, `verifyIndependentGovernanceHandoff`, and human-only CLI.
- **Adversarial tests:** `tests/phase1cu-independent-governance-handoff.test.mjs` with 18 groups (synthetic passing fixture cannot grant GO; no rulesets/incomplete source; hidden/configured bypass; wrong branch/enforcement/name; missing/extra rules; weakened two-person policy; wrong eight app checks; wrong CODEOWNERS file/base64/size/Git blob; sole owner; nominee mismatch; invalid reviews/permissions; old CI SHA; main-ref/PR races; proposal drift; bounded GET/redirect/403; absent token; invalid operator arguments).
- **Custody:** Phase 1BV and Phase 1BW source inventories now include both code and tests. No changes to existing workflow YAML, job count, action-pin SHAs, GitHub write permissions, protected `main` or service credentials.
- **Hosted tests:** Validate *final commit's* GitHub Actions push and PR runs before marking CI complete. Any earlier green runs, including Phase 1CT `44411519874` and `44411534470`, cannot sign off newly added CU code.
- **Important limitation:** A test invoking the pure evaluator with synthetic "all green" objects demonstrates consistency checks only; it **does not execute the human-nominated operator command** or authenticate legal Security/Business authority.

**All actual external evidence/approvals remain outstanding; production release stays HARD HOLD.**
