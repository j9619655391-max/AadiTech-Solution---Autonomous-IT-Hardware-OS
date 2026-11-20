# Phase 1DE — Protected-main authorized-admin rollout preflight (PROPOSAL ONLY; HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development-only branch:** `chore/phase0-foundation-20261106`  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 Draft/unmerged; Issue #2 OPEN; `main` unchanged.

## Actual acceptance problem

Phase 1DD already produced the nine corporate and external evidence action-register rows. The remaining critical dependency is **a human-authorized corporate Security and Business reviewer pair**, with legally valid delegated mandates, independently verified GitHub access, and approved admin installation of main CODEOWNERS and bypass-free main branch governance. A technical GitHub write permission, username, self-signed provider attestation or green internal CI **does not grant** corporate reviewer authority.

The original `docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` is **not installed**; do not call it a live repository policy. Phase 1DE does not change that status. It provides a **narrow read-only operator preflight and manual handoff sequence**, reusing the Phase 1CM controls and actual Phase 1DC official GitHub evidence rather than inventing more synthetic certificates.

## Current official GitHub readback (20 November 2026)

| Control | Actual API result | Appropriate interpretation |
|---|---|---|
| Development `chore/phase0-foundation-20261106` | `717b0a931f27f69ba92eda9fb90cbf8f3ec75bb0` at phase start | Exact current source must be reread after any subsequent commit |
| `main` | `b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b` | Unchanged |
| PR #1 | Draft/open/unmerged | Not approved to merge |
| Issue #2 | OPEN | External blockers tracked |
| Submitted PR reviews | 0 | No actual independent current-HEAD reviews |
| Listed branch rulesets | 0 | No installed repo rulesets observed to current integration |
| `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` on `main` | Each HTTP 404 | Not verifiably installed in any of the three standard base-branch paths |
| Direct branch protection endpoint | HTTP 403, Resource not accessible by integration | **UNKNOWN / UNVERIFIED**: 403 is not evidence that branch protection is disabled |

Current integration credentials cannot prove the effective branch protection setting. That calls for an independently authorized administrator with appropriate read privileges, not a bypass or an invented conclusion.

## Authorized-human operator preflight

New source: `scripts/phase1de-admin-activation-readiness.mjs`. It only executes **official GitHub GET operations** using the existing 1DC and 1CM allowlisted clients. Run *manually* after confirming operator authority, outside CI.

```sh
# Observe real main/PR/reviews/ruleset/CODEOWNERS/protection state.
node scripts/phase1de-admin-activation-readiness.mjs --inspect-admin-readonly

# Only AFTER company owner and Legal independently appoint two real role-holders:
# substitute verified GitHub usernames, never put access credentials in arguments.
node scripts/phase1de-admin-activation-readiness.mjs \
  --inspect-admin-readonly VERIFIED_SECURITY_GITHUB_LOGIN VERIFIED_BUSINESS_GITHUB_LOGIN
```

`GITHUB_READ_TOKEN` can be supplied through an approved operator secrets manager/environ­ment **only if appropriately scoped**. It must not appear in chat, shell command arguments, Git commits, test data or PR comments. A public-API read with no token can still produce `access_denied`, `not_found_or_hidden` or `unavailable`; these statuses do not constitute negative corporate/legal verification.

When both human-provided logins pass syntax and independent nonauthor checks, the existing Phase 1CM collaborator endpoint may be queried with **read-only GET** to see current GitHub repository `write`/`maintain`/`admin` technical permissions. Missing/403/404/read/triage permission fails the technical precondition. A login string alone is **not a nominated corporate officer**. A passing technical check cannot prove Security and Business signed legally acceptable mandates or represent two actually independent reviewers.

The preflight validates the existing proposal requires **two approving reviews, code-owner review, last-push approval, stale review dismissal, thread resolution, no bypass actors, no force push or deletion, and all eight named GitHub Actions check contexts bound to app 15368**. It computes a **SHA-256 of a proposed CODEOWNERS draft** for the nominated distinct accounts. It does NOT write that draft to `main`, install rulesets, submit reviews, request PR approval, or apply any admin actions. The result deliberately does **not** publish the nominee usernames or credentials.

### Manual change-control sequence

| Step | Independently accountable party | Evidence required before proceeding |
|---|---|---|
| 1. Appoint Security + Business officers | Company Owner + Legal | Actual appointments with scope, separation and out-of-band identity verification (not a GitHub username assertion) |
| 2. Observe repository access | Authorized GitHub admin with read scope | Official API shows two named nonauthor accounts with current write-capable access; technical access is not legal mandate |
| 3. Install effective `main` CODEOWNERS | Authorized repo/org admin via separately approved governance change | Content is base-branch effective, contains independently approved owners, explicit GitHub owner access and no unintended precedence overrides |
| 4. Install/verify enforceable no-bypass `main` rules | Authorized repo/org admin | Real active effective ruleset/branch protection; empty verified bypass actors, two current approving reviews, stale/codeowner/last-push controls, eight exact hosted checks; 403 requires authorized readback |
| 5. Collect actual independent current-HEAD reviews | Genuinely appointed Security + Business personnel | Latest push source SHA, submitted nonauthor approval, no later CHANGES_REQUESTED or dismissal; independent signoff provenance |
| 6. Confirm provider/CA/storage/staging external authority | External provider, corporate Legal, independent Security/Ops/Owner | Contracted eMudhra/RCAI/CCA/MCA signatory, live CRL/OCSP, authenticated issuer/TLS, externally durable CAS/WORM COMPLIANCE/DR, signed OIDC/SLSA and staging acceptance |

**Ordering matters:** do not merge Draft PR #1 to make CODEOWNERS appear on `main`; the authorized governance installation must be an independently approved change following the correct corporate process. Do not bypass already installed policy or install an alternative that silently permits administrator overrides.

## Explicit tool trust boundary

`assessAdminActivationPreflight` outputs only a technical candidate status. It reports stable official source HEAD/base, local ruleset proposal validity, nominated account syntax, read-only GitHub technical permission observations, proposed CODEOWNERS content hash, and which policies/reviews the official GitHub API made visible. Its `requiredHumanActions` remain **manual instructions**. It unconditionally returns:

```json
{
  "reviewOfCorporateRoleAppointmentsAuthenticated": false,
  "approvedActualAdminWriteOrPolicyInstallation": false,
  "trustedExternalOfficerProviderAndCaMandatesAuthenticated": false,
  "finalIndependentProductionAcceptance": false,
  "canInstallOrChangeMainGovernance": false,
  "canRequestOrSubmitReviewOrMerge": false,
  "canActivateExternalProvidersOrDeploy": false,
  "productionReleaseAuthorized": false,
  "productionReleaseBlocked": true,
  "releaseDecision": "HOLD"
}
```

A mock test passing **all** technical GitHub controls does not change these fields. No actual corporate nominations, authorized admin change request, latest-head approved reviewer pair, provider sandbox agreement or real remote archival storage proof has been received or authenticated. This preflight is not a release authorization service.

## Tests, inventory and final CI contract

- New `scripts/phase1de-admin-activation-readiness.mjs` — explicit human-only read-only official GitHub observer plus existing proposal and optional reviewer-permission inspection.
- New `tests/phase1de-admin-activation-readiness.test.mjs` — **20 adversarial Node test groups**: no nominees, author/self/duplicate spoof, wrong technical permission, 403 unknown, degraded ruleset, exact head drift and untrusted technical APPROVED signals.
- Both files included in Phase 1BV and Phase 1BW immutable source-input custody and this phase documented in `docs/completion/MASTER_M01_M30_COMPLETION_PLAN.md`.
- No GitHub admin PUT/POST/PATCH/DELETE, CODEOWNERS installation, CI workflow changes, secret injection, production deploy or provider actions.

Verify the exact final SHA with **fresh GitHub-hosted push and PR workflows**, JS/TS/staging-security baseline, frozen audit, disposable MySQL and Chromium MFA/role smoke, and official Check Runs/Actions Jobs 16-record reconciliation. If a test fails, preserve that failure honestly and verify a subsequent corrective SHA before calling the internal engineering work complete.

**Any external GO decision stays blocked until independent corporate/provider and authorized protected-main evidence is real and reviewed.**


## Actual final Phase 1DE source-HEAD GitHub verification — 20 November 2026 IST

The **tested engineering source commit** is `4c5de3b8048a3f395a47586b9e3ff819d4fb76c1`; this document-only custody update is a later commit and must not be confused with that exact tested SHA.

- Official branch/PR identity: repository `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, dev `chore/phase0-foundation-20261106` at `4c5de3b8048a3f395a47586b9e3ff819d4fb76c1`, `main=b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b`, PR #1 **DRAFT/OPEN/UNMERGED**, Issue #2 **OPEN**. No main change or merge.
- **Push** [run 44717002976](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44717002976): `completed/success`, source HEAD `4c5de3b8048a3f395a47586b9e3ff819d4fb76c1`, suite `121037035523`, **7 successful jobs and 1 intentional `source-merge-lineage-hold` skip** for a non-PR push. Not 8/8 push success.
- **PR** [run 44717011255](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44717011255): `completed/success`, same exact source HEAD, Actions workflow ID `408632517`, path `.github/workflows/ci.yml`, suite `121037057914`, **all 8/8 Actions Jobs completed/success**. These are `live-github-governance-hold`, `baseline`, `independent-evidence-hold`, `review-vendor-intake-hold`, `mysql-integration`, `build-input-provenance`, `source-merge-lineage-hold`, `production-runtime-scope`.
- Official source-HEAD Check Runs API returned **16** checks across **two distinct run suites**; each suite's check records matched its own run/job IDs, all were GitHub Actions App **15368**. The PR suite's **8** check IDs/names agree with its separately fetched **8** Actions Jobs; the push suite's skipped check was **not imported** into the PR's green count.
- Official completed PR job steps show typecheck, baseline tests, build, frozen-lock dependency advisory checks, disposable MySQL migration/integration and isolated Chromium MFA/role smoke succeeded. These steps are **internal engineering CI only**, not third-party signed provenance, genuine provider onboarding or staging verification.
- Fresh official main-state re-read: **0** submitted PR reviews, **0** listed repository rulesets, all three base-main `CODEOWNERS` standard paths returned **404**; direct branch-protection GET returned **403 Resource not accessible by integration**. Protection is **UNKNOWN**, not certified absent/disabled.
- No corporate owner/Legal mandate, named genuinely independent Security/Business officers, authorized admin change record, eMudhra/RCAI/CCA/MCA live credentials/issuer and revocation, external WORM COMPLIANCE+DR, independent signed OIDC/SLSA or final staging signoffs supplied or authenticated. Proposed ruleset remains **UNAPPLIED**.

**Boundary:** green push/PR workflows certify only that exact development commit's hosted technical gates. They do not confer corporate authority, create external evidence, approve main policy changes or authorize release. `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep Draft PR #1 and Issue #2 open; do not merge or deploy.
