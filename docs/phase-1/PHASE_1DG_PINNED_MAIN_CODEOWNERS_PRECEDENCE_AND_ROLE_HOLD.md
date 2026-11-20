# Phase 1DG — Exact-base-main CODEOWNERS precedence and nominee matching (READ-ONLY / HARD HOLD)

Date: 20 November 2026 IST. Correct repository: `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. Engineering branch: `chore/phase0-foundation-20261106`. PR #1 stays **Draft/unmerged**, Issue #2 **OPEN**, and `main` unchanged.

## Concrete false-positive risk

GitHub selects CODEOWNERS in this priority: `.github/CODEOWNERS`, repository-root `CODEOWNERS`, then `docs/CODEOWNERS`. A lower-priority file does **not** rescue a malformed or conflicting higher-priority file. Inside an effective file, later matching owner rules may override earlier owner mappings. GitHub accepts one of the named CODEOWNERS users for a requested code-owner review; listing two accounts in one line is **not evidence that Security and Business each approved**. A file appearing on the dev branch is not effective for PRs targeting `main`.

Phase 1DG addresses only this narrow **technical readback** gap, reusing the existing Phase 1DF real role-specific latest-HEAD join. It **does not** establish the legal identity or corporate mandate of either person, approve a branch policy installation, or make production releasable.

## Read-only authorized operator (not CI)

Only *after* independently verified corporate Owner/Legal appointments and approved operator read-scoped GitHub access, with a token supplied by an approved secrets manager (never in chat, Git, CLI token args or logs), an authorized human may run:

```bash
node scripts/phase1dg-effective-codeowners.mjs \
  --inspect-pinned-main-codeowners-readonly VERIFIED_SECURITY_LOGIN VERIFIED_BUSINESS_LOGIN
```

The command rejects execution inside GitHub Actions, nonexistent or malformed nominee logins, author-as-reviewer, duplicate nominees, missing read token and unpinned main SHA. It obtains two Phase 1DC official governance snapshots around two Phase 1CO exact-HEAD role-specific reviewer reads (Phase 1DF reconciliation). Only if this bounded technical join is valid does it read all **three** CODEOWNERS paths **at the verified exact 40-character `main` commit**, twice, using only fixed official GitHub GET endpoints, a 6.5-second deadline, no redirects, bounded 128KiB JSON and 64KiB decoded CODEOWNERS. HTTP 403 remains **UNKNOWN**, never treated as 404 or installed policy evidence.

The effective file selected by GitHub's precedence must be a canonical Git blob with matching SHA-1 git-blob checksum, matching size/path and strict canonical base64 UTF-8/ASCII content. This deliberately conservative validator admits only reviewed patterns (`*`, `/.github/CODEOWNERS`, `/.github/workflows/`, `/docs/security/`, `/server/security/`, `/scripts/`, `/tests/`), an all-files wildcard, and exactly two distinct nonauthor nominated accounts **on every noncomment rule**. It rejects unknown pattern, duplicate/reordered override with different owners, malformed encoding, unexpected owner, non-wildcard-only coverage, source digest mismatch, unknown file status and different effective file/digest across double reads. An otherwise valid but unrecognized CODEOWNERS syntax remains **HOLD** pending an authorized human policy review; this tool is not GitHub's full CODEOWNERS grammar.

## Exact limits

The output omits reviewer usernames, GitHub token, raw files and explicit reviewer identity assertions. It may disclose only the public selected path/immutable Git blob SHA, exact source/base SHA, booleans and anomalies. Even when synthetic controls are all positive it unconditionally reports:
```json
{
  "independentlyAuthenticatedCorporateSecurityBusinessMandates": false,
  "effectiveMainRulesetOrAdminNonbypassApproved": false,
  "providerCaMcaWormDrOidcAndStagingAccepted": false,
  "canModifyMainRequestReviewsMergeOrDeploy": false,
  "productionReleaseAuthorized": false,
  "productionReleaseBlocked": true,
  "releaseDecision": "HOLD"
}
```

A read-only GitHub snapshot is not cryptographically signed external authority. It cannot guarantee that administrators or users will not change policy or reviews after observation. Repeated reads at the **same commit SHA** check consistency, but do not authenticate independent corporate appointments. **An operator-only technical YES is neither a mandatory independent approval nor production GO.**

## Tests and custody

- Added `scripts/phase1dg-effective-codeowners.mjs` (no GitHub mutations), `tests/phase1dg-effective-codeowners.test.mjs` (**20 adversarial Node test groups**), integrated into Phase 1BV build-input and 1BW review-source inventories. Existing `tests/*.test.mjs` hosted baseline automatically executes the tests; no CI permissions, endpoint allowlists of existing collectors, or production routes changed.
- Actual **local test history**: first run 13/20 passed and seven tests failed due to `null` rather than `false` for negative-case predicate output; corrected strict boolean normalization with no release bypass; final standalone `node --test` **20/20 PASS**. The initial 7 failures were not presented as success.
- Hosted **exact new development HEAD** push and PR runs, original checks vs Actions Jobs IDs, frozen audit, real disposable MySQL and Chromium MFA/role smoke must be independently observed before describing this engineering increment as hosted CI VERIFIED.

## Real blockers / protected main

Official GitHub before this phase: PR #1 Draft/open/unmerged, zero submitted reviews, zero listed main rulesets, all three standard base-main CODEOWNERS paths HTTP 404 and branch-protection GET HTTP 403 (**UNKNOWN**, not disabled). Corporate Owner/Legal must first authenticate and appoint genuine independent nonauthor Security and Business personnel; approved GitHub admin must install and prove effective protected-main no-bypass governance. External eMudhra/CCA/RCAI provider-authorized trust, MCA legal signatory, live signed CRL/OCSP, real WORM COMPLIANCE CAS/DR, third-party OIDC/SLSA and independently approved staging remain absent.

**Release remains `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.** No CODEOWNERS installation, reviewer request, main merge, production deployment, provider onboarding or business dispatch.


## Official source-run verification — 20 November 2026 IST

**Actual Phase 1DG engineering source SHA:** `cb88a9add0ad9c0cd6e67bfc8806f2d19921ef24` on `chore/phase0-foundation-20261106`. This runbook update is documentation-only and does **not** reuse an earlier SHA's CI as certification of its own later commit.

- [PR GitHub Actions #44728317106](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44728317106): `completed/success`, **8/8 GitHub Actions jobs passed**. Official check suite `121067378043`.
- [Push GitHub Actions #44728308969](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44728308969): `completed/success`, **7 jobs passed and 1 `source-merge-lineage-hold` expected skipped**. Official check suite `121067356631`. Do not represent the push run as eight passes.
- Official GitHub source-HEAD Check Runs API returned **16** checks across the two separate suites. The eight checks of each suite were independently matched to the eight corresponding Actions Jobs by **check/job ID, name, run ID, exact source SHA, GitHub Actions app 15368 and conclusion**. No cross-run blending or skipped-check promotion.
- Actual hosted typecheck, baseline Node test job (including 20 DG adversarial groups), build, dependency advisory checks, disposable MySQL migration/integration and isolated Chromium MFA/role smoke all completed successfully. All are internal engineering tests, not independent release approvals.
- Fresh GitHub governance after push: **zero PR submitted reviews**, **zero listed rulesets**, all three `main` CODEOWNERS standard paths HTTP **404**, direct branch protection HTTP **403/UNKNOWN**, `main=b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b` unchanged, Draft PR #1 open/unmerged and Issue #2 OPEN. No actual nominated Security/Business account or live privileged operator token was provided. Human-only 1DG live operator check was **NOT** performed or misrepresented as passing.

Production remains `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; independent corporate/CA/MCA/provider/WORM/CAS/DR/OIDC/SLSA/staging approvals are still mandatory and unverified.
