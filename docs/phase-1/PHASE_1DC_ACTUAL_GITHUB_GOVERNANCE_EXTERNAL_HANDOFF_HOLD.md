# Phase 1DC — Actual GitHub governance and external-authorization prerequisite handoff (HARD HOLD)

**Observed:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development-only:** `chore/phase0-foundation-20261106`  
**Production:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`  
**Workflow ownership:** PR #1 remains Draft/open/unmerged; Issue #2 remains open. `main` stays unchanged.

## Why Phase 1DC changes priority

The Phase 1CZ–1DB candidate receipts mathematically check detached Ed25519 source signatures, claimed corporate mandates, a claimed offsite CAS, and a claimed WORM/DR recovery. **None independently authenticates corporate officers, actual provider authority or durable remote state.** Repeating self-signed synthetic attestations cannot clear production readiness. Phase 1DC intentionally concentrates on **real official GitHub read-only governance** and an actionable external intake prerequisites list. It does not create further fake trust authorities.

## Observed official GitHub state at phase start

The available read-only GitHub integration actually returned:

| Item | Official observation | Meaning |
|---|---|---|
| Development branch HEAD | `c1b7b8d172d8793fc46fd12ee600832f102cc23f` | Internal Phase 1DB code pushed and verified |
| Base `main` HEAD | `b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b` | No production merge performed |
| PR #1 | Draft, OPEN, UNMERGED | Not a release |
| Issue #2 | OPEN | External blockers remain tracked |
| Submitted PR #1 reviews | **0** | No observed current-head human approval |
| Official repo branch ruleset list | **0** | No installed rulesets observed by this integration |
| `main` `.github/CODEOWNERS` | HTTP **404** | File is absent or hidden to current GitHub integration, not independently verified installed |
| Direct `main` branch protection | HTTP **403 Resource not accessible by integration** | **UNKNOWN**, NOT proof protection is disabled; an independently authorized admin must verify the actual configured policy |

**Important:** A denied branch-protection read is not evidence of no protection, and a single 404 at the conventional CODEOWNERS path is not a complete test of all three GitHub-recognized CODEOWNERS locations. Even when all GitHub technical permissions become readable, an arbitrary GitHub account approval does not establish the person's corporate Security or Business legal appointment.

## Human-initiated read-only verification

New script: `scripts/phase1dc-live-external-governance-readiness.mjs`. An explicitly authorized operator may run:

```sh
# Obtain a read-only GitHub API token in an approved credential manager.
# Inject it through the operator's approved execution environment, not Git/chat.
node scripts/phase1dc-live-external-governance-readiness.mjs \
  --inspect-actual-github-readonly
```

The command reads optional `GITHUB_READ_TOKEN` from the environment and never prints it. On a public repo it can attempt uncredentialed read-only GETs, but any 401/403 remains unknown; no authentication bypass is attempted. The CLI refuses `GITHUB_ACTIONS=true`. **Never use an admin/write token where a read-scoped token suffices, and do not put PATs or private signing keys in PR comments.** Actual security-restricted ruleset bypass visibility may require a separately approved authorized admin to independently inspect/reconcile settings.

The verifier uses only strictly allowlisted `https://api.github.com/repos/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` GET routes, no URL from a manifest:

```text
/git/ref/heads/main
/pulls/1
/pulls/1/reviews?per_page=100        (bounded pages 1–3)
/rulesets?per_page=100&includes_parents=true&targets=branch  (bounded pages 1–2)
/rulesets/{numeric_id}?includes_parents=true  (only listed IDs)
/contents/.github/CODEOWNERS?ref=main
/contents/CODEOWNERS?ref=main
/contents/docs/CODEOWNERS?ref=main
/branches/main/protection
```

All calls are GET-only, redirect forbidden, body limited to 128 KiB, 6.5-second deadline, JSON response checked against fixed official URLs and content types. The tool reads PR #1 and `main` **before and after** reviewing the intermediate sources; if HEAD/base/merge SHA or PR update timestamp changes, it fails closed. It reads GitHub submitted reviews with bounded pagination and validates the **latest submitted** review state for each distinct nonauthor account against the **current** exact development HEAD. Old-head approvals, latest `CHANGES_REQUESTED`, draft/pending reviews, duplicate IDs and self-approvals never count.

It fetches all three recognized `main` CODEOWNERS paths. Its *strict conservative* technical coverage test presently accepts one uncommented wildcard `* @owner1 @owner2` rule with two distinct nonauthor user accounts; more complex GitHub-legal CODEOWNERS syntax is **NOT automatically deemed insecure** but must be independently reviewed and remains **not verified** in this narrow gate. Do not mistake a file existing only on the development branch for an effective base-branch CODEOWNERS policy.

An installed branch ruleset must be **active**, include `refs/heads/main`, have an explicitly visible **empty bypass actor** array, and contain deletion and force-push prevention, 2+ required reviews, stale-review dismissal, CODEOWNERS, last-push approval, required thread resolution, and exactly the eight known GitHub Actions job context names with integration ID 15368 and strict status checks. An absent/hidden `bypass_actors` field is **UNKNOWN/FAIL CLOSED**, not the same as `[]`. Direct branch protection must also be readable with admin enforcement, 2+ reviews, stale dismissal, codeowner requirement and strict checks. If an organization chooses a policy system with equivalent guarantees but different schema, an independently authorized administrator must first update/review the gate in a new development PR and test it; never bypass or quietly waive it.

The result distinguishes `access_denied`, `absent_or_hidden`, `unavailable`, `invalid`, and `read` states. The operator-facing output contains counts, blocker codes, SHA and an external prerequisites list, **not GitHub tokens or private data**.

Even if `technicallyObservedGithubPrerequisitesOnly=true`, the script **always** sets `legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated=false`, all external trust/DR/staging fields false and `productionReleaseAuthorized=false`.

## Genuine external intake action register: named responsible human authority needed

| Workstream | Required independent evidence | Who must provide/approve | Current state |
|---|---|---|---|
| Corporate Security and Business owners | Genuine board/management mandate, distinct authorized nonauthor GitHub accounts, role and delegated signing authority | Company owner/Legal + Security | **NOT PROVIDED** |
| GitHub protected-main governance | Authenticated main CODEOWNERS, no-bypass active ruleset or verified equivalent, latest-head two-person review, required CI contexts | Authorized repo/org admin and named independent reviewers | **NOT VERIFIED** |
| eMudhra and RCAI/CCA | Signed sandbox provider agreement, allowed credential scopes, independently verified CA hierarchy/policy OIDs and CRL/OCSP responses | Provider + authorized corporate owner | **NOT PROVIDED** |
| MCA/GST identities | Verified company registration and signatory power; legal counsel checks documents | Corporate Legal/Compliance | **NOT PROVIDED** |
| External trust provider | Independently authenticated endpoint/domain and TLS/SPKI pins, issuer organization and revocation keys | Approved third-party trust operator | **NOT PROVIDED** |
| Immutable offsite storage and DR | Actual CAS compare/write/readback, external fork witnesses, retained object-version/COMPLIANCE delete-denial, DR restore/RTO/RPO observation | Independent storage administrator + DR/security auditor | **NOT PROVIDED** |
| Build supply chain and deployment | Signed CI OIDC/SLSA run attestation, Security/Legal/Ops/Owner staging acceptance, rollback test | Authorized release governance group | **NOT PROVIDED** |

The table is a handoff, **not an installed policy or a grant of admin authority**. No unknown third-party personnel or keys are invented. The real authority owners must supply names and approved contact channels **outside chat and Git**, verify the legal mandate independently, then initiate the approved access/review/enrollment process.

## Protected-main governance change control

The existing `docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` is explicitly a **proposal**. A legitimate owner/admin can review its exact required status checks, no-bypass actors, last-push and CODEOWNERS requirements; it is **not** itself a live installed ruleset. This project does not autonomously POST branch protection/rulesets or add `main` CODEOWNERS because legal owner/reviewer nominations and admin authorization have not been established. Do not merge the Draft PR simply to activate CODEOWNERS.

No PR review/request, GitHub admin setting, provider secret, live supplier/customer action, invoice/PO/GRN/inventory/finance posting, production deployment or external CA enrollment is performed by 1DC.

## Tests, source custody and verification requirements

- `scripts/phase1dc-live-external-governance-readiness.mjs` — exported pure assessment and explicit operator-only bounded read-only GitHub HTTP observer.
- `tests/phase1dc-live-external-governance-readiness.test.mjs` — **25 adversarial Node test groups** with mock official responses for stable SHA/head, latest submitted reviews and staleness, 403/404 distinctions, CODEOWNERS strict coverage/overrides, missing bypass data, protection weakness, required checks, paginated lists, and GET route/redirect/response integrity. These are *test fixtures only*, not actual company approvals.
- Phase 1BV/BW exact source-custody lists updated with both files; M01–M30 master plan updated. CI workflow YAML, runner action pin/permissions, main branch, rulesets, PR state and Issue status untouched.
- Before calling Phase 1DC internal work verified, independently check **new exact HEAD** hosted push and PR workflow runs, JavaScript/TypeScript/staging-security suites, frozen Bun audit, disposable MySQL + Chromium MFA/role smoke, and official GitHub Actions Jobs against Check Runs, event, suite and job IDs. Preserve any failed initial run/corrective commits accurately and post verified facts to PR #1 and Issue #2.

**FINAL RELEASE/EXTERNAL AUTHORITY GATE: HARD HOLD.**
