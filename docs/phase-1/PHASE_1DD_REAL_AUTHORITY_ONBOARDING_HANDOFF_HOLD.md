# Phase 1DD — Real-authority onboarding handoff and nonsecret evidence metadata (HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch only:** `chore/phase0-foundation-20261106`  
**Protected `main`:** unchanged; PR #1 Draft/unmerged; Issue #2 OPEN.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Why this phase is different

Phases 1CX–1DB provide mathematically consistent **candidate-only** evidence for source keys, operator approvals, claimed append-only CAS and WORM recovery. They do **not** authenticate outside company mandates, legal/corporate trust roots, provider-issued credentials or actual remote storage events. Phase 1DC added a read-only official GitHub governance observer.

Phase **1DD does not generate another synthetic signing layer**. It converts the actual Phase 1DC read-only findings and a strictly limited optional **metadata-only** list into a concrete handoff for independent human approval and external provider onboarding. Its output can never authorize production. A candidate SHA-256 digest records which *untrusted metadata* was presented, not who legally issued or independently verified it.

## Actual official GitHub findings at phase start

| Control | Result returned by GitHub integration | Required next step |
|---|---|---|
| Development HEAD | `16d204687ae2163f629fa9a4c429581dd30203f0` | Recheck after every new commit |
| `main` HEAD | `b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b` | Never merge without authorized independent governance |
| PR #1 | Draft, OPEN, unmerged | Keep draft while external HOLD |
| Issue #2 | OPEN | Track approval/evidence dependencies |
| Submitted reviews | **0** | Company owner/Legal must appoint distinct Security/Business nonauthor reviewers; they must approve the exact latest HEAD through GitHub |
| Branch ruleset inventory | **0** | Authorized GitHub admin must review and enforce appropriate no-bypass `main` protection, confirmed through sufficient read access |
| `main` CODEOWNERS: `.github/CODEOWNERS` | **404** | Authorized admin checks and installs effective base-branch CODEOWNERS through approved change process |
| `main` CODEOWNERS: `CODEOWNERS` | **404** | Same |
| `main` CODEOWNERS: `docs/CODEOWNERS` | **404** | Same |
| Direct `main` branch protection | **403 Resource not accessible by integration** | **UNKNOWN, not necessarily disabled.** Authorized admin with separately approved permissions must inspect and independently record its actual configuration |

The current repo does not show verified latest-head independent reviewer approvals, enforceable no-bypass rulesets or effective CODEOWNERS. The 403 cannot establish the actual branch-protection state. Do **not** invent reviewer names, bypass admin protection, force merge or paste access tokens/private company files into Git/chat.

## Safe operator workflow

Use `scripts/phase1dd-authorized-human-handoff.mjs` locally, explicitly, outside CI.

```sh
# Read-only official GitHub observation + nine-item action register
node scripts/phase1dd-authorized-human-handoff.mjs --inspect-authorized-handoff

# Optional nonsecret metadata-only packet stored OUTSIDE this repo
node scripts/phase1dd-authorized-human-handoff.mjs \
  --inspect-authorized-handoff /approved/offrepo/phase1dd-metadata-only.json
```

`GITHUB_READ_TOKEN` may be injected only through an approved secrets manager or operator environment, never CLI arguments, chat, Git or PR comments. The underlying Phase 1DC client permits **only fixed official GitHub API GET routes**, no redirects, bounded bodies and exact current main/PR rereads; the 1DD wrapper does not write. It refuses automated GitHub Actions execution. Optional metadata must be a regular nonsymlink local JSON file **no more than 64 KiB**, contains no raw evidence or secrets, and is **not transmitted** by this program.

It prints fixed prerequisite role labels, technical status, redacted structural evidence count, safe source HEAD/base and a digest of the handoff view. It prints no candidate record digests, reviewer usernames, private/public keys, organization secrets, document URLs or credentials. All output unconditionally remains `releaseDecision=HOLD`.

## Nonsecret external metadata packet schema

The optional packet can be assembled only **after an appropriately authorized human collects actual external records through approved mechanisms**. It is **not** a means for applicants to self-certify.

Top-level fields are exactly `schemaVersion:1`, `repository`, `sourceHeadSha`, `mainBaseSha`, `createdAt` (canonical UTC milliseconds), and `records` (exactly nine). Every record has exactly `gate`, `custodianRole`, `evidenceClass`, `recordDigestSha256`, `collectedAt`, `expiresAt`, and **`reviewState:'UNVERIFIED'`**. Use one bounded, nonzero 64-hex digest per logically distinct off-repo record; repeated/placeholder hashes, unknown extra fields, expired/stale timestamps, wrong source HEAD or a forged `VERIFIED` status are rejected. The digest is an untrusted **reference**, not validation of its source. The real record, issuer chain, legal signatory and independent authorization remain in approved external evidence custody.

For illustration, one *incomplete and intentionally invalid* placeholder record **must not** be accepted as evidence:

```json
{
  "gate": "GOVERNANCE_SECURITY_AND_BUSINESS_NONAUTHOR_MANDATE",
  "custodianRole": "CORPORATE_OWNER_AND_LEGAL",
  "evidenceClass": "CORPORATE_MANDATE",
  "recordDigestSha256": "NOT_A_VERIFIED_DIGEST",
  "collectedAt": "2026-11-20T00:00:00.000Z",
  "expiresAt": "2026-12-20T00:00:00.000Z",
  "reviewState": "UNVERIFIED"
}
```

No genuine corporate owner, admin, provider or custodian names were supplied. All action owners below identify **required functions**, not appointments.

## Action register and independent authorities

| Gate / required evidence | Responsible role; action | Technical state at phase start |
|---|---|---|
| Security + Business corporate mandates | Corporate Owner/Legal: authenticate and appoint two distinct nonauthor role-holders | NOT PROVIDED |
| Base-main CODEOWNERS | Authorized GitHub Admin: review all three recognized locations, install effective owner coverage through approved governance | Not verifiably installed (all three 404) |
| No-bypass branch rulesets + protection | Authorized GitHub Admin: verify effective rules, bypass actors, eight GitHub Actions checks, admin enforcement, read permissions | 0 listed rulesets; branch protection UNKNOWN (403) |
| Latest-head reviewers | Independently appointed Security and Business reviewers: submit real approval on exact new development HEAD | 0 submitted reviews |
| MCA legal signatory | Corporate Legal/Compliance: authenticate corporate registration, signatory authority and GST evidence | NOT PROVIDED |
| CCA/RCAI/eMudhra CA and revocation | Authorized provider + company Legal: approved contract, chain/policy OIDs, signed real CRL/OCSP | NOT PROVIDED |
| Trust-provider source enrollment | Authorized external provider: approved domain, issuer/revocation credentials and independently authenticated SPKI/TLS pins | NOT PROVIDED |
| Immutable external CAS/WORM/DR | Independent Storage/Security auditor: real authenticated compare/write/readback, fork gossip, Object Lock COMPLIANCE delete-denial, restore with RTO/RPO | NOT PROVIDED |
| OIDC/SLSA + staging acceptance | Independent release governance: signed supply-chain and Security/Legal/Ops/Owner approved staging | NOT PROVIDED |

Only a person with **actual** corporate/legal and delegated admin permissions should perform an approval or governance installation. The previously drafted `docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json` remains a **proposal**; it has not been installed by Phase 1DD. Even a positive technical GitHub read does not certify a company's legal officer mandate or trust-provider contract.

## Developer test and source custody

`scripts/phase1dd-authorized-human-handoff.mjs` uses the Phase 1DC official read-only collector. `tests/phase1dd-authorized-human-handoff.test.mjs` adds **26 adversarial Node test groups** without private signing keys, external secrets, invented reviewer accounts, provider contracts or remote CAS claims. Cases cover unknown 403 protection, missing owners/rules/reviews, stale SHA, applicant-asserted GO/APPROVED, wrong role/class, duplicated/missing nine-gate record, forged or repeated metadata hash, secret fields, stale/expired timestamps, source drift and redacted output.

Both new paths are in Phase 1BV/BW exact source-custody inventories; the M01–M30 master plan records the open external dependencies. CI workflow, GitHub token permissions and `main` are not modified.

Before declaring internal implementation verified, separately confirm **new exact-HEAD** hosted push+PR CI, JavaScript/TypeScript/security tests, frozen dependency audit, disposable MySQL/Chromium MFA/role smoke, and official check runs vs job IDs, run IDs, check suites and original SHA. Report failed initial CI truthfully and update Draft PR #1 and Issue #2 with final independently observed results only.

**All independent external authority and production GO prerequisites remain HARD HOLD.**
