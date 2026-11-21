# Phase 1CJ — Withdrawn GitHub advisory, conflicting CVE sources, and independent security adjudication HOLD

**Date:** 18 November 2026 (Asia/Kolkata). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Engineering branch:** `chore/phase0-foundation-20261106`. **Release:** unconditionally HOLD; `main` unchanged, Draft PR #1 unmerged, Issue #2 OPEN.

## New externally observed material event, not a vendor patch

On **18 November 2026**, GitHub's official advisory page changed to **“Withdrawn Advisory”** for `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366`. Its page simultaneously retains the historic **High** label, affected Picomatch **`<= 4.0.7`**, **“Patched versions: None”**, and a link to maintainer discussion `micromatch/picomatch#235`.

- Official GitHub advisory: https://github.com/advisories/GHSA-fc5q-39xc-vjpf — **withdrawn 18 November 2026**, not a released safe npm artifact.
- OSV mirror: https://osv.dev/vulnerability/GHSA-fc5q-39xc-vjpf — still carries an advisory record; its local lifecycle can lag or diverge from GitHub.
- NVD official CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-112366 — independent CVE entry remains visible and requires independent adjudication, not blind suppression.
- Snyk vendor analysis: https://security.snyk.io/vuln/SNYK-JS-PICOMATCH-21248802 — reports advisory revoked/maintainer disputed; this is **not** independently authorized waiver of this repository's frozen dependency audit.
- Picomatch official npm and upstream release records were checked on previous Phase 1CH exact-head hosted CI: `picomatch@4.0.7` latest, SHA-512 agreeing with actual Bun lock, official GitHub upstream latest 4.0.7. No verified upstream fixed package was installed or published as part of this phase.

A withdrawn GHSA does **not** mean “safe by default”, nor does a historical CVE prove reproducible exploitability in every use of Picomatch. The accurate engineering state is **a disputed security finding requiring independent technical adjudication**. Do not fake a `4.0.8` vendor release, create an unchecked patched fork, silently remove the audit rule, or call a withdrawal a signed vendor statement. The mandatory global zero Critical/High/unknown audit remains intact and its **actual exact-HEAD CI result**, not a past claim, governs the software dependency control.

## Implementation

**Existing public observer updated:** `scripts/phase1cb-public-advisory-observer.mjs` now records `githubLifecycleState`, `osvLifecycleState`, `githubWithdrawnAt`, `osvWithdrawnAt`, `withdrawnAdvisoryNotEquivalentToFixedVersion=true`; an official reported withdrawal or disagreement produces specific anomalies and the old `twoPublicFeedsDescribeCurrentUnpatchedRange` flag cannot be asserted merely because both still cite the old vulnerable version range. Missing/invalid/public API rate-limited sources remain UNKNOWN. Phase 1CB still uses strict fixed-host GET, no redirect/credentials and bounded streams.

**New independent-adjudication preflight:** `scripts/phase1cj-advisory-withdrawal-quarantine.mjs` reads only already-produced local Phase 1CB + 1CH unsigned public-source observations, the real frozen Bun v2 lock and the reviewed dependency baseline, under `--ci-hold`. It correlates:

- Literal advisory GHSA/CVE and official GitHub/OSV endpoints, source SHA-256 digests and successful/failed fetch status, lifecycle values (`active`, `withdrawn`, `unavailable`, `invalid`), and withdrawal timestamps.
- Exact matching withdrawal conflict/anomaly from earlier CB source, prevention of false “both feeds active” semantics, and preservation of the historical High-risk baseline even when GitHub removes/withdraws an advisory.
- Phase 1CH observed upstream npm version and tarball/lock matching, no `actualPatchedPicomatchReleaseVerified` or `globalZeroCriticalHighAuditPassed` claim, and the actual current GitHub job/repository/ref/checkout SHA.
- Neither the new report nor public-source agreement supplies genuine vendor code-level proof, signed publisher identity, independently authenticated Security approval or an enforceable production release decision.

All real authority/release flags stay **false**. Phase 1CJ does not use a credential, fork, external provider API, new npm override, live business transaction or elevated GitHub job permission.

**Tests:** `tests/phase1cj-advisory-withdrawal-quarantine.test.mjs` adds **15 adversarial groups**: historically active advisory feeds, official-GitHub-withdrawn/OSV-active cross-source disagreement, both withdrawn, unavailable GitHub/OSV, malformed/replayed or forged timestamps, missing source-content SHA-256, false “active” or “patched” claim, fake GO, npm/lockfile drift, weakened reviewed High baseline, mismatched GitHub CI context, and Node `process.env` object behavior. Three additional Phase 1CJ regression groups appended to Phase 1CB tests to independently validate the new withdrawal/disagreement branch.

**CI path:** The existing **eight-job** GitHub Actions workflow runs Phase 1CJ after the real public Phase 1CB and Phase 1CH read-only observations in the **`review-vendor-intake-hold`** job and archives a **fourth UNSIGNED local public/vendor HOLD report**. Phase 1BV and 1BW selected-source custody now hash Phase 1CJ script and test. No new write permission, mutable action tag, job, key or independent signing claim. The existing baseline strict frozen-lock `bun audit` and `verify-patched-dependencies.mjs` are **not bypassed**.

`docs/security/dependency-advisory-baseline.json` records the **withdrawn/disputed but independently unadjudicated** status while retaining this same historical High severity and `independentSecurityApproval=PENDING` to prevent silent baseline deletion.

## External resolution requirements and named responsibility

| Accountable authority | Evidence needed for a legitimate security resolution | Current state |
| --- | --- | --- |
| Genuine upstream maintainer/publisher | Verifiable maintainer's technical rebuttal, public code review/reproduction with reason for dispute, or authentic safe signed released npm tarball/source and matching provenance | **NOT INDEPENDENTLY VERIFIED** |
| Independent Security reviewer | Authenticated external identity/role, reproducible evidence showing behavior or absence of exploit in bounded sandbox, second-source CVE/GHSA/OSV resolution, signed risk decision linked to exact Git commit and unmodified audit | **PENDING** |
| CI/dependency owner | Fresh **whole-lock** `bun audit --json` with zero Critical/High/unknown; no ignored packages; reviewed frozen `bun.lock` and all JS/TS/browser/MySQL regressions | **MUST BE VERIFIED** |
| GitHub owner/business | Real `main` protection/CODEOWNERS/no bypass; two latest exact-HEAD genuine non-author Security and Business approvals, independent accountable signoff | **PENDING** |
| Provider/legal team | Genuine approved eMudhra/CCA/RCAI provider sandbox agreement and secret-managed credentials, authenticated live signed CRL/OCSP/policy, MCA/GST corporate authorized signatories, OWNER/SECURITY/LEGAL/OPS staging approvals | **PENDING** |
| Storage/witness team | Independently enrolled and revocable offsite witness/public log key, real durable monotonic checkpoints, authenticated WORM Object Lock/delete-denial and offsite DR restore, signed CI workload provenance | **PENDING** |

**Decision protocol:** Until the independent parties can authenticate and sign the appropriate evidence, do not merge PR #1, close Issue #2 or deploy. Even if an advisory is withdrawn and a later `bun audit` reports no High findings, that fact alone does not satisfy external provider, reviewer, legal, WORM, staging or signed-CI provenance gates. Conversely, if the audit still reports High, the strict baseline must fail—never waive it because the GitHub web page changed.

**Never post private provider credentials, private signing keys or secret-manager exports to the repository, issue, PR or chat.** No live quotes/PO/GRN, stock/finance/tax, customer/supplier messages or external provider writes.

`productionReleaseAuthorized=false` • `productionReleaseBlocked=true` • `releaseDecision=HOLD`.
