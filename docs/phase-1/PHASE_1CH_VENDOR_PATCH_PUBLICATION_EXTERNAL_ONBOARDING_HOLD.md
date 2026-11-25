# Phase 1CH — Upstream Picomatch patch-publication corroboration and authorized external evidence HOLD

**Date:** 18 November 2026 IST  
**Project repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Protected `main`:** unchanged, Draft PR #1 open/unmerged, Issue #2 OPEN.

## Evidence-based finding: no independently verifiable official patched Picomatch release

On **18 November 2026**, publicly inspected sources:
- GitHub Advisory `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366`: Picomatch **through 4.0.7** affected by High-severity single-branch repeated extglob ReDoS. Official fixed version not identified in the advisory. https://github.com/advisories/GHSA-fc5q-39xc-vjpf
- OSV advisory `GHSA-fc5q-39xc-vjpf`, modified 17 November 2026: the same affected source and CVE; no generally accepted official safe upstream version evidenced. https://osv.dev/vulnerability/GHSA-fc5q-39xc-vjpf
- Official upstream GitHub release list: latest observed release 4.0.7, not a verified remediation to CVE-2026-112366. https://github.com/micromatch/picomatch/releases
- Upstream issue #247 explicitly requests a verified fix/release; proposed fixes and pull requests are **not** an official published npm artifact. https://github.com/micromatch/picomatch/issues/247
- Official package page still presents Picomatch 4.0.7. https://www.npmjs.com/package/picomatch

Do **not** claim a verified `4.0.8` release, mark the advisory resolved, accept unreviewed forks or scoped package aliases, alter `bun.lock` to fabricate remediation, skip entire development dependencies, or reduce the **global** strict zero-Critical/High/unknown dependency gate.

## Engineering implementation

New `scripts/phase1ch-upstream-patch-publication-preflight.mjs` exports `assessPublisherRemediation` and `readFixedPublicPublisher`. It observes *only* two literal HTTPS endpoints:
- `https://registry.npmjs.org/picomatch/latest`
- `https://api.github.com/repos/micromatch/picomatch/releases/latest`

The existing Phase 1CB read-only observer separately accesses fixed official GitHub Advisory and OSV API records. The Phase 1CH read-only path consumes Phase 1CB's **unsigned** source report and verified local `bun.lock`, then checks published version, official npm package name, exact npm tarball origin URL, SHA-512 integrity structure, local locked `picomatch@4.0.7` SHA-512 agreement, official upstream GitHub release/tag name, draft/prerelease status, release link, time validity, matched version and source-relative GitHub Actions identity.

Each network call:
- Uses **GET only**, fixed hostname/path, no user-provided URL, credentials or redirects; rejects non-200 status, wrong effective response URL/MIME, excessive content-length or a streamed response greater than 96 KiB.
- Runs under a bounded timeout; unavailable/rate-limited registry or GitHub is treated as **UNKNOWN**, never proof of no vulnerability or a safe patch. No third-party package download or install is attempted.
- Uses no read/write admin token or provider sandbox credential and cannot modify real GitHub or cloud resources.

Candidate findings are deliberately **not** release approval. Even if some future npm registry metadata and upstream GitHub release both show a new version, genuine acceptance requires independently verified maintainer trust/signature/provenance, corroborating **both** advisory feeds with a fixed range, published safe upstream code, verified package provenance/integrity, an explicitly approved frozen dependency graph rebuild and all real integration/regression tests and the independent Security review. The existing mandatory `bun audit` baseline **must** pass with zero Critical/High/unknown; a candidate release tag or registry claim is not enough.

The CLI `node scripts/phase1ch-upstream-patch-publication-preflight.mjs --ci-hold` runs immediately after Phase 1CB inside existing **`review-vendor-intake-hold`** job and generates `phase1ch-publisher-remediation-hold.json` alongside BW and CB **UNSIGNED** reports. The existing eight-job CI graph, pinned actions, read-only permissions and fail-closed audit remain unchanged. Phase 1BV and 1BW selected-source custody include the new verifier and tests.

`tests/phase1ch-upstream-patch-publication-preflight.test.mjs` contains **15 adversarial test groups**: current unpatched release and SHA-512 lock agreement, unavailable upstream source, forged npm package/tarball, integrity mismatch, hypothetical newer version requiring manual review, prerelease/unofficial aliases, fake GitHub release/tag/maturity/time, advisory missing/drift, modified Bun lock/version, wrong GitHub run/repository/ref, exact fixed-host/no-redirect public HTTP and response-stream bounding, and denial of false external release GO.

## Genuine external-evidence onboarding and remediation acceptance sequence

| Required action | Verified independent evidence | Status |
| --- | --- | --- |
| Vendor remediation | Official upstream `picomatch` release with confirmed fixed vulnerable code, publisher identity, signed provenance, verified tarball and provenance to exact source tag | **NOT AVAILABLE/VERIFIED** |
| Advisory closure | GitHub and OSV independently publish consistent *fixed version* ranges and a complete frozen Bun `bun audit` confirms zero Critical/High/unknown | **NOT SATISFIED** |
| Integration acceptance | Rebuild frozen `bun.lock` using an approved release; run typecheck, all JS/TS/staging/real MySQL/Chromium regression and security tests | **BLOCKED ON REAL PATCH** |
| Security review | Independent non-author Security reviewer authenticated through official GitHub review + external corporate enrollment; real effective protected-branch controls | **PENDING** |
| eMudhra trust | Provider-authorized sandbox contract, credentials via approved secret manager, independently authenticated CCA/RCAI certificate hierarchy, live signed CRL/OCSP | **PENDING** |
| Corporate/legal | Actual MCA/GST company and authorized signatory verification; independent OWNER/SECURITY/LEGAL/OPS staging approvals | **PENDING** |
| WORM/DR & CI authority | Externally enrolled witness keys, separate persisted monotonic checkpoint source, offsite signed WORM Object Lock/denied deletion and DR restore, independent signed CI workload provenance | **NOT VERIFIED** |

**Safety and release decision:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Never merge `main`, mark PR #1 Ready, close Issue #2, deploy, make live quote/PO/GRN, dispatch stock, post finance/tax, message real customers or connect an unapproved external trust provider.
