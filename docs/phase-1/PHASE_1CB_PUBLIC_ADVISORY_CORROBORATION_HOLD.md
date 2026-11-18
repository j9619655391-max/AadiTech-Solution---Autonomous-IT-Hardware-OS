# Phase 1CB — Two-source public Picomatch advisory observation and CI provenance HARD HOLD

**Date:** 18 November 2026 (IST).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`.  
**Engineering branch:** `chore/phase0-foundation-20261106`. `main` intentionally unchanged; PR #1 Draft/open/unmerged and Issue #2 open.

## Confirmed public advisory status

GitHub's reviewed advisory for `GHSA-fc5q-39xc-vjpf` (CVE-2026-112366) lists `picomatch` versions `<= 4.0.7` as affected, severity High, and **no patched versions**, last updated 17 November 2026. OSV independently exposes the same advisory alias, package, High rating, and `last_affected: 4.0.7` record, modified on 17 November 2026. These two feeds may share an upstream advisory origin, so their agreement is **not** independent publisher/cryptographic authentication or proof of a patched build.

References (public only):
- https://github.com/advisories/GHSA-fc5q-39xc-vjpf
- https://osv.dev/vulnerability/GHSA-fc5q-39xc-vjpf
- https://api.github.com/advisories/GHSA-fc5q-39xc-vjpf
- https://api.osv.dev/v1/vulns/GHSA-fc5q-39xc-vjpf

## Implemented development-only observation

New `scripts/phase1cb-public-advisory-observer.mjs --ci-hold` makes only two exact fixed public HTTPS GET requests, with no token, redirect or dynamic URL; bounded stream/body (128 KiB), 6.5 second per-source timeout, response URL/content-type/status checks, and no raw transport-error or untrusted provider content logging.

The deny-only snapshot assessor cross-checks:
- GitHub reviewed-advisory GHSA/CVE identity, exact npm package/ecosystem, High severity, updated-date, affected range and absence of a first patched version;
- OSV GHSA/CVE alias, npm `picomatch`, High severity, modified-date, SEMVER introduced/last-affected events, and no `fixed` event;
- actual checked-in Bun-lock `picomatch@4.0.7` entry and SHA-512 integrity syntax, correct Github repo, exact PR-merge/dev branch reference, and runner commit SHA when in hosted CI.

The output `phase1cb-public-advisory-hold.json` carries SHA-256 digests of received JSON objects and a known/unknown/anomalous status, but is intentionally **unsigned**, not a signed package artifact, verified external auditor witness, WORM receipt, or vendor fix acceptance. An observed newer patched version is flagged for separate independent review, never auto-adopted. Public API 403/429, timeout, failure, unexpected schema or disagreement are **UNKNOWN / anomaly**, never evidence that a fix exists, a waiver is available or production release is safe. Observational upstream failures do not replace or weaken the existing mandatory zero-High dependency baseline gate.

Nine adversarial tests in `tests/phase1cb-public-advisory-observer.test.mjs` cover valid unpatched double-source fixture, unavailable data, GHSA/CVE/source spoofing, fake OSV fixes and aliases, claimed future patch without authority, swapped lock/hash/ref/repo, fixed endpoint allowlist, HTTP/content-type errors, oversized/invalid responses, and permanent release HOLD.

The existing `review-vendor-intake-hold` Actions job now runs this observation after the Phase 1BW intake and uploads both UNSIGNED reports. No extra job name, event permission or action ref was introduced; the Phase 1BZ/1CA reviewed eight-job workflow shape remains intact. Phase 1BV selected source custody and Phase 1BW governance-source custody now hash the new verifier and adversarial tests.

## What is still NOT established

A read-only GitHub Actions token, public GHSA/OSV HTTPS responses, the CI merge checkout and SHA-256 fingerprints **do not** independently authenticate npm publisher release identity, signed package provenance, GitHub Actions workload identity, branch protection, actual non-author Security/business approvals, codeowner eligibility, off-platform immutable WORM/DR, or legal provider authorities.

The Picomatch High advisory remains a strict **release-blocking** baseline failure; there is no published supported patched version established by these checks. No fabricated `picomatch@4.0.8`, forced override, disabled audit, dev-only vulnerability waiver, altered first-party vulnerability report or partial-green CI can replace a real upstream release with independent patch verification, regenerated frozen lockfile and a strict zero-Critical/High full audit.

Additional external prerequisites remain: enforced `main` rulesets and authenticated latest-head reviews, independently signed CI provenance and witnessed externally immutable WORM/DR, genuine CCA/RCAI/eMudhra contract and live authenticated signed CRL/OCSP, MCA/GST corporate/signatory evidence, approved real staging and separate OWNER/SECURITY/LEGAL/OPS signoffs.

**Final governance:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep development PR Draft/open/unmerged; never merge to `main` or deploy/dispatch external business effects without independent authorizations.
