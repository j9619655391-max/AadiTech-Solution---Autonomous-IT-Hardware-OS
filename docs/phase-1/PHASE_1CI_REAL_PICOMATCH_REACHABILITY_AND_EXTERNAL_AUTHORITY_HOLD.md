# Phase 1CI — Real locked Picomatch exposure tracing and externally authenticated remediation prerequisites (HARD HOLD)

**Date:** 18 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`; `main` unchanged; Draft PR #1 unmerged and Issue #2 OPEN.

## Verified vulnerability and actual dependency surface

GitHub security advisory `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366` lists **High** ReDoS for Picomatch **through 4.0.7**, **patched versions: none** as of 18 Nov 2026. The earlier Phase 1CH hosted CI read the actual **npm latest Picomatch 4.0.7**, corroborated the official `micromatch/picomatch` latest GitHub release 4.0.7 and checked its npm SHA-512 integrity against the repository's real Bun v2 frozen lock. A correctly bounded local scope is **not a patched dependency**. Do not install fabricated `4.0.8`, rely on patched-looking forks or override/waive the mandatory global zero Critical/High/unknown audit.

Phase 1CI inspected the **actual** frozen Bun lock, rather than trusting an operator-submitted dependency map. The selected repo lock currently contains **336 package records** (including Bun nested package records); `picomatch@4.0.7` is pulled by the following recorded edges:

| Package in Bun lock | Edge class | Requested Picomatch version |
| --- | --- | --- |
| `vite@6.4.5` | `dependencies` | `^4.0.2` |
| `tinyglobby@0.2.17` | `dependencies` | `^4.0.4` |
| `fdir@6.5.0` | `peerDependencies` (optional peer) | `^3 || ^4` |

The server's `NODE_ENV !== 'production'` guard keeps Vite imports development-only. Phase 1BT checks the *production root* transitive closure excludes Picomatch and Vite. Phase 1CI separately enumerates the full lock's direct introducers, whether the above two **actual** package dependencies remain reachable from development roots, and whether any new production-root path to Picomatch appears. It does **not** prove there are no other untrusted glob entrypoints anywhere in the repository, nor does it repair Picomatch's vulnerable algorithm.

## Implementation and CI

`scripts/phase1ci-picomatch-exposure-preflight.mjs` exports `assessLockedPicomatchExposure`, `EXPECTED_INBOUND`, `EXPECTED_LOCK`. It:

1. Reads the exact Bun v2 lock, package manifest and selected `server.ts` and `vite.config.ts` entrypoints using bounded, regular-file, no-symlink reads. Handles actual Bun nested lock keys rather than falsely treating a nested scoped package name as an injected dependency.
2. Pins the existing `picomatch@4.0.7` locked tarball SHA-512, the inspected `vite@6.4.5`, `tinyglobby@0.2.17`, and `fdir@6.5.0` versions, and exact Picomatch direct inbound dependency/peer edges. New or removed introducers, changed ranges, unreviewed package version/integrity, unexpected Picomatch lock metadata or direct workspace Picomatch are anomalies. These pins provide **tamper/drift detection**, not security remediation.
3. Reuses the Phase 1BT real production dependency closure checker, and traverses bounded actual production/development roots to record representative paths and reject Picomatch production reachability. The reviewed project currently lists `vite -> picomatch` and `vite -> tinyglobby -> picomatch` as development paths. `fdir` has an optional peer, **not** proof of direct production inclusion.
4. Checks *selected entrypoints only*: direct `picomatch`/`tinyglobby`/`fdir` imports in `server.ts` or `vite.config.ts`, and the intended Vite loopback-only host, allowed hosts, strictPort, false CORS/HMR, file-system strictness and watcher disabling option. It **does not** parse all modules or guarantee no runtime dynamic imports or untrusted patterns; report flags for those claims are permanently false.
5. Runs inside the unchanged, read-only `production-runtime-scope` GitHub Actions job after Phase 1BT, in the job that already executes a disposable `bun install --frozen-lockfile --production` and proves vulnerable build-only modules do not appear in that isolated install. Writes `phase1ci-locked-matchers-exposure-hold.json` next to Phase 1BT's **UNSIGNED** hold report. No ninth job, new write token, new external credentials, lockfile edits or real production operations.

`tests/phase1ci-picomatch-exposure-preflight.test.mjs` adds **15 adversarial groups**: exact real Bun lock introducers, accurate dev/production routes, forged direct/transitive production edges, malicious extra dev introducers, mutated peer/ranges, tampered SHA-512 package, unexpected vite/fdir/tinyglobby versions, new entrypoint imports, permissive Vite/HMR configuration, malformed/nested dependency metadata, fake GitHub runner/ref, and injected production GO claims.

Phase 1BV build-input and 1BW review-policy selected-source inventories include the new verifier and test source. The CI source-bundle digest changes accordingly, but remains a **local unsigned hash**, not an independent CI attestation.

## Required actions for genuine release eligibility

| Owner / gate | External, objectively verifiable evidence required | State |
| --- | --- | --- |
| Picomatch upstream maintainer | Official released safe source revision, documented ReDoS fix, authorized npm publisher identity and package provenance; GitHub + OSV advisory fixed-range corroboration | **PENDING** |
| Dependency/Security reviewer | Approved new version/lock, actual package tarball provenance and integrity, regression test for vulnerable repeated extglob in separately sandboxed bounded process, full frozen build and **global** zero Critical/High/unknown Bun audit | **PENDING** |
| GitHub administrators | Enforced actual protected-`main` rulesets/CODEOWNERS/no admin bypass, two independent Security/business latest-HEAD non-author reviewer identities and approvals, auditable current branch source | **PENDING** |
| eMudhra / CCA / RCAI | Genuine authorized sandbox contract, separated secret-manager credentials, independently pinned certificate policy/trust roots and authenticated signed live CRL/OCSP | **PENDING** |
| Corporate/legal/finance | Actual MCA/GST company and authorized-signatory evidence, independently approved roles and legal acceptance | **PENDING** |
| Independent witness + storage | Enrolled and revocable external keys, offsite signed monotonic checkpoints, authenticated immutable WORM version, Object Lock retention/denied-delete audit, isolated DR restore and independent fork detection | **PENDING** |
| Staging + release board | Independently authorized OWNER/SECURITY/LEGAL/OPS staging acceptance; signed CI workload provenance and reproducible audit; all unresolved high vulnerabilities genuinely removed | **PENDING** |

**No external authority should send secrets, private keys, signing certificates' private material, or production credentials into GitHub or chat.** Provider credentials only through approved secrets management; onboarding needs contract owner, lawful signatory and separately authenticated provider contact before sandbox traffic.

## Nonwaivable release state

The narrow isolated production dependency report and the locked inbound-graph inventory are useful **defense-in-depth containment evidence**, not vulnerability remediation, proof of no untrusted runtime globs, a global green audit or an approval to merge.

`productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Maintain `main` unchanged, PR #1 Draft/unmerged and Issue #2 OPEN. No production deployment, genuine quotes/POs/GRN/stock, finance/tax posting, customer messaging, live external trust-provider requests or supplier dispatch.
