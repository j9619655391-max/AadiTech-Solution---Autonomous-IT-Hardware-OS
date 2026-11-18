# Phase 1CK — Real Picomatch fixed-pattern bounded worker observations, full-lock audit, and independent security adjudication HOLD

**Date:** 18 November 2026 (Asia/Kolkata). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; dev branch `chore/phase0-foundation-20261106`; `main` unchanged; PR #1 Draft/open/unmerged; Issue #2 OPEN.

## Unresolved public security evidence

The official GitHub Advisory Database withdrew `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366` on **18 November 2026**. The advisory page still lists its historical Picomatch **4.0.7** affected range and no upstream patched version; OSV and NVD preserve the CVE record. The latest observed official npm publication remains `picomatch@4.0.7`. Phase 1CJ's exact-head CI also found that the real full-lock `bun audit` **still reports one High**, even after the GitHub advisory withdrawal. The GHSA withdrawal is neither a vendor patch nor a signed independent security adjudication; a positive alert is not automatic proof that every deployed call path is exploitable.

Public sources for human review:
- https://github.com/advisories/GHSA-fc5q-39xc-vjpf
- https://osv.dev/vulnerability/GHSA-fc5q-39xc-vjpf
- https://nvd.nist.gov/vuln/detail/CVE-2026-112366
- https://github.com/micromatch/picomatch/pull/235

## Material Phase 1CK engineering capability

The previous phases built advisory/state observers and identified the actual Bun lock introduction routes `vite -> picomatch`, `vite -> tinyglobby -> picomatch` and an optional `fdir` peer, with production-only Bun dependency isolation. The 1CK code adds a **different measurable observation**: a local, disposable, **actually installed** locked Picomatch `4.0.7` matcher is evaluated on tiny, literal, advisory-inspired inputs in a separate Node worker, with a hard parent-controlled deadline.

**Scope, safety, and interpretation:**

- `scripts/phase1ck-picomatch-worker.cjs` defines **three immutable tiny cases**: a plain literal/glob control `alpha*`, and the published potentially risky repeated extglobs `+(*)` and `+(*a)`. Input strings are **at most 12 characters**, deliberately too short to independently establish practical catastrophic-backtracking exploitability. No dynamic pattern, external URL, user-controllable input or credential enters the worker.
- `scripts/phase1ck-picomatch-bounded-adjudication.mjs` invokes only those reviewed case IDs under a **2,000-ms wall-clock deadline per worker**, with small V8 resource limits. A completed sample records Boolean match, package version and elapsed matching time; a terminated worker records `TIMEOUT`. Unexpected worker error, wrong version, malformed output, changed case ID or invalid clock/data causes the new *structural* check to fail. Timeout indicates a bounded observation requiring further analysis, **not** confirmed exploitability.
- The CLI accepts only `--ci-hold` and runs in the existing `baseline` job **after** the actual frozen `bun install`, real complete `bun audit --json` and raw-to-normalized dependency triage, but **before** the mandatory `check-dependency-baseline` and `verify-patched-dependencies` gates. It checks the frozen Bun lock version/integrity and sorted root dependency constraints, actual GitHub checkout SHA/ref/repository/job context, whole-lock advisory severity counts, raw-vs-triage consistency and the individual worker receipts. It never edits the lock, replaces the upstream vendor package, injects overrides, skips a high-risk category, or alters `bun audit`/mandatory zero Critical–High–unknown security enforcement.
- The output `phase1ck-real-picomatch-bounded-worker-hold.json` is added to the **existing** dependency audit artifact. It is a **locally produced UNSIGNED** technical observation. In particular, three short finite-time runs cannot prove no exponential blow-up on longer strings, no attacker-controlled pattern reachability, or a safe upstream patched release. Even a later truly zero-High audit is **not** a production decision without separately authenticated independent reviewer, provider, legal, external witness and staging evidence.
- `tests/phase1ck-picomatch-bounded-adjudication.test.mjs` adds **15 adversarial Node regression groups** including one actual isolated worker control in the installed dependency environment and other bounded synthetic report-shape tests, tampered global audit and normalized triage, false safe-on-withdrawal, arbitrary pattern, timeout vs success confusion, forged version, package version and tarball integrity drift, wrong GitHub job, root lock mismatch and attempted release GO.

Source custody: Phase 1BV and 1BW selected-source hashes now cover the new worker, bounded sampling orchestrator and test file; GitHub Actions remains the same eight SHA-pinned read-only jobs. No external authority, secret, endpoint, write permission or production operations were enabled.

## Independent acceptance evidence needed to close the risk

| Gate / accountable party | Independently verifiable evidence | Status |
| --- | --- | --- |
| Upstream publisher | Authenticated technical explanation/maintainer position on the withdrawn advisory and `picomatch` patterns, published source tag, reproducible behavior or real safe vendor release with independently verified npm publisher provenance/tarball | **PENDING** |
| Security engineering | Separately authorized reviewer runs a *full* bounded, isolated reproduction and safe-vs-unsafe revision comparison, identifies actual application entrypoints and attacker-input control, determines effect of Vite dev isolation, records clear signed risk decision on exact source HEAD | **PENDING** |
| Dependency/CI security | `bun audit --json` over entire actual frozen lock with zero Critical/High/unknown and corroborated GHSA/CVE/OSV dispositions, reviewed source integrity/lock changes, full JS/TS/staging/MySQL/Chromium regressions | **PENDING; DO NOT WAIVE** |
| Repository owner + business | Effective protected `main` branch rules, CODEOWNERS, latest-HEAD two distinct nonauthor Security/business approvals, no bypass and signed CI provenance | **PENDING** |
| Provider/legal | eMudhra-approved sandbox agreement, genuine CCA/RCAI trust policy + authenticated CRL/OCSP, verified MCA/GST corporate legal/signatory approvals and independent staging OWNER/SECURITY/LEGAL/OPS | **PENDING** |
| Storage/trust operators | Independently enrolled, rotated/revocable witness/reviewer keys, authentic immutable WORM version/retention/deletion denial, offsite DR restore, signed monotonic remote checkpoint/fork evidence | **PENDING** |

No user-provided credentials, private signatory keys or provider tokens should be posted to chat, CI logs, GitHub or these documents. A withdrawn advisory or short local timing evidence never confers authority to merge or deploy.

**NONNEGOTIABLE:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. `main` unchanged, PR #1 Draft/unmerged, Issue #2 OPEN, no live external provider/customer/supplier, financial, tax or stock operations.
