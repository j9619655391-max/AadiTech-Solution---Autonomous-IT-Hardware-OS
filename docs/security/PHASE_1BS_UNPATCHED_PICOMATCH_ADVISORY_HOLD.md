# Phase 1BS dependency advisory triage — unpatched picomatch ReDoS

**Date reviewed (technical triage only):** 17 November 2026 (UTC/IST)  
**Status:** KNOWN UNRESOLVED, independent security approval PENDING.  
**Environment:** Draft, unmerged, disposable CI / isolated approved staging only; **production HARD HOLD**.

## Finding

GitHub Actions [run #44136778343](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44136778343) triggered the `Block unreviewed new or escalated dependency advisories` gate. The exact `bun audit --json` summary was **one High** newly surfaced advisory **GHSA-fc5q-39xc-vjpf** for `picomatch`. This alert was not caused by the new BS certificate code; the existing immutable `bun.lock` already included `picomatch@4.0.7` through **Vite** (`^4.0.2`) and **tinyglobby** (`^4.0.4`). The advisory was updated 17 November 2026; GitHub currently lists **affected versions through 4.0.7** and **no patched versions** for CVE-2026-112366: <https://github.com/advisories/GHSA-fc5q-39xc-vjpf>.

The issue concerns ReDoS on attacker-controlled repeated single-branch extglob patterns. The dependency is part of build/glob tooling. **Runtime reachability was not independently established or conclusively ruled out.** There is no verified supported patched release to upgrade to as of this technical triage. No dependency upgrade or security patch has been applied, and a local bypass or speculative unreviewed dependency override is prohibited.

## Disposition without silent waiver

`docs/security/dependency-advisory-baseline.json` now explicitly identifies `GHSA-fc5q-39xc-vjpf` / `picomatch` / `high` as **known unresolved development-only** with `independentSecurityApproval=PENDING`. This makes any renewed difference/escalation fail the baseline checker, while the baseline checker **never authorizes production**. This does **not** constitute independent Security, Legal, Operations or owner signoff. The pipeline's triage report must continue to show `requiresManualSecurityApproval=true`; production continues blocked.

**Independent security work required:** identify which Vite/tinyglobby glob inputs, if any, are accessible to untrusted customers, update to a vendor-confirmed patched release when published, regenerate/checksum-lock `bun.lock`, review exposure and run full baseline, MySQL and browser smoke, obtain independently documented Security acceptance. Do not interpret a green development baseline as evidence that the vulnerability is remediated.

**Production gating remains unchanged:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; PR #1 stays Draft/unmerged, Issue #2 open, `main` unchanged, no quote issuance, procurement dispatch, inventory, finance, tax or live provider integration.
