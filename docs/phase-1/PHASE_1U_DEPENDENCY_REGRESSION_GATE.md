# Phase 1U — Dependency regression barrier and release hold

**State:** Development branch / Draft PR only. Phase 1T already documented 11 unresolved package advisories (1 critical, 3 high, 6 moderate, 1 low). **This change does not remediate or waive any of them.**

## Security rule now enforced by CI

New `scripts/check-dependency-baseline.mjs` compares the raw `bun audit --json` result, the independent normalized triage output and the explicit, checked-in `docs/security/dependency-advisory-baseline.json`.

- A previously unknown GitHub advisory ID, changed package association, or increased severity **fails development CI** until a security reviewer investigates and updates the reviewed baseline. Unparseable raw data, missing output and inconsistent triage likewise fail closed.
- Existing documented findings are visible as **still unresolved**. They do **not** become approved/accepted just because CI remains green. When an advisory disappears from the dependency audit, it is reported as `noLongerReported`; this is not proof that all attack paths are closed.
- `dependency-baseline-status.json` is uploaded with the raw advisory and triage artifacts. The status **always** contains `productionReleaseAuthorized:false` and `productionReleaseBlocked:true`, even if the audit returns zero advisories. No override, waiver, automatic release or production deployment action is offered.
- Unit tests cover a known critical finding, unexpected new findings, severity escalation, altered package mapping, tampered reports, duplicated baselines and an empty audit.
- Security baseline identifiers are source-recorded advisory IDs for the Phase 1T inventory. Its review date indicates this comparison point, **not a vulnerability fix or security certification**.

## Priority remediation work still blocking release

1. **Critical:** Investigate `proxy-addr` trust-proxy/IP-spoofing exposure, rate-limit `req.ip` assumptions and the exact patched dependency path. The current package advisory must not be suppressed.
2. **High:** Verify patched `body-parser`, `source-map-js` and `vite` versions, package reachability and impact on the deployed Express server and build.
3. **Moderate/low:** Review `qs` and remaining Vite advisories. Plan a reviewed lockfile update and rerun TypeScript, build, CI MySQL, Chromium login/MFA tests and preflight.
4. Security owner must approve actual vulnerability remediation with evidence; development baseline changes alone never satisfy this requirement.

## Other outstanding blockers

Real encrypted backup+restore, measured RTO/RPO, trusted staging TLS CA, device-level MFA, operational alerts, safe lost-device recovery, independent incident and privacy review remain unverified. No production DB migrations, customer messaging, invoicing, inventory or quote dispatch; HELD/DISABLED outbox and Draft PR are preserved.

**Release authority:** Nothing in this script or documentation authorizes merging, deploying, database deletion, user provisioning or external communications.
