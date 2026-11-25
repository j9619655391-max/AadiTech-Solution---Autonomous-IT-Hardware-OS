# Phase 1CA — CI job scope, YAML shadowing, runner and expression drift HARD HOLD

**Date:** 18 November 2026 (IST).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`.  
**Engineering branch:** `chore/phase0-foundation-20261106`; `main` remains out of scope, PR #1 remains Draft/unmerged and Issue #2 OPEN.

## Objective and actual engineering

Phase 1BZ had already pinned 20 action references to three exact observed full-length GitHub Action commit IDs and required a single `.github/workflows/ci.yml` file. It did not fully address semantic YAML shadowing or job-level permission drift. Phase 1CA extends its **existing** deny-only `scripts/phase1bz-actions-pin-preflight.mjs --ci-hold` gate, without creating an exception to the dependency advisory gate.

The added bounded `phase1caWorkflowShapeAnomalies` rejects:
- duplicate, missing, inline or unexpected root keys; trigger shadowing; and any departure from the read-only global `contents: read` scope;
- altered names/order of all eight reviewed jobs, unreviewed extra jobs, missing step containers, runner image changes away from `ubuntu-24.04`, and absent/unbounded job timeouts;
- any job-level token override other than the **existing exact** read-only scopes of the live GitHub governance observer and PR source-merge lineage job;
- changed PR-only merge-lineage execution condition, newly inserted job skip conditions, fail-open `continue-on-error`, job containers/environments, YAML tabs and selected tag/merge forms;
- extra GitHub expression interpolations or changed values outside the three reviewed read-only GitHub observer bindings for the token and exact PR head/base SHAs.

Seven added adversarial test blocks in `tests/phase1bz-actions-pin.test.mjs` check duplicate keys, scoped token privilege escalations, jobs/runner changes, condition bypass, new expressions, YAML ambiguity and retained hard-HOLD output. The standalone pure shape function was exercised against the checked-in workflow and 16 representative mutated strings: 0 issues on the unchanged workflow, and rejection of each mutation. The complete hosted test and CI status **must still be inspected**; local source checks are not equivalent to independently verified CI.

A source-edit generation mistake in the initial Phase 1CA commit caused duplicate code sections. This was corrected immediately by rebuilding the script from the exact pre-edit source, checking that it contains exactly one validator and one CLI entrypoint, and re-running 16 mutation checks on the fixed code. **Only the final fixed head should be evaluated for acceptance**, and no earlier intermediate commit should be treated as valid.

## Security boundary and limitations

This verifier uses bounded source-line checks, **not** a full YAML semantics implementation, independent review of actions' actual publisher identities, pinned immutable runner images, independent OIDC workload signature or externally witnessed in-toto/SLSA provenance. A PR contributor may edit both this source and its tests unless actual server-side protection and independent reviewer approvals are enforced. The `mysql:8.0` service image and GitHub-hosted `ubuntu-24.04` label remain mutable infrastructure dependencies, not independently digest-pinned attestations. The unsigned report `phase1bz-actions-pin-hold.json` and Phase 1BV bundle never constitute a production signature or WORM receipt.

**Unresolved mandatory controls:** independently authenticated repository admin ruleset/CODEOWNERS, distinct post-head Security and business approvals, signed CI run/source identity, immutable external WORM/DR witnessed evidence, real upstream-approved remediation of `picomatch@4.0.7` `GHSA-fc5q-39xc-vjpf` (CVE-2026-112366) and strict zero Critical/High audit, actual CCA/RCAI/eMudhra sandbox contract and signed CRL/OCSP, MCA/GST authorized signatories, approved staging and separate release signoffs.

**Hard release decision:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep PR Draft/unmerged, Issue #2 open, and `main` unchanged. No live quotes, supplier purchase orders, GRN or inventory movements, finance/tax postings, customer messaging, live provider API access or production deployment.
