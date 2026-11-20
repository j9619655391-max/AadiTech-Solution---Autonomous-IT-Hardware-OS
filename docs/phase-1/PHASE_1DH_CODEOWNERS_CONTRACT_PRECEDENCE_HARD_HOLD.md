# Phase 1DH — Phase 1CM/1DC/1DG CODEOWNERS contract repair and shadowing hardening (HARD HOLD)

Date: 20 November 2026 (IST). Correct GitHub repository: `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. Development branch: `chore/phase0-foundation-20261106`; no change to `main`.

## Specific reproducible defect

Before this phase, Phase 1CM's explicit two-user CODEOWNERS proposal (seven recognized rules: global wildcard, CODEOWNERS itself, workflow, docs/security, server/security, scripts and tests) was permitted by Phase 1DG's exact-main pinned Git-blob/nominee verifier, but **Phase 1DC only accepted a single noncomment wildcard rule**. Phase 1DF requires 1DC's `strictRootCoverageCodeownersFiles>0` before 1DG can accept the technical join. Consequently, an authorized administrator installing the actual 1CM proposed format could never satisfy that intended read-only operator chain. Meanwhile 1DC counted coverage across all three CODEOWNERS paths without respecting GitHub's first-existing-path precedence. Thus a malformed higher-priority `.github/CODEOWNERS` could be spuriously rescued by a valid lower-priority `CODEOWNERS` in the 1DC summary.

## Corrected engineering contract

Updated `scripts/phase1dc-live-external-governance-readiness.mjs` with exported strictly read-only helper `validOwners` and shared **seven-pattern recognized subset** `REVIEWED_CODEOWNER_PATTERNS`. This preserves the prior single-wildcard layout but also accepts the complete Phase 1CM multi-rule proposal **only** when:
- every noncomment line is exactly one unique member of the reviewed pattern allowlist followed by two distinct, nonauthor, syntactically valid GitHub usernames;
- the same two accounts (case insensitive; either order) occur on **every** rule;
- one unambiguous `*` line covers the root; no repeated pattern, unknown glob, inline override, extra owner or bypass-looking syntax;
- API payload has exact path, bounded canonical base64, proper declared size and syntactically valid SHA; decoded bytes are valid UTF-8 ASCII with no BOM, embedded control bytes or bare carriage returns.

**Important:** Phase 1DC's helper verifies **syntax only**; it intentionally does not certify the file's genuine Git SHA or authentic GitHub human roles. Phase 1DG independently verifies the actual Git blob SHA under the exact `main` commit, plus the specific nominees and double-read consistency. Phase 1CM proposal is not applied on GitHub; no admin change was performed.

The updated Phase 1DC CODEOWNERS scan applies GitHub precedence `.github/CODEOWNERS` then repository-root `CODEOWNERS` then `docs/CODEOWNERS`, and counts **at most one effective protected root file**. A higher-priority selected file with invalid/missing strict coverage is not rescued by a lower one. Inaccessible paths are fail-closed; **403 means UNKNOWN**, not an absent file. The prior `observedCodeownersFileCount` stays diagnostic only. Separate exact current-HEAD Security and Business approvals, actual role mandates, ruleset and branch protection remain independent gates.

## Adversarial regression

Added `tests/phase1dh-codeowners-contract.test.mjs` with **20 adversarial Node test groups**. Coverage: authentic Phase 1CM multi-rule rendering as a synthetic fixture consumed by Phase 1DC and Phase 1DG, earlier single wildcard compatibility, owner order/case, highest-precedence effective file, malformed top-file shadowing despite valid lower file, lower-path selection only when higher absent, 403 UNKNOWN, unmatched role/author, unknown glob, repeated override, no root wildcard, invalid base64/path/size/encoding, invalid UTF-8/BOM/control bytes, oversized/repeated lines, no GO from otherwise good technical syntax. Code/test registered in both Phase 1BV build-input source inventory and Phase 1BW human review source custody. The existing hosted Node test command picks up the new file. No workflow/permissions, GitHub mutation methods, or external release controls changed.

## Operator / acceptance limits

A real human operator must **not** run nominee-verification commands until Owner/Legal independently confirms genuine nonauthor Security and Business delegates, and a read-scoped `GITHUB_READ_TOKEN` is approved via a secrets manager. After an authorized administrator independently installs and verifies effective no-bypass main protection and base-main CODEOWNERS, the existing Phase 1DG human-only command can check the actual pinned file; this Phase 1DH code alone installs **nothing**. Synthetic self-issued/mock signatures, candidate user strings or passing green CI are not corporate appointments, staging acceptance or CA/MCA evidence.

At phase start actual GitHub readback: Draft PR #1 open/unmerged, Issue #2 OPEN, zero submitted PR approvals, zero listed rulesets, all three main CODEOWNERS locations 404 and direct main protection 403/UNKNOWN; genuine external CCA/RCAI/eMudhra/MCA, signed CRL/OCSP, CAS/WORM/DR, OIDC/SLSA and independent Security/Legal/Ops/Owner staging signoffs remain absent.

**Permanent release state:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No production deployment, merge, admin installation, provider credential, supplier/warehouse authorization, customer dispatch, stock or finance posting. Record official hosted push+PR CI only after the exact new development HEAD completes and its official Check Runs/Actions Jobs are reconciled.

