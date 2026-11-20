# Phase 1DP — Offline registrar-witness equivocation quarantine (HARD HOLD)

**Engineering scope:** Candidate-only, local mathematical signature assessment; no external enrollment or live proof. Source repository: `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, development branch `chore/phase0-foundation-20261106`. PR #1 must remain Draft/unmerged; Issue #2 stays open and `main` must not be changed.

## Why this phase exists

An attacker can present two distinct next-checkpoint heads for the same sequence and predecessor, each bearing mathematically valid signatures from the two pinned candidate witness roles. Phase 1DP detects such a same-sequence fork and **quarantines the candidate** rather than selecting a winner. It never treats copied receipts as proof of independent publication. If one packet has an invalid signature, the packet fails verification: the discrepancy alone is not authenticated proof of actual witness equivocation.

All candidate witness keys, observation origins, comparison pins and clock values are caller supplied and may be colluding or forged. A mathematical signature check can never independently establish legal identity, corporate authority, live revocation status or WORM publication.

## Implementation and security invariants

- `scripts/phase1dp-offline-registrar-witness-equivocation.mjs` provides `assessRegistrarWitnessEquivocationCandidate` and recomputes domain-separated dual-role Ed25519 evidence against explicit source/organization/sequence/previous-checkpoint pins. Only validated packet digests enter fork comparison.
- A detected dual-signed head conflict remains **HOLD**; duplicates, incomplete observation sets, key collisions, swapped roles, tampering, misbound source pins, missing or malformed explicit clock, invalid validity windows, rollback/predecessor forks, claimed digest mismatch, unknown extra fields and forged GO all fail closed.
- The result excludes raw nonce, key PEMs, signatures and registry evidence; it does not perform network requests, files writes, real reviewer requests, provider approvals, state transitions, CAS or external persistence.
- `tests/phase1dp-offline-registrar-witness-equivocation.test.mjs` has **18 adversarial Node test groups**, including dual-signed fork detection, replay/duplicate handling, unsigned-manifest mismatch, witness-role substitution/collision, source and pinned context mismatch, genesis/sequence/predecessor integrity, clock and validity, digest/GO/unknown-field injection, observation limits, redacted outputs and no-side-effects verification.
- The detector and test are explicitly listed in both `scripts/phase1bv-build-input-provenance.mjs` and `scripts/phase1bw-review-vendor-intake.mjs` build/reviewer input inventories.

## Verification acceptance criteria

1. The exact final development-branch commit must contain both source/test files, this document, the master completion-plan entry and both updated inventories.
2. GitHub Actions **push and pull_request** workflow runs must each report `status=completed`, `conclusion=success`, `head_sha` equal to the same final commit; verify individual required jobs/steps, not just the workflow conclusion. An expected skip must not be counted as pass.
3. If any run/job remains queued, in-progress, stale-SHA or contradictory, CI remains unverified; record exceptions and keep the release blocked.
4. Maintain PR #1 Draft/unmerged, Issue #2 open, `main` unchanged; no production deployment.

## Open external-authority and deployment blockers

Real independently authenticated MCA legal company/signatory evidence; provider-approved RCAI/CCA/eMudhra credentials, certificate hierarchy and live signed CRL/OCSP; trusted witness-key custody/enrollment and independent origin attribution; genuine time, append-only WORM publication, compare-and-swap and disaster-recovery proofs; protected branch release governance; independently authenticated Security/Business/Legal/Ops review and staging acceptance; OIDC/SLSA provenance. These cannot be created or approved by synthetic tests or a code-only change.

**Release decision: HARD HOLD.** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. No merge, release, provider activation or state-changing business action.
