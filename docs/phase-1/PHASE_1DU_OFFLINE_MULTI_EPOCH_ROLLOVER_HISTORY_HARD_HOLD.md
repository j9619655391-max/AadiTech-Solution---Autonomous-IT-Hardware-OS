# Phase 1DU — Offline multi-epoch signed rollover history continuity (HARD HOLD)

**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Engineering ref:** `chore/phase0-foundation-20261106`  
**Governance:** PR #1 remains Draft/open/unmerged; Issue #2 open; main unchanged. No production activation.

## Narrow mathematical gap

Phase 1DT checks one four-way Phase 1DS witness rotation against a fully dual-signed Phase 1DR next-v2 checkpoint. It does not by itself guarantee that several individually matching candidate checkpoints form a single consecutive history. Phase 1DU adds `scripts/phase1du-offline-multi-epoch-rollover-chain.mjs` and `assessOfflineMultiEpochRolloverChain`: a **pure, offline, read-only, deny-only** reconciliation of 2–6 consecutive 1DT steps.

Each epoch supplies exactly the five untrusted Phase 1DT inputs `transitionCandidates`, `checkpointObservations`, `expected`, `previousIdentityPins`, `comparisonPins`; the top level supplies exactly `epochs` and explicit `now`. Inputs are bounded to 512 KiB aggregate. The evaluator invokes unchanged 1DT crypto checks on **every epoch**, not trusting a stored success summary. Once verified, every next epoch must extend the preceding *verified* v2 checkpoint digest and sequence, match previous dual-signed LEGAL/REGISTRY key IDs **and** SPKI digests, keep organization/source/main pins fixed and preserve signed chronological order. A reused signed transition digest, checkpoint digest or signed rotation/checkpoint nonce across epochs quarantines the history. Invalid, reordered, skipped, replayed, tampered or schema-extended histories cannot become an authenticated chain. A failed earlier epoch cannot be skipped to restart counting later ones.

The report contains bounded counts, boolean mathematical result and anomaly codes only; no signature, PEM, private key, raw witness key ID or nonce is reported. `consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly=true` is **not** a GO, enrollment decision, independent publication or acceptance of the applicant-provided starting checkpoint.

## Verification scope and adversarial coverage

Fifteen synthetic 1DU adversarial tests share the real Ed25519 fixture generation in `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`; the pre-existing fifteen 1DT groups remain unchanged. Tests exercise a correct two-epoch chain, swapped history, fully signed rogue predecessor keys, validly signed repeated cross-epoch nonces and time-order drift, duplicate signed epochs, wrong predecessor digest, previous key-ID drift, altered later signature bytes, partial packet sets, no skip after first-epoch failure, added approval fields, missing/stale clock, malformed/over-bounded history and response redaction/HOLD. These are **generated test keys**, never government-issued or independently entrusted witnesses.

Both Phase 1BV build-input and Phase 1BW reviewer source-custody inventories include the Phase 1DU verifier. Run local regression with:

```bash
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

Follow with exact-final-HEAD GitHub push and PR CI job verification. This runbook does **not** pre-certify unobserved hosted runs, identity, supply chain or independent release approval.

## Authority and deployment boundaries

The first checkpoint and all later packets may be authored by a single adversarial applicant. Sequence/digest continuity cannot prove an independent transparency observer, immutable off-platform WORM/CAS checkpoint, externally certified time, authenticated legal witnesses, lawful corporate appointment, live trusted revocation, incident mandate, original officer/GitHub session or recovery authorization. No main ruleset/CODEOWNERS/non-author quorum, genuine MCA/CCA/RCAI/eMudhra certificate-chain + signed live CRL/OCSP, OIDC/SLSA, real staging Security/Legal/Ops/Owner, independent backup/DR acceptance or production release is established by this phase.

**Immutable result:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. No main merge, provider key enrollment, admin policy change, real credentials, customer/supplier dispatch, PO/GRN, finance/tax/stock posting or deployment.
