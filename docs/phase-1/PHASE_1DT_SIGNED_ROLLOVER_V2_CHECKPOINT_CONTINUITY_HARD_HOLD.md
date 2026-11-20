# Phase 1DT — Offline signed rollover → next v2 checkpoint continuity (HARD HOLD)

**Scope:** `chore/phase0-foundation-20261106` development branch in `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; PR #1 Draft/unmerged; Issue #2 open; production **HARD HOLD**.

## Gap closed at the mathematical layer (not external authority)
Phase 1DS authenticates four Ed25519 role/step signatures across *candidate* old-to-new witness identities, but its next v2 checkpoint digest is a caller-provided claim. Phase 1DT **does not trust that digest alone**: `scripts/phase1dt-offline-rollover-checkpoint-continuity.mjs` accepts 2–8 offline 1DS transition candidates and 2–8 offline v2 checkpoint envelopes. It invokes the existing Phase 1DS and Phase 1DR validators unchanged, requires a single fully signed non-forked transition, compares the new LEGAL/REGISTRY key IDs **and** SPKI digests to the v2 signed witnesses, independently recalculates and validates both v2 witness signatures and checkpoint claims through Phase 1DR, and matches all verified checkpoint digests to the four-way signed transition claim. Exact source/organization/main SHA, previous sequence and checkpoint, explicit UTC time and expiry must agree.

Duplicate copies can show a mathematical link, **never independent publication or a quorum**. Valid signed transition forks, valid signed v2 manifest/identity forks, swapped or replaced keys, unsigned relabeling, tampered digest, rollback, missing/wrong clock, recovery without real mandate, version-v1 reinterpretation and forged GO are denied. Output includes only bounded summary counts and anomaly codes, excluding raw PEM, signatures, private keys and key IDs. No production or key-enrollment code paths exist.

## Verification and limits
`tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs` contains 15 adversarial Node test groups. Both Phase 1BV build-input and 1BW reviewer custody inventories include the new script and test. Existing Phase 1DR/1DS cryptographic domains and historical signatures are unchanged.

All observations, predecessor pins, source heads, role identities, clock and signed candidate bytes can still be supplied by the same untrusted applicant. Passing these mathematical checks **does not establish independent signatory identity, legal authority, trusted publication, transparency consistency across real observers, WORM/CAS/DR, revocation, trusted time, or incident-recovery mandate**. Genuine MCA/CCA/RCAI/eMudhra, protected-main nonauthor reviewers, OIDC/SLSA and independently signed staging remain unresolved.

**CI receipt:** exact final documentation-inclusive HEAD push and PR Actions must both complete and be checked after GitHub push; this document does not pre-certify future results.

**No exception:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No merge to main, provider credentials, deployment, real financial/stock/quote/customer or supplier actions.
