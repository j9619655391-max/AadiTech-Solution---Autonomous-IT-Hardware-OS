# Phase 1DS — Cross-signed offline witness-key rollover (HARD HOLD)

**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` · development branch `chore/phase0-foundation-20261106` · PR #1 Draft/unmerged · Issue #2 OPEN · production **HARD HOLD**.

## Why this exists

Phase 1DR signs witness key IDs and SPKI hashes inside role-separated Ed25519 v2 envelopes. A changed *validly re-signed* identity is correctly classified as a signed identity fork, not automatically treated as legitimate rotation. There was no explicit candidate handover ceremony to distinguish a four-party mathematical co-signature from a changed label. Phase 1DS provides this **strictly offline, non-authoritative** transition *candidate* check; it does not authorize or perform rollover.

## Candidate contract

`scripts/phase1ds-offline-witness-key-rollover.mjs` compares 2–8 bounded candidate packets against **caller-supplied, untrusted** previous identity pins, exact source/main SHA, organization, previous sequence/checkpoint and declared next candidate checkpoint digest plus explicit canonical UTC time. Every packet contains a versioned, HOLD-only manifest, exact identities for LEGAL_WITNESS and REGISTRY_WITNESS, each role's *previous* and *next* Ed25519 public key attestations, and a claimed transition digest.

Four role-and-step-domain-separated Ed25519 signatures each cover the **entire identical manifest and four identities**; no partial rotation or key substitution is accepted. Each PEM must cryptographically match the claimed SPKI SHA-256; all four key IDs and SPKI digests must be distinct and the old identity must match the caller's pinned predecessor. New sequence must equal previous+1, previous checkpoint must match, expiry is bounded to 15 minutes and production decision must be HOLD. Duplicate packets never count as independent witnesses. Different valid fully cross-signed transitions at the same predecessor trigger signed-fork quarantine; same nonce across such a fork receives a separate warning. Invalid signatures, unsigned key relabels, GO, stale times, rollback, wrong role, pin collisions, claimed digest drift and unknown fields fail closed. Incident recovery is independently quarantined even when all four candidate signatures verify.

No code path registers, rotates, revokes or publishes a real key, moves a Git ref, posts a business transaction or changes reviewer/production state. **No signed next Phase 1DR checkpoint is actually fetched or independently checked:** its hash is a caller-supplied claim, not a verified external receipt. A co-signature under potentially compromised old private keys is not genuine recovery mandate. Historical Phase 1DO v1 and Phase 1DR v2 signing domains remain untouched.

## Engineering acceptance and honest boundary

`tests/phase1ds-offline-witness-key-rollover.test.mjs` covers cryptographic four-party candidate signatures, unsigned drift, properly re-signed fork, nonce reuse, tamper/GO, role swaps, key collision, predecessor and source rollback, clock failures, incident recovery quarantine, digest/signature forgery, domain separation, observation bounds, privacy and immutable HOLD. Paths are inventoried by Phase 1BV and 1BW for CI source custody.

Final source+docs HEAD requires independently verified **both** GitHub push and pull_request CI successful with all required jobs and exact source SHA. A skipped PR-only source lineage job on push is not a success. Historical failing CI runs must remain historically failing.

**External acceptance not established:** real MCA corporate/signatory records, genuine Legal/Registry witness key enrollment, independently authenticated revocation/rollover authority, WORM/CAS/DR published predecessor, trusted time/origin, exact-head nonauthor review and no-admin-bypass protected main, authorized CCA/RCAI/eMudhra live cert/CRL/OCSP, OIDC/SLSA and independent staging signatures are pending. Supply provider credentials only via approved secrets management; never in chat or Git.

**Immutable HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No main merge, production deployment, external provider activation, PO/GRN, dispatch, finance/stock/tax postings or reviewer requests.
