# Phase 1BC — Local witness head custody, source-of-truth enrollment hold and independent acceptance gates

**Engineering status:** Offline/isolated-CI-only signature, Merkle and candidate-custody hardening. **Genuine external witness enrollment: NOT AUTHENTICATED.** **Production: HARD HOLD.**

**Correct repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, development branch `chore/phase0-foundation-20261106`. PR #1 remains Draft/unmerged, Issue #2 remains open and `main` is unchanged.

## Context and scope

The Phase 1BA/1BB modules already inspect candidate Ed25519 signed heads, Merkle **inclusion plus consistency**, witness/ref/key associations and offline digest-only source attestations. Phase 1BC adds a **locally durable, fail-closed history** of accepted untrusted tree heads, making split views, rollback, undocumented self-proclaimed key changes, and altered predecessor claims visible to the disposable staging/CI review system.

The Phase 1BC *external-adapter protocol* and its HOLD preflight are complementary offline interfaces. Neither interface may be used to claim verified external provider authority or operate external systems.

## Implemented engineering controls

1. `scripts/lib/phase1BcWitnessCustody.mjs`: invokes the existing Phase 1BB RFC 6962 consistency/inclusion and signature assessor over **all claimed witness organizations**. Requires every head to bind the same Phase 1AZ packet SHA-256, checkpoint receipt, archive object, log identity and candidate SPKI/admin refs. Insists on strict growth from an old tree size to a new tree size (equal-size 're-sign' is not a fresh append-only extension).
2. Local key-set commitment: SHA-256 of the canonically ordered witness ref, organization ref, claimed administrator ref and Ed25519 SPKI fingerprint. Accepting one self-supplied pin set **does not authenticate its independent custody**. New pins never inherit authority from the former set automatically.
3. Local signed-evidence commitment: SHA-256 over the Phase 1AZ packet hash, both tree heads, canonical sorted signed witness observations, inclusion proof nodes and consistency proof nodes. Raw proofs, PEMs, private keys, legal documents, contracts, cloud objects, provider credentials, signed data or request content are **not persisted** in the Phase 1BC database.
4. `database/migrations/0031_bc_witness_continuity_holds.sql`: InnoDB per-log candidate head and forensic observation history with `external_source_authenticated=NO`, `independent_key_custody_verified=NO`, `immutable_worm_retention_verified=NO` and `production_release=HOLD` constrained by ENUM values.
5. `scripts/migrate-bc-witness-continuity.ts`: migration registry/count and exact SHA-256 checksum verification of migrations 0001–0030, advisory migration mutex and idempotent schema rerun; targets only disposable `aaditech_ci` or explicitly approved isolated TLS staging with a restricted name. Production targets are refused.
6. `server/witnessCustody/durable.ts`: before recording a witness head, locks and verifies an **existing, unquarantined Phase 1AZ local readiness stream** with an exactly matching packet SHA-256. It then transactionally locks the Phase 1BC head and accepts either an untrusted genesis observation or a monotonic extension that reuses its stored last size/root and witness candidate pin set. Exact latest replay is idempotent. A same-size different root is a fork; older head is rollback; nonmatching historical predecessor is an incident; a new witness key set or changed AZ packet requires quarantine and separate review; after incident no automatic recovery or release is allowed.
7. `inspectPhase1BcWitnessCustody`: readback consistency checks for accepted Merkle-head chain, persisted SHA-256 fields, key-set continuity, last head and incident/quarantine agreement. Internal MySQL is **not** immutable WORM and the stored hashes cannot independently re-validate original signed proofs. Operators with elevated DB privileges may alter/remove rows; external immutable audit remains required.
8. `scripts/lib/stagingPreflight.ts`: read-only Phase 1BC counters, illegal external-trust/release state denial, staging unresolved-fork blocking and explicit `NOT_VERIFIED` external source/pin/real archive/DR gates.
9. `tests/support/phase1bcFixture.mjs`, `tests/phase1bc-witness-custody.test.mjs`, `tests/bc-witness-mysql.integration.ts`: independent deterministic Merkle fixtures, signed split views, complete proofs, multi-witness pin fingerprints, AZ packet substitution, forbidden release flags, concurrent forks, rollback replay, unlinked predecessor, unauthorized key changes, broken head readback, invalid signed claims and only-disposable-CI operation.
10. `scripts/phase1bc-witness-custody-preflight.mjs`: zero-input `--ci-hold` only, no network/credentials. CI validates the HOLD invariant, applies/reruns migration 0031 and executes the real disposable MySQL suite. `tests/release-candidate.test.ts` includes migration 0031 in its deterministic candidate manifest and `tests/staging-preflight.test.ts` checks the updated migration registry.

## Genuine external acceptance required before **any** production trust

- Legal signoff for the specific provider/vendor, service, company and authorized signatory via independently verified MCA records and authenticated provider contract. Public reference documentation is not authorized access; credentials must enter only through an approved secret manager, **never chat or Git**.
- Out-of-band independently authenticated witness organizations, custody attestations, current public SPKI keys and key revocation/rotation policy; direct verification of witnessed provider-issued tree heads through independently trusted channels, not an applicant-uploaded PEM.
- At least two truly independently administered transparency witnesses with independently published append-only roots and tested gossip/split-view alerts; trusted time source, revocation and emergency quarantine distribution.
- Real provider-verified compliant WORM/Object Lock versioning, deletion/overwrite denial and retention/legal-hold evidence with immutable administrative audit; no local MySQL/CI record may be presented as equivalent external retention.
- Approved encryption/KMS stewardship, actual encrypted backup restoration to **fresh isolated staging**, independently measured RTO/RPO, checkpoint revocation continuity, verified HTTPS/MFA, separate signed owner/security/operations DR acceptance.
- Independently authenticated RCAI/CCA/eMudhra PKIX chains, certificate policies and active CRL/OCSP and corporate/signatory legal evidence. Synthetic chain fixtures cannot become a trusted legal certificate hierarchy.

## RELEASE HOLD policy

All Phase 1BC paths explicitly return `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. A correct or repeatably verified internal signature/proof **is not evidence of real external authorization**.

This phase does **not** enroll an external witness, configure provider credentials, create a real WORM bucket, run an encrypted cloud restore, provision a live signing key, deploy production, post stock/finance journals, release supplier dispatch or merge the draft PR.

**Acceptance evidence for internal engineering only:** latest branch commit plus both successful GitHub Actions baseline and disposable-MySQL jobs. Confirm those results before saying 'CI passed'.
