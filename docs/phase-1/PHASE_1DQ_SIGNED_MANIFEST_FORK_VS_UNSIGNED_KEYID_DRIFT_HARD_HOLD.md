# Phase 1DQ — Offline signed-manifest fork vs unsigned key-ID drift (HARD HOLD)

**No production authority.** This is a development-only correction to the offline Phase 1DP candidate detector. Draft PR #1 stays unmerged, Issue #2 open and `main` unmodified.

## Confirmed integrity gap

The Phase 1DO witness signing bytes include a role-separated canonical **manifest**. The derived checkpoint SHA-256 additionally hashes each witness's `keyId`, but that label is not signed by the witness. Consequently, two packets with the *same* dual-signed manifest, same public keys and signatures can produce different valid checkpoint digests merely by replacing a syntactically valid key-ID label. Phase 1DP previously reported any such differing checkpoint hashes as dual-signed same-sequence equivocation; that conclusion overstated what the signatures cryptographically bind.

## Correction

Phase 1DP validates all original scope, explicit UTC clock, sequence/predecessor, pinned distinct SPKI keys, both role-separated signatures and claimed checkpoint hashes before considering observations.

It now counts **domain-separated hashes of the actually signed canonical manifest** in addition to the checkpoint hashes. `DP_DUAL_SIGNED_SAME_SEQUENCE_EQUIVOCATION` and `sameSequenceConflictingDualSignedHeadsObservedOnly=true` require *different dual-signed manifests*. Different checkpoint digests with identical signed manifests set `DQ_CHECKPOINT_HASH_DRIFT_WITHOUT_SIGNED_MANIFEST_FORK`; different unsigned key labels set `DQ_UNBOUND_WITNESS_KEY_ID_METADATA_DRIFT`. A mixed true manifest fork with key-ID tampering reports both; invalid signatures and forged checkpoint claims never enter the validated set. Duplicate packets cannot prove independent publication.

No output reveals nonce, registry digest, witness PEM/signatures or checkpoint hash. A structurally correct mathematical result remains untrusted because comparison pins, witness origins, clock and previous checkpoint are caller supplied.

## Test and provenance

Six adversarial regression groups were added to the existing Phase 1DP test suite: unchanged replay, key-ID-only forged fork, real signed payload fork with relabeling, invalid signature, mixed three-packet evidence and output secrecy/HARD HOLD. This **existing** source/test pair is already in the 1BV build-input and 1BW review-vendor inventories. Both GitHub push and PR exact-head CI runs must be verified after commit; green prior SHA is insufficient.

## External follow-up and immovable holds

A future versioned signature envelope must cryptographically bind witness `keyId` and require an independently authenticated key registry/source provenance. Do not mutate historic v1 signatures in place. Real MCA/legal registrars, Security/Business appointment approvals, CCA/RCAI/eMudhra provider and revocation evidence, independently trusted time, WORM/CAS/DR/OIDC/SLSA, enforced main branch governance, human staging approvals remain unverified.

**Immutable:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No main branch changes, deployment, provider enrollment, stock/finance/tax posting, external communications or reviewer requests.
