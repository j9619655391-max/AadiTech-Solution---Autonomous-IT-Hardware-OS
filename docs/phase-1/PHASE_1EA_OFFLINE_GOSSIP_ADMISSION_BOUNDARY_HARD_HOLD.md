# Phase 1EA — Offline three-peer gossip consistency and external-admission HOLD boundary

**Date:** 21 November 2026 IST. **Canonical GitHub repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`. PR #1 remains **OPEN/DRAFT/UNMERGED**, Issue #2 **OPEN**, `main` unchanged.

## What the code can and cannot prove

`scripts/phase1ea-offline-gossip-admission-boundary.mjs` is a pure, deterministic, read-only evaluator for **applicant-provided packets and time**. It re-verifies the original Phase 1DZ cross-epoch signed history, 1DY five-reviewer freeze statements, 1DX frozen incident claims, 1DW revocation claims, 1DV archive observer statements and 1DU signed Legal/Registry witness history. It then compares **three locally supplied, role-signed claimed gossip snapshots** of the same entire 2–4-epoch archive chain and demands two further separately signed, explicit **NO-AUTHORITY freeze** attestations. It is a mathematical *consistency and negative-admission* exercise, **not** genuine independently authenticated publisher/gossip enrollment, external trust, production approval, anti-equivocation network gossip, durable cursor/verified WORM, or incident unfreeze.

The exported API:
- `assessOfflineGossipAdmissionBoundaryEa(args)` — checks exact bounded inputs and ALWAYS returns `releaseDecision='HOLD'`.
- `candidateEpochViewEa(anchorCandidate)` — extract canonical original source vector; cannot be used as trusted source outside the top-level re-verification.
- `epochViewDigestEa(epochVector)`, `peerSigningBytesEa(role,statement)`, `peerQuorumDigestEa(orderedStatements)`, `admissionClaimDigestEa(claim)`, `freezeSigningBytesEa(role,statement)` — exact-schema, SHA-256 domain-separated or Ed25519 signature messages.
- `EA_PEER_ROLES`: `ARCHIVE_GOSSIP_PEER`, `REGISTRY_GOSSIP_PEER`, `RECOVERY_GOSSIP_PEER`.
- `EA_FREEZE_ROLES`: `LEGAL_GOSSIP_FREEZE_REVIEW`, `SECURITY_GOSSIP_FREEZE_REVIEW`.

## Exact input and mathematical checks

```js
assessOfflineGossipAdmissionBoundaryEa({
  anchorCandidate,      // all original 1DZ/1DY/1DX/1DW/1DV/1DU packets
  previousGossipCursor, // applicant-supplied sequence/hash/time, exactly equals 1DZ previous anchor
  admissionClaim,       // EXACT offline-not-authenticated, all seven approval flags FALSE
  peerPins,             // exactly three detached claimed key/SPKI/operator/org pins
  peerPackets,          // exactly three role-signed complete epoch vectors
  freezePins,           // two separate Legal/Security claimed key/org pins
  freezePackets,        // two signed CONTINUE_FREEZE_NO_AUTHORITY statements
  now                   // explicit UTC clock submitted by caller, NOT trusted
});
```

The whole packet must fit within **2.5 MiB**; exact domain-separated view format holds 2–4 ordered entries and maximum **8 KiB**, and signed statements and packets must remain bounded. A view entry contains sequence, previousSequence, predecessor anchor digest, current anchor digest, hash of original epoch nonce, and canonical UTC observation. Every peer must sign its own exact view SHA, full original source/main/organization/incident/checkpoint/evidence bundle/inventory/final anchor scope, previous caller cursor, fresh per-peer challenge nonce, claimed operator and distinct signing-key pin, UTC timestamp/expiry and immutable HOLD. Views must match the complete **original verified Phase 1DZ vector entry-for-entry**, not just its final tip hash. This rejects a re-signed interior fork, truncated history, reordered epochs, copied nonce, skipped sequence, changed predecessor, source substitution and stale/expired packet even if a synthetic peer key is valid.

The canonical THREE-role ordered signed statement-set digest must then be signed by **two** synthetic Legal/Security freeze reviewers. Their statements bind the signed peer quorum, the same full source+final checkpoint, evidence bundle and vector digests, a SHA-256 of exact offline admission claim, original incident review nonce, and `disposition='CONTINUE_FREEZE_NO_AUTHORITY'`. Both review timestamps must follow the latest peer observation. A second copy of the same role, reused signature, changed quorum hash, fake Legal GO, old key, late/early observation or altered release disposition fails.

The separate `admissionClaim` exact schema accepts **only** `kind='UNTRUSTED_OFFLINE_ADMISSION_PREFLIGHT'`, `sourceType='APPLICANT_OFFLINE_SUBMISSION'`, `trustStatus='NOT_AUTHENTICATED'`, `decision='HOLD'` and seven literal FALSE approvals (`providerAuthorized`, `legalAuthorityVerified`, `liveIssuerRevocationAuthenticated`, `remoteArchiveRetrieved`, `wormCasRetentionVerified`, `independentStagingApproved`, `releaseApproved`). It rejects all affirmative claims even when all five new synthetic signatures are internally consistent. No preflight report is itself an issued provider certificate or real legal authorization.

Distinct key IDs, Ed25519 SPKI SHA-256, operator and claimed organization labels are required for all 5 new signers, distinct from historical Phase 1DU through 1DZ signer pins/witnesses. **Syntactic uniqueness is not independent custody or organizational verification.** Source URLs/TLS/HTTP and all clock, revocation, retained-until, previous cursor and identity claims remain applicant-controlled. The evaluator makes **zero network requests, off-platform changes, secret-manager reads or approval operations** and has no production unfreeze or credential-enrollment method.

## Adversarial synthetic evidence

**25 new Phase 1EA Node test groups** added to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`, including:
- Valid synthetic 3 peer + 2 freeze review packet consensus that ALWAYS blocks release.
- Independent key re-signed interior forks, copied historic entries, shortened/reordered vectors, changed final anchor, previous cursor rollback/substitution, replayed original/peer nonces.
- Detached signed key/operator/org collisions across earlier 1DU–1DZ signers, copied Ed25519 signatures/PEMs, forged GO, source SHA/previous anchor drift and stale/future claimed time.
- False official provider/MCA/CRL-OCSP/live HTTPS/WORM/DR/approved release assertions, exact-schema unwanted `approved` flags, forged quarantine/unfreeze, conflicting or copied review/quorum, early reviewer, missing clock, malformed/cyclic/oversized JSON, immutable redacted report.

The new verifier path is registered in both Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS`. Focused test:

```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Verified initial code+docs engineering HEAD:** `5ecb7be6c307cc3dd730722e658bf46da4ab279b`; [push 44892739804](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44892739804) **COMPLETED/SUCCESS**, 7 successfully executed jobs and expected PR-only lineage skipped; [PR 44892743971](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44892743971) **COMPLETED/SUCCESS**, all 8/8 including disposable MySQL, isolated Chromium, baseline, build/reviewer source custody and governance. GitHub Checks API **16/16** exact SHA/check ID/job name/status/conclusion matched Actions jobs. Hosted baseline logs executed **25 Phase 1EA synthetic tests, 0 full test failures**. This proves engineering mathematics only, never provider/Legal/CA approval or release. Writing this documentation-only receipt produces a **new SHA** whose own exact HEAD push/PR CI must be separately verified; these successful initial workflows cannot substitute for it.

## Permanent external blockers and release invariants

Actual next-step independent authority requires **explicit** written eMudhra/provider sandbox access agreement and credentials in approved secrets manager; out-of-band official MCA corporate/signatory mandate; CCA/RCAI/eMudhra independently authenticated certificate hierarchy and signed current serial/nonce-bound CRL/OCSP; independently enrolled Legal/Security/peer keys with validated organization/authorization; actual separately retrieved HTTPS archive bytes with TLS hostname/SPKI/trust-chain validation and SSRF/redirect prevention; off-platform signed gossip, protected CAS/high-watermark and WORM/object-lock retention/delete-denial; independently tested DR restore, trusted timestamps, protected main/CODEOWNERS two nonauthor approvals and independently signed staging Security/Business/Operations signoff. None is present here.

**The output never reports external trust or GO.** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'`, `actualHttpsGossipOrPublicationRetrievalPerformed=false`, `actualOffPlatformCasWormObjectLockOrDurableCursorVerified=false`, `independentlyAuthenticatedExternalPeerEnrollment=false`, `productionIncidentUnfreezeOrSourceActivationPossible=false`. Results are frozen metadata with typed anomaly codes only and contain no private keys/signatures/source identity, claim nonce, archive bytes or hashes.

No provider credentials, actual organizational identity evidence or live external signatures in Git, Issues or chat. PR #1 stays Draft/unmerged, Issue #2 stays open, `main` unchanged; no production provider activation, source unfreeze, financial/stock/tax/PO/GRN/customer/supplier transaction or deployment.
