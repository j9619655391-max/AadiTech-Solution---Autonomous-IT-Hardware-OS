# Phase 1DZ — Offline cross-epoch anchor and recovery-evidence custody HARD HOLD

**Date:** 21 November 2026 IST. **Canonical GitHub repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Active development branch:** `chore/phase0-foundation-20261106`. PR #1 stays **OPEN/DRAFT/UNMERGED**, Issue #2 **OPEN** and `main` unchanged. **No genuine production onboarding, credential enrollment, independent online retrieval, remote storage operation or release decision is performed by this engineering phase.**

## Trust boundary and contribution

Phases 1DU–1DY verify **applicant-controlled** evidence from synthetic signing identities: multiepoch signed checkpoint history; alleged publisher/archive observer signatures; Legal/Security custodian and Registry/Provider revocation-status claims; apparent three-source retrieval and frozen DR rehearsal; and an exact 12-gate external-readiness inventory with five signed HOLD-only review statements. Despite mathematical consistency, no step authenticates a genuine provider agreement, eMudhra/CCA/RCAI issuer, MCA legal appointment, real external TLS bytes, independent organizational separation, trusted off-platform WORM/retention or actual recovery acceptance.

**Phase 1DZ** adds deterministic signed cross-epoch *candidate* anchor continuity and locally hashed recovery evidence with two **synthetic** retention-custodian receipts. It rejects observable forks and replay **within the submitted packet set only**. This can never prove the absence of unobserved forks, real off-platform publication, immutable object storage or live operational unfreeze.

Source: `scripts/phase1dz-offline-cross-epoch-anchor-custody.mjs`

Public exports:
- `DZ_ANCHOR_ROLES`: `ARCHIVE_ANCHOR_OBSERVER`, `RECOVERY_ANCHOR_COMPARATOR`.
- `DZ_CUSTODY_ROLES`: `LEGAL_CUSTODY_RECEIPT`, `SECURITY_CUSTODY_RECEIPT`.
- `assessOfflineCrossEpochAnchorCustodyDz(args)` — exact-schema pure offline, no I/O and always HARD HOLD.
- `evidenceBundleBytesDz(dyCandidate)` — canonical domain-separated bytes bound to *applicant-provided* original phase 1DY admission case, actual supplied 1DX source statement digests, final frozen rehearsal digest and review statement digest.
- `anchorDigestDz(record)`, `anchorSigningBytesDz(role,statement)`, `custodySigningBytesDz(role,statement)` — v1 domain-separated exact-schema SHA-256/Ed25519 mathematical verification.

## Contract and verification chain

```js
assessOfflineCrossEpochAnchorCustodyDz({
  admissionCandidate,    // entire original 1DY with original 1DU–DX packets
  previousAnchor,        // caller's {sequence,digestSha256,observedAt}
  epochs,                // 2–4 exact consecutive applicant-signed epoch records
  anchorPins,            // exact two detached candidate observer pins
  evidenceBundleBase64,  // exact locally supplied canonical evidence-bundle bytes
  custodyPins,           // exact Legal/Security retention-custodian pins
  custodyPackets,        // two detached Ed25519 HOLD-only retention claims
  now                    // caller-supplied canonical UTC time; NEVER trusted time
});
```

The aggregate JSON input must not exceed **2 MiB**. The exact candidate bundle must be strictly canonical base64 and at most **16 KiB**, with bounded epoch/statement/packet and exact top-level schemas. Cyclic/oversized input, unexpected approval fields, unknown roles and malformed signed data fail closed.

The verifier **re-runs the entire 1DY verifier**, which itself re-verifies all 1DX/DW/DV/DU original candidate packets. It never takes `priorVerified=true` or an external authorization boolean. Previous submitted anchor must match the original 1DY frozen-case digest and observation sequence and must be claimed no earlier than the final DY review statements. The previous digest/time are **caller-supplied and not an external persisted high-watermark**.

Every one of the 2–4 epochs has an exact `record` and **two** separately domain-signed observer packets. The signed epoch record binds incident ID, original source/main SHA, organization, final original checkpoint/archive/revocation digest, original 1DY authority-inventory SHA and frozen-case digest, source-evidence-set and recovery-ledger digests, canonical candidate bundle SHA, contiguous sequence (`previousSequence+1`), exact previous epoch SHA-256, unique nonce, strictly increasing bounded UTC clock and immutable `HOLD`. Both observer roles must sign **the same** exact epoch contents and record SHA. Different signed archive/anchor views, duplicate signer, omitted role, re-signing a conflicting predecessor, nonce replay, sequence rewind or gap, old signing keys, GO and forged source digest are rejected.

The last epoch is bound to **exactly two** new synthetic Legal/Security retention-custodian Ed25519 signatures over terminal anchor SHA, final sequence, original previous-anchor digest, source/main/organization/incident, candidate bundle SHA, frozen source/inventory digests, fresh timestamps, the original DY review nonce and `disposition='RETAIN_HOLD_NO_DELETE'`. Both candidates must claim identical retention-until timestamp, at least **30 days after caller-supplied now** and no more than the deliberately bounded upper horizon. This is **not** actual retention, object-lock enforcement, CAS success, delete-denial testing or a WORM provider attestation; the software cannot enforce that promise.

Both new observer signers and both new custodian signers must have distinct submitted key IDs, Ed25519 SPKI, operator IDs and claimed organizations from one another, all earlier phase DY, DX, DW, DV signers and the complete 1DU signed Legal/Registry witness history. These are *syntactic* separations, not organizational verification; a single applicant may control every key.

## Deny-only report and negative safety guarantees

Even when all local applicant-provided cryptographic packets correlate, the frozen report always contains:
- `productionReleaseAuthorized=false`
- `productionReleaseBlocked=true`
- `releaseDecision='HOLD'`
- `actualCrossSystemForkAbsenceOrGossipAuthenticated=false`
- `externalWormRetentionOrObjectLockDenialTestVerified=false`
- `independentlyPersistedAntiRollbackHighwatermarkVerified=false`
- `authenticSignedLiveCrlOcspMcaMandateAndExternalTrustVerified=false`
- `independentRealIncidentRestoreAndUnfreezeApprovalVerified=false`
- `safeProductionSourceThawPossible=false`
- `productionMutationOrExternalCredentialEnrollmentPossible=false`

Only minimal frozen booleans, numeric checked signature counts and typed, sorted anomaly codes leave the function. No PEM, signer ID, digest, external identity, nonce, evidence payload, archive content or signature bytes are returned. All time, keys and data come from the caller; **zero live actions** occur.

## Adversarial synthetic verification

**21 Phase 1DZ adversarial Node test groups** are appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`, covering locally consistent 2/3 epochs with immutable HOLD, signed fake GO and source rebind, independently re-signed conflicting observer view, duplicated/reordered/skipped epoch or previous anchor digest, replayed nonce, bad evidence bytes, copied/retired DY keys and signer collisions, Ed25519 signature/PEM substitution, stale/invalid dispositions, claimed delete or unfreeze and too-short retention, opposite retention claims, absent/copied Legal/Security custodians, late/early clocks, upstream signed history forgery, exact-schema unauthorized approval extension, cyclic/oversized payload and redacted output. They use **synthetic** generated keys, not provider credentials.

Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` both now list `scripts/phase1dz-offline-cross-epoch-anchor-custody.mjs`.

Focused test command:
```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Verified initial docs-inclusive Phase 1DZ engineering HEAD** `4f3155a27ecec33b3bc4a8bcf2c3f987bf53a936`: [push 44891920227](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44891920227) **COMPLETED/SUCCESS** (7 successfully executed jobs and one expected PR-only lineage skip); [PR 44891923928](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44891923928) **COMPLETED/SUCCESS** (8/8 jobs), including baseline, governance, provenance, disposable MySQL and isolated Chromium smoke. GitHub Checks API reconciled **16/16** exact SHA, check/job ID, job name, completed status and conclusion. Hosted baseline logs executed all **21 Phase 1DZ synthetic tests with 0 full baseline failures**. All evidence is strictly engineering only; no actual source identity, real external anchor, WORM/CAS/Object Lock or release approval is established. This new CI evidence receipt causes a documentation-only commit; independently verify its *new* exact HEAD push/PR jobs rather than borrowing prior 4f3155a results.

## External authority and production prerequisites — UNFILLED

Genuine onboarding requires an approved written provider agreement, credentials in approved secrets management, independent MCA company/signatory mandate, authenticated CCA/RCAI/eMudhra chain and live issuer-signed CRL/OCSP validation (serial, issuer, nonce, thisUpdate/nextUpdate and certificate policy), independently authenticated signer and publisher TLS keys, real separate-source byte fetch with certificate/hostname chain validation and SSRF/redirect protection, external signed anti-equivocation gossip and durable CAS/high-watermark, WORM/object-lock delete-denial and retention, independently verified backup restoration, trusted time, genuine independent incident unfreeze approvals, protected-main CODEOWNERS and two nonauthor PR reviewers plus authorized Security/Business/Operations staging. **None of these is established through synthetic GitHub tests or signed self-reported JSON.**

No secrets, legal identity evidence, provider certificates/credentials, production signatures or live counterparties should be placed into Git, chat or Issue #2. PR #1 remains Draft; Issue #2 remains open; `main` unchanged; no production deployment, source unfreeze, credential enrollment, finance/stock/tax/PO/GRN/customer/supplier transaction or external message. This module is solely a fail-closed mathematical offline preparation step.
