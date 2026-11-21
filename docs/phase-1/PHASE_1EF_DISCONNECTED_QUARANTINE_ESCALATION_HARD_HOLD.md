# Phase 1EF — Disconnected independent-authority escalation quarantine HARD HOLD

**Date:** 21 November 2026 IST. Canonical source repository: `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; engineering branch `chore/phase0-foundation-20261106`. No deployment, real provider agreement, issuer evidence, independent off-platform custody or production authorization.

## Objective

Turn Phase 1EE's exact 12 pinned-v1 locally simulated failure events into **12 deterministically ordered, source-linked, NON-EXECUTABLE applicant-only quarantine escalation cases**. This is a checklist for later independent verification, *not* a case-management service or approval workflow. Local applicant-controlled hashes, generated role labels and cases are never independent external authority.

## Strict machine contract

`scripts/phase1ef-disconnected-quarantine-escalation.mjs` exposes:

- `EF_INDEPENDENT_AUTHORITY_ROLES`: one exact unfilled independent human or organizational role requirement per Phase 1EC authority gate (provider contract, secrets custodian, issuer chain, live revocation, MCA mandate, signer enrollment, TLS archive, off-platform anti-equivocation, trusted time, DR, protected-main reviewers, and staging signoffs).
- `failureTranscriptDigestEf(previousEe)`: SHA-256 domain-separated local digest of original Phase 1ED source bundle, 12 ordered EE v1 negotiation plans and 12 ordered local failure event digests.
- `quarantineCaseDigestEf(case)`: bounded exact-schema, locally domain-separated SHA-256 of applicant case metadata, not a signature or an independently immutable storage commitment.
- `createOfflineQuarantineCasesEf(previousEe)`: re-executes the original Phase 1EE assessor, which re-verifies prior Phase 1ED through Phase 1DU applicant-controlled signed history; only internally consistent, denied, fully local EE records can produce 12 *frozen* quarantine cases.
- `assessOfflineQuarantineEscalationEf({previousFailureCandidate,cases,now})`: exact bounded local read-only comparison against freshly derived expected cases and immutable redacted HARD HOLD assessment. Caller `now` must be exactly the previously checked EE clock; never describe it as trusted independent time.

Every case binds one source bundle SHA, 12-event transcript SHA, version plan digest, simulated fault event digest and previous case SHA (first case roots at entire transcript SHA), exactly one ordered gate and its required independent role. No actual reviewer is enrolled. Status is always `OPEN_UNVERIFIED`, `MANUAL_REVIEW_ONLY_NO_AUTO_RETRY`, `NO_LOCAL_CASE_CLOSURE_OR_RELEASE`, network/side effects = 0, all authority booleans false and decision `HOLD`. `NOT_ATTEMPTED` and gate-specific injected `SIMULATED_...` outcomes merely control a local classification; neither can prove real authority or close a case.

## Adversarial coverage

12 appended Phase 1EF test groups assert deterministic 12-case HOLD, 12 injected negative classifications still HOLD, fake CLOSED/GO/reviewer/issuer/legal approval, auto-retry or fake IO, swapped gate/role/source/plan/receipt/case predecessor, reordered/duplicated/truncated events, rehashed attacker case suffix, original EE protocol downgrade/fallback/GO and original ED issuer spoof, altered signed upstream manifest, unauthorized top-level approval, mismatched clock, cyclic/oversized exact-schema rejection, frozen redacted metadata. Tests append to existing `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`; build/reviewer custody source inventories include the new source. CI must independently verify the exact committed SHA before marking this increment verified.

## Remaining real evidence

Written licensed sandbox permission and managed credentials; authentic independent MCA mandate; CCA/RCAI/eMudhra policy and live issuer-signed CRL/OCSP with serial, nonce and freshness; independent reviewer/custodian enrollment and actual protected-main quorum; actual allowlisted TLS/SPKI archive bytes and out-of-band WORM/CAS signed gossip and deletion denial; trusted timestamp and independent DR restore; independently signed Security/Business/Operations staging signoff. None is obtained by synthetic tests, GitHub green CI, role labels or locally linked SHA.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Draft PR #1 remains unmerged; Issue #2 remains open; `main` unchanged. No production release, real provider messaging, finance/stock/tax/PO/GRN/dispatch mutation, source activation or credential enrollment.

## Verified initial Phase 1EF engineering CI (21 November 2026 IST)

Exact engineering source SHA `18cd3ffa98b2a05a0a2c574bdac40ec13efa413d`; [push 44921605750](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44921605750) COMPLETED/SUCCESS (7 passed + 1 expected push-only lineage skipped); [PR 44921608922](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44921608922) COMPLETED/SUCCESS (8/8); 16/16 GitHub Checks exact SHA, job/check ID, name, completed status and conclusion reconciled, zero mismatches. Push hosted baseline ran **1,400/1,400 Node tests with 0 failures**, including **all 12/12 newly added EF groups**, and passed build, source provenance, reviewer custody, disposable MySQL and isolated Chromium smoke. This is not genuine provider, independent issuer, legal or staging proof. Recording this text produces a new documentation-only commit, which must itself receive separate exact-SHA CI verification.
