# Phase 1DW — Offline observer enrollment / dual-source revocation consensus (HARD HOLD)

**Repo and branch:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, `chore/phase0-foundation-20261106`. Phase 1DV exact-head GitHub-hosted push and PR CI both green at `5c9a8dbc959567c36a510f3893064cf223e8d91c`. PR #1 **OPEN/DRAFT/UNMERGED**; Issue #2 **OPEN**; main unchanged. This is engineering containment, **not** an externally accepted release.

## Contract

`scripts/phase1dw-offline-observer-enrollment-revocation.mjs` exports:
- `assessOfflineObserverEnrollmentRevocationCandidate({publicationCandidate,enrollmentPackets,enrollmentPins,revocationPackets,revocationPins,revocationState,previousAnchor,now})`
- `observerPinDigestDw(comparisonPins)` — domain-separated digest of the *applicant-supplied* detached Phase 1DV observer key and claimed TLS/operator pins.
- `revocationStatusDigestDw(expected,revocationState)` — domain-separated digest of claimed common revocation state, previous anchor and Phase 1DV terminal checkpoint scope.
- `signingBytesDw(role,statement)` — canonical domain-separated Ed25519 statement bytes for bounded signed witness packets.

The input schema is exact (no approval extensions) and limited to **1 MiB**. It re-runs all Phase 1DV verification (including Phase 1DU multi-epoch Ed25519 signatures, witness rollover identity continuity, terminal checkpoint, signed two-observer digest and actual supplied archive bytes). It never accepts `candidate...=true` from a previous submitted report.

A candidate local quorum requires **exactly one** signed statement from each of:
- `LEGAL_ENROLLMENT_CUSTODIAN` and `SECURITY_ENROLLMENT_CUSTODIAN` — both sign the same canonical two-observer key/TLS/endpoint/operator pins digest and source/main/organization/checkpoint/archive/mandate/revocation digest claims.
- `CORPORATE_REGISTRY_REVOCATION` and `EXTERNAL_PROVIDER_REVOCATION` — both sign the same current revocation version, previous version/digest, ordered and unique revoked-key-ID list, source scope, challenge nonce, observed time and immutable HOLD.

Each statement has detached signer role key ID, SPKI SHA-256, operator ID and claimed organization ID; canonical Ed25519 signature verified against the submitted PEM. Sources must not share signer SPKI, key ID or operator ID with each other, either Phase 1DV observer or the verified Phase 1DU Legal/Registry witness signers. **This checks only mathematical key separation, not organizational independence.** The claimed applicant previous high-watermark must increment **exactly by one**, with unchanged previous digest, while status digest must exactly match the Phase 1DV signed revocation-digest claim. Current observers, enrolled custodians, revocation signers and all supplied signed history witness key IDs must not appear in the *claimed* revocation list. Reversed, duplicated, unbounded, stale or changed signed inputs fail closed.

Freshness is evaluated against explicit caller-supplied canonical UTC `now`; signed statements may be at most 15 minutes old or 5 minutes in the future, with signed expiry after now and no more than 15 minutes after observation. All input clocks and keys **remain caller-controlled**. Only typed anomaly codes, counts and immutable release HARD HOLD leave the evaluator; no raw keys, signature, observer identity, nonce, revoked-key list or archive bytes are emitted. No source is fetched, queried, enrolled, written or persisted.

## Adversarial synthetic engineering tests

**16 Phase 1DW groups** were added alongside original 1DT, 1DU and 1DV synthetic tests in `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`. They exercise valid local four-signer mathematics vs explicit HOLD, copied custodian/revocation role, shared operator/SPKI/ID, former witness impersonation, genuinely re-signed revocation of current observer or Legal witness, version rollback/gap/anchor digest drift, signed split-view revoked-key-list fork, re-signed observer pin digest drift, forged GO, stale expiry, signature key substitution, caller-input approval extension, malformed/reordered revoked IDs, previous signature rollback, missing/untrusted time, claimed live CRL/OCSP nonpromotion, bounded redacted frozen output.

Provenance: Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` both include `scripts/phase1dw-offline-observer-enrollment-revocation.mjs`. Engineering acceptance command:

```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Phase 1DW corrected engineering HEAD:** `158ecdc6c8f627b29d84345516fd8a766d6f0ac4`: [push 44886614151](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44886614151) COMPLETED/SUCCESS (7 successful executed jobs and expected PR-only skip), [PR 44886618773](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44886618773) COMPLETED/SUCCESS (8/8). GitHub Checks API independently reconciled all **16/16** job/check IDs, names, exact SHA, completed status and conclusions. Source custody, baseline, read-only governance, disposable MySQL and isolated Chromium smoke all passed. Earlier `82b908ea92aa6e09f274f55d4ea5a48d4c7f9e15` push 44886539486 and PR 44886541429 genuinely FAILED one synthetic mathematical-consistency test because signer custodian's organization ID shadowed source company's ID. Fixed with a **separate custodianOrganizationId and extra uniqueness constraint** in commits 9ea846aa and 158ecdc6; these failed runs are not presented as passing. This CI is **engineering only**, not external legal/prod approval. After adding this documentation-only receipt, verify its new exact latest HEAD in push and PR GitHub Actions rather than counting 158ecdc6 twice.

## Why this is still UNTRUSTED and not release authorization

The two custodians and two revocation source *roles* are labels on applicant-generated Ed25519 keys. Their claimed legal/corporate/provider affiliation, TLS SPKI/endpoint, high-watermark, trusted clock and revocation currentness have **not** been authenticated out of band. A signed empty revoked-key list or signed legal-mandate hash is not an official RCAI/eMudhra/CCA CA-issued signed CRL or nonce-bound OCSP status, and is not MCA verification. A purported external archive digest is not independent retrieval, WORM/CAS enforcement or disaster-recovery evidence. Mathematical agreement of four synthetic signatures can never become external independent approval.

Actual future onboarding must be separately authorized and performed using named independent Legal and Security officers, independently identified provider/registry custodians, signed mandate and MCA company/signatory verification, explicit provider agreement and credentials in approved secrets manager, authenticated public key enrollment, official CCA/RCAI/eMudhra certificate policies/chain and live signed fresh CRL/OCSP, out-of-band TLS hostname and certificate validation, independent bounded archive GET and byte hash comparisons, off-platform durable signed high-watermark and anti-equivocation gossip, object-lock retention/denied delete/DR restore, external trusted time, and Security/Business nonauthor protected-main PR plus staging release approvals. All private records live in approved external custody, never chat/Git fixtures.

**Hard invariants:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No provider activation, real signing credential enrollment, main merge, release, financial/customer/supplier record mutations or outgoing production messages authorized. PR #1 draft and Issue #2 open.
