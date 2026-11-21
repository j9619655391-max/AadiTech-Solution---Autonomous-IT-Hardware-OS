# Phase 1ED — Disconnected external-authority verification-port contracts and HARD HOLD

**Date:** 21 November 2026 IST. **Canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`. Draft PR #1 remains OPEN/UNMERGED, Issue #2 remains OPEN, `main` unchanged.

## Trust boundary and concrete implementation

Phase 1EC verified only the internal mathematical correspondence of an applicant-controlled 12-gate external authority preflight and synthetic Legal/Security incident-custody signatures with the earlier 1DU–1EB synthetic rollover, archive, revocation and cross-run gossip evidence. It **did not** authenticate any genuine MCA mandate, eMudhra/CCA/RCAI issuer, live signed CRL/OCSP, independently controlled signer or provider sandbox, real TLS archive, durable off-platform WORM/CAS, trusted time or production staging.

Phase 1ED introduces a **machine-readable, exact-schema disconnected verification-port interface** to make the eventual independent authority checklist actionable by authorized engineers **without pretending to run it**. The new `scripts/phase1ed-disconnected-authority-verification-ports.mjs` exports:

- `ED_GATE_INTERFACE_CONTRACT`: immutable 12 gate-to-port mapping with exact ordered required checks.
- `ED_RECEIPT_STATUSES`: only `NOT_EXECUTED`, `SIMULATED_MISSING`, `SIMULATED_REJECTED`, `SIMULATED_UNVERIFIED`; no VERIFIED, APPROVED or GO result exists.
- `createDisconnectedAuthorityWorkOrdersEd(handoffCandidate)`: returns 12 deeply frozen work orders after **re-running the entire 1EC-to-1DU synthetic evidence chain**. No network calls or credential handling.
- `workOrderDigestEd(workOrder)`: exact-schema SHA-256 domain binding, not a trusted signature or issuer credential.
- `createDisconnectedTestReceiptEd(order,{adapterId,status,observedAt})`: returns one frozen applicant-created local mock receipt; it makes **zero** network requests, authenticated-authority verifications or side effects.
- `assessDisconnectedAuthorityVerificationPortEd({handoffCandidate,workOrders,receipts,now})`: verifies all prior original packet content and 12 input/response pairs, then returns an immutable **HOLD-only** metadata report.

The whole input must be bounded to **4 MiB**, the ancestor 1EC candidate remains bounded to its prior limit, each order **8 KiB** and each receipt **8 KiB**. Exact object property sets, immutable static ordered port checks, source/main SHA, original organization/incident, previous source handoff manifest SHA, 12 original authority-claim digest, source evidence SHA, previous handoff sequence, per-gate domain-separated applicant challenge nonce, strict `DISCONNECTED_TEST_ONLY_NO_IO` and `decision='HOLD'` are required. Work-order fingerprints depend on the full original **synthetic** context, not a user-provided `priorApproved` flag.

## Twelve separate adapter contracts — all absent in real life

| Gate | Adapter contract | Required evidence checks when *properly authorized* |
| --- | --- | --- |
| PROVIDER_WRITTEN_AGREEMENT | PROVIDER_CONTRACT | Genuine signed contract and named license/account authority |
| APPROVED_SANDBOX_CREDENTIAL_CUSTODY | SECRET_CUSTODY | Approved secrets manager and named credential owner |
| CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY | ISSUER_CHAIN | Official root/certificate chain, certificate policy, KU/EKU scope |
| LIVE_ISSUER_SIGNED_CRL_OCSP | REVOCATION_STATUS | Issuer/OCSP responder signature, serial, nonce, thisUpdate/nextUpdate and revocation state |
| MCA_LEGAL_AND_SIGNATORY_MANDATE | CORPORATE_LEGAL | Independent MCA registry, actual corporate mandate and signatory authority |
| INDEPENDENT_KEY_ENROLLMENT | INDEPENDENT_KEYS | Out-of-band organization proof and independently separated private key custody |
| AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES | HTTPS_SOURCE | TLS hostname, trusted chain/SPKI, bounded source bytes, no redirects, SSRF deny |
| WORM_CAS_SIGNED_ANTI_EQUIVOCATION | OFF_PLATFORM_STORAGE | Real object lock/WORM, CAS durable high-watermark, signed fork-gossip, delete-denial |
| TRUSTED_TIMESTAMP_SOURCE | TRUSTED_TIME | Independent trusted clock, replay/skew controls |
| INDEPENDENT_DR_RESTORE_ACCEPTANCE | DISASTER_RECOVERY | Genuine isolated restore, RTO/RPO evidence and real deletion/retention tests |
| PROTECTED_MAIN_NONAUTHOR_REVIEWS | PROTECTED_REPOSITORY | Enforced branch protection, CODEOWNERS, two genuine nonauthor reviewer approvals |
| INDEPENDENT_STAGING_RELEASE_SIGNOFF | STAGING_RELEASE | Independently authorized Security, Business/Legal and Operations approval |

These are **requirements**, not reports of performed verification. Real connector/adapters must be separately designed and authorized by named legal and security owners, with secrets stored only in an approved secrets manager, independently obtained verified issuer and source material, protected egress allowlists and off-platform independently authenticated audit receipts. No such real adapter is implemented or invoked in 1ED.

## Mock receipt contract and denied-proof semantics

```js
const workOrders = createDisconnectedAuthorityWorkOrdersEd(handoffCandidate);
const localReceipts = workOrders.map((order, index) =>
  createDisconnectedTestReceiptEd(order,{
    adapterId: `test_adapter_gate_${String(index).padStart(3, '0')}`,
    observedAt: '2026-11-21T00:00:30.000Z'
  })
);
const result = assessDisconnectedAuthorityVerificationPortEd({
  handoffCandidate, workOrders, receipts:localReceipts,
  now:handoffCandidate.now
});
```

The example illustrates the contract, **not a complete valid ordered transcript**: the validator requires each mock receipt to have a strictly increasing observedAt after original handoff custody, so a complete test fixture assigns 12 ascending timestamps. All timestamps are applicant controlled, not evidence of an external trusted time service. Receipt expiry is bounded; adapter IDs must follow the `test_adapter_...` namespace and be distinct. Each receipt must bind the exact work-order SHA-256, source evidence SHA, gate, port type, per-gate nonce, exact role order, matching original authority status, local test mode, and exactly `networkRequests=0`, `authoritiesAuthenticated=0`, `sideEffects=0`, `releaseDecision='HOLD'`. A missing original gate may return `NOT_EXECUTED` or `SIMULATED_MISSING`; present-but-unverified and rejected states can only produce the corresponding simulator-only status and never any actual issuer verification.

The interface never invokes a callback, URL, HTTP client, secrets manager, filesystem, database or production API. It accepts **only supplied offline objects**. Pretending that `status='VERIFIED'`, `networkRequests=1`, `authoritiesAuthenticated=1`, `executionMode='LIVE_PROVIDER'`, `providerApproved=true`, a copied adapter ID, a reused nonce, source digest drift, changed previous EC manifest or fake GO is **rejected**; none can unfreeze.

### Fail-closed report

For every input, including 12 correlated mock receipts:
- `productionReleaseAuthorized=false`
- `productionReleaseBlocked=true`
- `releaseDecision='HOLD'`
- `realProviderOrMcaMandateAuthenticated=false`
- `liveIssuerSignedCrlOcspOrCcaRcaiEmudhraVerified=false`
- `actualIndependentTlsEvidenceOrGossipObtained=false`
- `realProtectedWormCasObjectLockOrDrAcceptanceVerified=false`
- `independentSignerEnrollmentOrStagingReleaseApproved=false`
- `productionSourceActivationOrCredentialEnrollmentPossible=false`
- `workOrdersAreNonExecutableAndNoExternalProviderQueried=true`

Only sorted anomaly codes and counts/flags leave the final report; no nonce, company/adapter identity, source hashes, raw evidence, signer keys or signatures are emitted. This **does not** imply that caller-held work orders contain no sensitive metadata; handle them only within approved engineering/test contexts and do not expose real company credentials in Git or chat.

## Testing, provenance and GitHub acceptance

**22 new Phase 1ED adversarial Node test groups** appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`: positive 12-order/12-receipt mathematical HOLD, static issuer-CRL and HTTPS verification requirement definitions, immutable local fake constructor/no real IO, missing/duplicated/reordered orders, false VERIFIED and status drift, copied/forged test adapter, claimed network/authority/side effect, replayed challenge, changed source/manifest SHA or evidence digest, tampered required checks, unauthorized live-IO work order, stale/expired/out-of-order fake time, re-verification of original EC/DU signed history, forged EC GO, unexpected status/extra proof property, cyclic/oversized input, malformed UTC and fully redacted HOLD report.

Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` both list `scripts/phase1ed-disconnected-authority-verification-ports.mjs`.

Focused test: `node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`.

**Verified corrected initial code-and-docs engineering HEAD `efbae4c6ec9b793c804c4bb5d11fa29835d977e5`**: [push 44895692235](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44895692235) **COMPLETED/SUCCESS** (7 executed successful jobs, expected PR-only source-lineage SKIPPED), [PR 44895697478](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44895697478) **COMPLETED/SUCCESS** (8/8 passed), including Node baseline, governed input/reviewer custody, GitHub governance, disposable MySQL integration and isolated Chromium. GitHub Checks API independently matched **16/16** exact SHA, check/job ID, check name, status and conclusion. Hosted baseline log executed all **22 new Phase 1ED adversarial groups** with **zero full Node failures**. Previous intermediate `d0928d826f64a12288ff3bf4a4ffa41991c85782` was **NOT accepted**: one test erroneously attempted an unchanged original `ISSUER_CHAIN` port value, not a spoof. The follow-up `efbae4c` fixture uses a genuinely altered port type and an explicit no-op guard; **both** fresh workflows passed. These results are engineering only. This documentation-only verification receipt generates a **new final SHA**; its own exact push/PR CI and 16/16 Checks must be verified independently, never substituted by the corrected initial source result.

## Actual independent authority prerequisites still blocked

Genuine MCA corporate/legal signatory records, written provider license and approved sandbox account/secrets, out-of-band authenticated RCAI/CCA/eMudhra issuer chain/CPS and live signed issuer CRL/OCSP, real independently enrolled external public keys/organizations, independently verified allowlisted HTTPS/TLS archive evidence bytes, protected off-platform signed gossip/CAS/WORM/high-watermark with real delete-denial, independent DR restoration and timestamps, protected-main CODEOWNERS/two independent nonauthor approvals, and signed Security/Business/Operations staging approval remain missing. Do **not** treat applicant-created Ed25519 packets or this simulation as real external authorization. Avoid provider credentials, actual private legal records or secrets in Git, Issue #2, PR #1 or chat.

**Release invariants remain HARD HOLD:** no activation, provider enrollment, production thaw, financial/stock/tax/PO/GRN/customer/supplier transaction, external communication, main merge or deployment. PR #1 DRAFT/UNMERGED, Issue #2 OPEN and `main` unchanged.
