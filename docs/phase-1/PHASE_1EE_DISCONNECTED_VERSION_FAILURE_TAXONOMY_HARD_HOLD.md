# Phase 1EE — Disconnected verification-protocol version pinning and failure taxonomy HARD HOLD

**Date:** 21 November 2026 IST. **Only canonical GitHub repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`. Draft PR #1 OPEN/UNMERGED, Issue #2 OPEN; `main` unchanged.

## Security objective: no silent live-adapter fallback

Phase 1ED defines 12 non-executable verification work orders and local mock receipts for provider contract, secret custody, RCAI/CCA/eMudhra issuer policy and signed live CRL/OCSP prerequisites, MCA signatory, independent key enrollment, authenticated TLS archive, off-platform CAS/WORM, trusted time, isolated DR restore, protected nonauthor main reviews and signed staging approval. **All are still applicant-controlled test objects, not verified outside authorities.**

Phase 1EE makes cross-contract **version negotiation and mock adapter failure semantics** fail closed. It recomputes the **complete original Phase 1ED/1EC/1EB/1EA/1DZ/1DY/1DX/1DW/1DV/1DU synthetic signed evidence chain** and requires 12 corresponding **pinned protocol v1** work/receipt bindings with an exact local fault-event SHA-256 chronology. It neither implements actual adapters nor claims any cryptographic, legal, network or storage authorization.

**New module:** `scripts/phase1ee-disconnected-version-failure-taxonomy.mjs`.

Exports:
- `EE_SUPPORTED_PROTOCOL_VERSION=1`: no supported v0 downgrade, v2 upgrade, unpinned range or migration fallback.
- `EE_PORT_FAILURE_CLASSES`: exact, frozen one-to-one 12-gate map. Every gate accepts `NOT_ATTEMPTED` or **one unique, explicitly SIMULATED gate-specific failure code**.
- `compatibilityDigestEe()`: domain-separated SHA-256 of the exact 12 Phase 1ED port types, ordered checks, four permitted disconnected receipt statuses and pinned local-only protocol policy.
- `receiptDigestEe(r)`, `sourceBundleDigestEe(originalEd)`: domain-separated SHA-256 of exact prior local mock receipts, original ordered 12 work orders, 1EC signed manifest hash and original source/incident/sequence context.
- `planDigestEe(p)`, `failureDigestEe(event)`: strict exact-schema domain-separated local digests, never independently trusted signatures.
- `createDisconnectedFailurePlansEe(originalEd)`: after complete original Phase 1ED history re-verification, emits **12 frozen NON-EXECUTABLE plans**, in original authority-gate order.
- `assessDisconnectedVersionFailureTaxonomyEe({previousPortCandidate,plans,failureEvents,now})`: exact-schema, bounded, read-only deny-only assessment returning fixed production HARD HOLD.

## Exact version compatibility, never a production negotiation

Each plan is version 1 with `kind='DISCONNECTED_PINNED_V1_FAILURE_TEST_PLAN'`, exact source bundle SHA, original phase 1ED work order SHA and mock receipt SHA, global port compatibility digest, original required port type, and **all three numeric version positions =1**: `requestedVersion`, `minimumAcceptedVersion`, `maximumAcceptedVersion`. `negotiation='PINNED_V1_ONLY'`, `fallbackPolicy='DENY_NO_DOWNGRADE'`, `adapterExecution='NO_NETWORK_NO_SECRETS'`, `decision='HOLD'`.

A caller cannot use a new protocol number to switch to a live adapter, silently fall back to a legacy v0 scheme, expand accepted ranges, swap the issuer-status port for an arbitrary TLS/CA adapter, substitute the ED receipt or change its original 1EC source SHA/manifest lineage. Complete original Phase 1ED **synthetic** verification is recomputed; a copied `priorVerified=true` flag has no meaning. Plan compatibility and SHA checks only validate the inputs, not actual provider support, OIDC trust or issuer verification.

## Synthetic port-specific failure taxonomy

| Original authority gate | Only permitted injected failure, besides NOT_ATTEMPTED |
|---|---|
| PROVIDER_WRITTEN_AGREEMENT | `SIMULATED_PROVIDER_LICENSE_ABSENT` |
| APPROVED_SANDBOX_CREDENTIAL_CUSTODY | `SIMULATED_SECRET_CUSTODY_MISSING` |
| CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY | `SIMULATED_ISSUER_POLICY_MISMATCH` |
| LIVE_ISSUER_SIGNED_CRL_OCSP | `SIMULATED_REVOCATION_STALE` |
| MCA_LEGAL_AND_SIGNATORY_MANDATE | `SIMULATED_MCA_SIGNATORY_UNVERIFIED` |
| INDEPENDENT_KEY_ENROLLMENT | `SIMULATED_KEY_CUSTODY_COLLISION` |
| AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES | `SIMULATED_TLS_SPKI_MISMATCH` |
| WORM_CAS_SIGNED_ANTI_EQUIVOCATION | `SIMULATED_EXTERNAL_ANCHOR_FORK` |
| TRUSTED_TIMESTAMP_SOURCE | `SIMULATED_TRUSTED_CLOCK_ABSENT` |
| INDEPENDENT_DR_RESTORE_ACCEPTANCE | `SIMULATED_DR_RESTORE_REJECTED` |
| PROTECTED_MAIN_NONAUTHOR_REVIEWS | `SIMULATED_NONAUTHOR_REVIEW_MISSING` |
| INDEPENDENT_STAGING_RELEASE_SIGNOFF | `SIMULATED_STAGING_SIGNOFF_MISSING` |

These words are **local injected fault labels**, not a report that any real provider, MCA portal, issuer OCSP responder, TLS host, organization or WORM storage was contacted. Specifically, `SIMULATED_REVOCATION_STALE` does not establish issuer-signed serial, nonce, thisUpdate/nextUpdate or actual certificate revocation; `SIMULATED_EXTERNAL_ANCHOR_FORK` does not prove remote anti-equivocation gossip or independently persisted high-watermark.

## Exact 12-event local failure transcript

The top-level input is exactly `{previousPortCandidate,plans,failureEvents,now}`, max **4.5 MiB**. Every prior Phase 1ED packet is required and re-assessed, not replaced by summarized result. Exactly 12 ordered failure events, bounded to **8 KiB** each, bind the appropriate gate and domain-separated plan SHA, `schemaVersion=1`, `kind='APPLICANT_SIMULATED_ADAPTER_FAULT_HOLD'`, `sequence=previous+1`, previous local failure SHA or original source-bundle SHA for the first event, one of the allowed gate-specific statuses, `simulated=true`, `networkRequests=0`, `authoritiesAuthenticated=0`, `sideEffects=0`, `retryPolicy='HOLD_MANUAL_AUTH_REVIEW'`, `disposition='REMAINS_QUARANTINED'` and `releaseDecision='HOLD'`.

Local caller `now` must be strict UTC and equal the original Phase 1ED candidate clock. Simulated event timestamps must strictly increase after the **last** preceding Phase 1ED mock receipt, remain within the bounded explicit caller clock window, and have expiry after observation/now, at most 15 minutes from observation. No trusted external clock source exists here. A forged event's downstream SHA hashes may be recalculated by an attacker who controls applicant packets; such local consistency is **not authenticated remote evidence**. Even a correctly recomputed local chain remains DENIED if its version, gate, source scope or fault code deviates.

No callbacks, HTTP, browser navigation, issuer validation, secret-manager read, certificate enrollment, off-platform object-lock/DR write, deployed workload, external message, approvals, or source unfreeze are provided or invoked by Phase 1EE.

## Acceptance and synthetic adversarial proof

**22 new Phase 1EE Node test groups** appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`, preserving earlier 1DT–1ED suites. They cover: 12-v1/12-NOT_ATTEMPTED mathematical HOLD, frozen failure mapping, all 12 correctly classified simulated fault codes, v0/v2 and accepted-version-range downgrade/upgrade, silent live adapter fallback, original work order/receipt/source SHA substitution, reordered/duplicated/truncated plans, issuer-CRL vs TLS fault confusion, forged VERIFIED/GO and unknown positive fault codes, fake `networkRequests=1` and auto retry, SHA predecessor replay or rehashed source fork, missing/duplicated event count, stale/future/expired/nonmonotonic UTC, changed original ED mock `VERIFIED`, original 1EC/1DU signed history mutation, extra production `approved` fields, cyclic/malformed/oversized input and fixed redacted HOLD output.

Phase 1BV immutable build source inventory and Phase 1BW reviewer-intake custody inventory both include `scripts/phase1ee-disconnected-version-failure-taxonomy.mjs`.

Focused test:
```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Phase 1EE verified initial code+docs engineering source SHA:** `ae0ba1a8ed4662cb919dcd4449f1853ffb637088`. [Push CI 44896832379](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44896832379) **COMPLETED/SUCCESS** (7 executed successful jobs + expected PR-only lineage SKIPPED), [PR CI 44896837282](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44896837282) **COMPLETED/SUCCESS** (8/8), with hosted Node baseline, build provenance, reviewer custody, GitHub governance, independent evidence HOLD, production scope, actual disposable CI MySQL and isolated Chromium smoke. GitHub Checks API **16/16** completed checks reconciled by exact source SHA, check/job ID, name, status and conclusion; 0 mismatches. Hosted push Node logs ran **22 Phase 1EE synthetic test groups, 0 failures in full Node suite**. This is engineering math only, never real provider/CA/legal staging authority. Recording this CI evidence into runbook/ledger creates a **new docs-only final HEAD**; its own fresh push/PR CI and exact SHA Checks must be verified independently, not reused from the engineering SHA.

The assessment always returns a frozen, redacted code/count-only metadata report:
```text
productionReleaseAuthorized=false
productionReleaseBlocked=true
releaseDecision=HOLD
externalAdapterOrNetworkInvocationPerformed=false
genuineExternalProviderMcaCcaRcaiEmudhraAuthorityVerified=false
realIssuerSignedCrlOcspOrTlsSourceVerified=false
independentDurableCasWormGossipOrDrAccepted=false
independentLegalSecurityReviewerStagingReleaseAuthorized=false
mockFailureDiagnosisCanNeverUnfreezeIncident=true
```

No private signer keys, company/adapter IDs, original source hashes, local failure chain SHA, authority credentials or raw evidence appear in this report. Original local applicant packets contain scoped metadata and should not carry real credentials.

## Unfilled real-world external authority conditions

Still requires legitimate written sandbox agreement, named provider license and approved managed credentials; independently MCA-verified corporate signatory mandate; genuine independently sourced CCA/RCAI/eMudhra certificate chain/CPS with authenticated issuer-signed fresh CRL/OCSP tied to correct serial/nonce/time; independent out-of-band external signer identity and Legal/Security custody enrollment; authenticated separate HTTPS archive bytes (TLS hostname/SPKI/CA, bounded download, no SSRF or redirect); real off-platform protected signed gossip/CAS/WORM/object-lock, durable high-watermark and delete-denial; independently accepted DR restore and trusted timestamps; protected main CODEOWNERS and two nonauthor reviews, plus real Security/Business/Operations signed staging signoff. These are not available from local synthetic fixtures.

**Production HARD HOLD:** no external provider activation, credential/key enrollment, source thaw, production customer/supplier/finance/stock/tax/PO/GRN transaction, deployment, main merge or counterparty communication. PR #1 OPEN/DRAFT/UNMERGED; Issue #2 OPEN; unchanged `main` SHA; `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'`.
