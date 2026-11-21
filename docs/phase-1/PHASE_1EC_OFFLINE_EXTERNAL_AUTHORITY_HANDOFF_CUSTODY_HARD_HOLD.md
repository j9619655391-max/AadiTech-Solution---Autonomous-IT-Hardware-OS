# Phase 1EC — Offline external authority handoff and incident custody HARD HOLD

**Date:** 21 November 2026 IST. **Canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Branch:** `chore/phase0-foundation-20261106`. PR #1 remains **OPEN/DRAFT/UNMERGED**; Issue #2 remains **OPEN** and `main` unchanged. No real external approval, credentials, independent external identity, authenticated fetch, storage writing, incident unfreeze or production release occurs here.

## Goal and actual trust boundary

Phases 1DU–1EB already check the complete, **applicant-controlled** signed rollover/archive/observer/revocation, frozen incident, multi-epoch anti-fork, three-peer gossip, two linked run and Legal/Security retention candidate packets. They never established genuine MCA authority, an eMudhra/CCA/RCAI approved sandbox, official signed live issuer CRL/OCSP, independently verified external operator identity, actual source HTTPS or off-platform WORM/CAS durability. Phase 1EC adds an **exact, reject-by-default authority evidence handoff contract**, referencing those entire original packets and preparing a *checklist for legitimate independent owners* without declaring evidence verified.

New code: `scripts/phase1ec-offline-authority-handoff-custody.mjs`.

Exports: `assessOfflineExternalAuthorityHandoffEc(args)`, `sourceReceiptDigestEc(eb)`, `authorityClaimsDigestEc(claims)`, `manifestDigestEc(manifest)`, `reviewSigningBytesEc(role,statement)`, `reviewSetDigestEc(orderedStatements)`, `custodySigningBytesEc(role,statement)`; immutable `EC_AUTHORITY_GATES`, `EC_REVIEW_ROLES`, `EC_CUSTODY_ROLES`.

## Twelve authoritative prerequisites — every claim remains UNVERIFIED

Exact inventory map keyed by all 12 original Phase 1DY prerequisites. Every claim has exactly `{state,evidenceSha256,issuerOrganizationClaim,submittedAt,validUntil}`:
- `MISSING` requires SHA-256 zero, null issuer, null timestamps and null expiry.
- `PRESENT_UNVERIFIED` and `REJECTED` require a nonzero digest, syntactically bounded **claimed** issuer organization and canonical signed-local UTC timestamps. They must match **exactly the original Phase 1DY signed candidate inventory state, digest and observedAt**; no local mutable status promotion. Explicit expiry must be after caller-supplied `now`, not more than 30 days beyond it and after original observation.
- `VERIFIED`, `APPROVED`, `AUTHORIZED`, extra properties, unknown gates, mismatched digests, unbounded payloads, unsigned alternative versions and claimed real release approval are **never admitted**. The values are assertions by the applicant, not external issuer signoffs.

| Exact gate | Authentic external verification must eventually be conducted by |
| --- | --- |
| `PROVIDER_WRITTEN_AGREEMENT` | Actual provider-authorized legal contract and approved named account owner |
| `APPROVED_SANDBOX_CREDENTIAL_CUSTODY` | Provider credentials in approved secrets manager, independent credential owner |
| `CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY` | Independently verified official certificate hierarchy, issuer/CPS/policy and intended KU/EKU |
| `LIVE_ISSUER_SIGNED_CRL_OCSP` | Verified issuer or OCSP responder signature, serial, nonce, this/nextUpdate, revocation status |
| `MCA_LEGAL_AND_SIGNATORY_MANDATE` | Independent MCA company registry plus actual authorized corporate and signatory records |
| `INDEPENDENT_KEY_ENROLLMENT` | Named genuine corporate Legal, Security and external provider signer authority and key custody |
| `AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES` | Real allowlisted HTTPS/TLS hostname, chain, SPKI, bounded source archive bytes, deny redirects/SSRF |
| `WORM_CAS_SIGNED_ANTI_EQUIVOCATION` | Real off-platform immutable CAS/object lock, signed durable high-watermark and fork gossip |
| `TRUSTED_TIMESTAMP_SOURCE` | Independently obtained timestamps, issuer validation, replay window |
| `INDEPENDENT_DR_RESTORE_ACCEPTANCE` | Authorized isolated recovery test, RTO/RPO, retention and delete-denial evidence |
| `PROTECTED_MAIN_NONAUTHOR_REVIEWS` | Enforced branch protections, CODEOWNERS, genuine two independent nonauthor reviews |
| `INDEPENDENT_STAGING_RELEASE_SIGNOFF` | Authorized Security, Legal/Business and Operations staging signoff and authenticated workload |

An actual independent reviewer must retrieve official evidence using approved authenticated channels, examine the relevant legal/license/signer certificate/status/retention source and record a separately controlled redacted audit receipt **outside** this module. Real secrets, provider credentials, private certificates, legal signatory records or raw CRL/OCSP material must not be put in Git, chat, PR #1 or Issue #2.

## Exact bounded handoff contract

```js
assessOfflineExternalAuthorityHandoffEc({
  incidentCandidate,       // full original Phase 1EB (+ 1EA–1DU) signed packets
  previousHandoffAnchor,   // supplied {sequence,digestSha256,observedAt}
  authorityClaims,         // exact 12 original status/digest and claimed issuer/time values
  manifest,                // applicant-signed-source-bound release HOLD handoff manifest
  reviewPins,              // two new claimed Archive/Incident reviewer SPKI/operator/org pins
  reviewPackets,           // two Ed25519 REVIEW_UNVERIFIED_HOLD_ONLY packets
  custodyPins,             // two distinct Legal and Security custody pins
  custodyPackets,          // two Ed25519 RETAIN_UNVERIFIED_HOLD_NO_UNFREEZE packets
  now                      // applicant-supplied strict UTC, NOT trusted time
});
```

Exact top-level schema, bounded global **3.5 MiB**, claims **32 KiB**, individual signed scope **8 KiB**, signed packet **12 KiB**. Cycles, malformed nested original packets, unexpected fields and oversized inputs must deny without production effects.

First the entire original Phase 1EB result is **recomputed** from its original packet bytes; no caller-supplied verified flag is trusted. Its two sequential prior run digests and both role-ordered original custody statements are domain-hashed into an applicant-only `sourceReceiptDigestEc`. The previous handoff anchor must match this digest and the Phase 1EB second-run sequence; its time must be no earlier than both prior synthetic custody observations, while remaining inside the explicit input-clock skew. The previous anchor is caller supplied, **not** independently durable CAS/WORM high-watermark.

The exact frozen manifest carries original source/main SHA, incident and organization, terminal prior EB run hash/sequence, full EB source/custody digest, prior EA gossip handoff digest, exact twelve-claim digest, previous anchor SHA/sequence, `sequence=previous+1`, new distinct 64-character challenge nonce, UTC time after predecessor and `decision='HOLD'`. It cannot say GO or claim authenticated source/issuer authority.

Two separately role-signed Archive Evidence and Incident Provenance *candidate* review packets must sign every manifest field, its domain-separated hash and `disposition='REVIEW_UNVERIFIED_HOLD_ONLY'`, with separate post-manifest `reviewObservedAt` and bounded expiration. Their role-ordered signed statement digest must be carried by **two additional** claimed Legal and Security custody receipts. Those must bind the exact manifest fields, original legal/issuer/source claims, both reviewer digest, exact prior EB retentionUntil, `disposition='RETAIN_UNVERIFIED_HOLD_NO_UNFREEZE'`, a separate post-review observation and bounded expiry. The claimed retention must still be at least 30 days after applicant clock; short/early, mismatched, split or re-signed delete/unfreeze fail.

All four new signer IDs, Ed25519 SPKIs, operator and custodian-org labels must be syntactically pairwise distinct and not match *any* prior Phase 1EB/1EA/1DZ/1DY/1DX/1DW/1DV/1DU witness or custody identity. These comparisons do not validate independent legal identity, provider contract, external key enrollment or authentic issuer status; one applicant may control all keys.

## Adversarial regression and outputs

**22 new synthetic Phase 1EC test groups** are appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`, including: all 12 MISSING positive mathematical/HOLD; forged VERIFIED/APPROVED and submitted fake issuer; status/digest mismatches against original 1DY; previous source hash/sequence/time rollback; signed fake GO, source drift, signed custody and reviewer quorum forking; forged nonce and replay; cloned roles, copied SPKI, signature and operator/organization reuse; obsolete Phase 1EB custodian key reuse; premature/expired reviewer or custodian, altered original retention and split custody dates; upstream 1DU history forgery; unknown approval extension, cyclic/oversized/malformed ancestor inputs and immutable redacted release-HOLD results.

Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` list `scripts/phase1ec-offline-authority-handoff-custody.mjs`. Focused test: `node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`.

Only **GitHub-hosted exact-final-HEAD** completed/success push and PR workflows, including Node baseline, source/review custody, governance, disposable MySQL and isolated Chromium, may confirm engineering validation. Push expects 7 passed and 1 PR-only skipped, PR expects 8/8 successful; reconcile all **16/16** GitHub Checks exact check/job IDs, names, source SHA and conclusions. Previous green commit results do not establish newest documentation HEAD. Final evidence will be recorded on PR #1 and open Issue #2.

**Immutable negative output invariants for every input:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'`, `actualExternalProviderOrMcaMandateVerified=false`, `issuerSignedLiveCrlOcspOrCcaRcaiEmudhraVerified=false`, `independentTlsEvidenceRetrievalOrSignedGossipPerformed=false`, `durableWormCasObjectLockAndIndependentDrVerified=false`, `actualIndependentReviewerOrStagingAuthorizationVerified=false`, `productionSourceUnfreezeOrCredentialEnrollmentPossible=false`. Outputs are frozen redacted metadata, no raw keys, signatures, hashes, organizations or evidence bytes.

**No actual authority has been received**: approved eMudhra sandbox credentials, independently verified CCA/RCAI/eMudhra issuer/CRL/OCSP, MCA legal mandate, genuine separately enrolled external provider/reviewer identity, authenticated remote archive/gossip/TLS, WORM/CAS/DR and signed nonauthor staging are pending. No main merge, real provider activation, financial/stock/tax/customer/supplier/PO/GRN production actions, production source unfreeze or deployment.
