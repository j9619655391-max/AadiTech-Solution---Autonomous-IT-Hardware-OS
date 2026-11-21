# Phase 1DY — Offline external-admission prerequisites and incident-unfreeze review HARD HOLD

**Date:** 21 November 2026 IST. **Canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Branch:** `chore/phase0-foundation-20261106`. PR #1 remains **OPEN/DRAFT/UNMERGED** against unchanged `main`. Issue #2 remains **OPEN**. **All authority and evidence claims below are applicant-controlled. This phase is deliberately read-only and nonproduction.**

## Exact trust boundary

Phase 1DU checks an applicant-supplied 2–6-epoch signed Legal/Registry witness rollover and v2 checkpoints. Phase 1DV verifies two detached offline observer signatures on applicant-supplied archive bytes. Phase 1DW adds four applicant-supplied Legal/Security/Registry/Provider key- and revocation-status signatures. Phase 1DX checks three *claimed* publisher/archive/revocation source byte receipts and a three-stage read-only incident recovery rehearsal signed by two candidate custodians. **No previous phase has enrolled an independent legal/issuer/source authority, made an authenticated live external fetch, persisted a trusted anchor, or accepted production.**

Phase 1DY introduces an **offline-only evidence/authority preflight and five-signer independent-*claimed* incident review, always RELEASE HOLD**. Its new `scripts/phase1dy-offline-source-admission-unfreeze-preconditions.mjs` exports:
- `assessOfflineAdmissionUnfreezePreconditionsDy(args)`;
- `inventoryDigestDy(authorityInventory)`, `frozenCaseDigestDy(decisionCase)`;
- `oversightSigningBytesDy(role,statement)`, `oversightSetDigestDy(roleOrderedStatements)`, `reviewSigningBytesDy(role,statement)`;
- immutable `DY_REQUIRED_GATES`, `DY_OVERSIGHT_ROLES`, `DY_REVIEW_ROLES`.

### Authority prerequisites — no self-attestation is sufficient

An **exact** 12-gate map is mandatory. Each entry has exactly `{state,evidenceSha256,observedAt}`. Permitted states are **`MISSING`** (digest is 64 zeroes and `observedAt=null`), **`PRESENT_UNVERIFIED`** and **`REJECTED`** (both have nonzero digest and explicit canonical UTC observation). Even a complete inventory of `PRESENT_UNVERIFIED` never yields real trust, irrespective of signer count. `VERIFIED`, `APPROVED`, `PRODUCTION_READY`, extra keys, impossible timestamp claims and altered inventory digests are rejected. Externally issued signatures are **not** accepted merely by pointing to a SHA-256.

| Gate ID | What real independent owners must eventually authenticate |
| --- | --- |
| `PROVIDER_WRITTEN_AGREEMENT` | Signed provider agreement authorizing this particular account/workflow |
| `APPROVED_SANDBOX_CREDENTIAL_CUSTODY` | Named provider-issued credentials in approved secrets manager only |
| `CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY` | Independently verified official chain, certificate policy, KU/EKU and intended usage |
| `LIVE_ISSUER_SIGNED_CRL_OCSP` | Issuer/responder authenticated serial, nonce, thisUpdate/nextUpdate, revoked status |
| `MCA_LEGAL_AND_SIGNATORY_MANDATE` | Independently verified Indian company, mandate, legal signatory appointment |
| `INDEPENDENT_KEY_ENROLLMENT` | Verified external signer/operator key custody, authority and separated roles |
| `AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES` | Real approved HTTPS host identity, TLS peer+chain, bounded no-redirect source bytes |
| `WORM_CAS_SIGNED_ANTI_EQUIVOCATION` | External immutable object retention, CAS/compare-and-swap, signed durable high-watermarks |
| `TRUSTED_TIMESTAMP_SOURCE` | Independent accountable clock and timestamp evidence |
| `INDEPENDENT_DR_RESTORE_ACCEPTANCE` | Isolated verified recovery, signed RTO/RPO, denied-delete/object-lock tests |
| `PROTECTED_MAIN_NONAUTHOR_REVIEWS` | Enforceable protected main/CODEOWNERS, genuine two nonauthor reviewer approvals |
| `INDEPENDENT_STAGING_RELEASE_SIGNOFF` | Distinct Security/Business/Operations staging signatures and workload proof |

**Never put original identities, private company records, provider credentials, live certificates, CRL/OCSP response bytes or external evidence into this repository, chats or issue comments.** A reviewer must independently verify official evidence through approved provider/legal custody and separately record redacted verification receipts.

### Exact bounded candidate input

```js
assessOfflineAdmissionUnfreezePreconditionsDy({
  rehearsalCandidate,       // entire original Phase 1DX packets, not a trusted summary
  authorityInventory,       // exact 12 self-reported MISSING/PRESENT_UNVERIFIED/REJECTED
  previousObservationAnchor,// {sequence,digestSha256,observedAt}, caller supplied
  decisionCase,             // exact previously frozen source+recovery+inventory scope
  oversightPins,            // two separate role/signer/operator/organization pins
  oversightPackets,         // two Ed25519 signed "OBSERVE_FROZEN_ONLY" receipts
  reviewPins,               // three distinct legal/security/operations pins
  reviewPackets,            // three Ed25519 signed "REVIEW_HOLD_ONLY" receipts
  now                       // caller supplied canonical UTC string, never trusted time
});
```

Whole input is bounded to **1,536 KiB**; the authority inventory to **32 KiB**, each signature statement to **8 KiB** and each signed packet to **12 KiB**. Top-level fields, gates, pinned signer identities, signed packets and frozen decision case must match their *exact* key sets; no permissive approval extensions. The verifier **re-executes original 1DX/1DW/1DV/1DU mathematical checks over original input packets**, never trusting a caller boolean or report.

A candidate incident case must bind the original signed organization, source and main SHA, terminal checkpoint and archive hashes, current synthetic revocation digest, original DX three-receipt evidence-set digest and final read-only recovery step digest; it must bind its own exact inventory SHA-256 and the supplied previous observation high-watermark, increment the sequence **exactly by one**, retain original challenge nonce and use a separate fresh review nonce. The case must be frozen at the original last DX read-only rehearsal step, strictly after the claimed previous observation anchor, with `decision='REMAINS_FROZEN'`. **The previous anchor, sequence and UTC clock are caller-supplied—not independently durable anti-rollback protection.**

Two candidate oversight signer roles must separately sign that exact frozen case: `SOURCE_INTEGRITY_OVERSIGHT` and `RECOVERY_FREEZE_OVERSIGHT`. Both carry `disposition='OBSERVE_FROZEN_ONLY'`. The role-ordered digest of their exact signed statements binds three further candidate reviewers: `LEGAL_UNFREEZE_REVIEW`, `SECURITY_UNFREEZE_REVIEW`, `OPERATIONS_UNFREEZE_REVIEW`, each requiring `disposition='REVIEW_HOLD_ONLY'`. Each reviewer signs the same source/main/incident/evidence/ledger/inventory/case/previous anchor/sequence/challenge/review nonce and two-oversight digest. The dual source views may not fork, and the three reviews must occur **no earlier than the latest oversight observation**; all signed observations have explicit bounded timestamp/expiry limits.

**Signer/key separation is local math only.** All five new Ed25519 key IDs, SPKI SHA-256, operator IDs and candidate organizations must differ among themselves and from prior DX retrieval/recovery, DW custodian/revocation and DV observer identities; none may reuse any Legal/Registry witness signing key in the supplied multi-epoch history. All pins/organizations can still be controlled by the same applicant; syntactic distinctness is NOT independent enrollment or legal authority.

### Incident-unfreeze denial, fork handling and recovery handoff

A fully valid five-signature *synthetic* case may only report `candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly=true`; it **must never** report GO, independent evidence acceptance, a live unfreeze, a regulator/CA/issuer assertion or production readiness. Any signed `GO`, fake `AUTHORIZED_UNFREEZE`, promoted checklist `VERIFIED`, changed role or key, forged old/future timestamp, prior high-watermark substitution, upstream source byte fork, new review nonce replay, missing/stale/duplicate review, split-view source digest, extra field or predecessor mismatch yields anomaly codes and global HOLD. The evaluator has no HTTPS, DNS, signing authority, secrets manager, storage writer, real quarantine switch, break-glass unlock or deploy controls.

Real incident recovery, if separately authorized in future, must be a **new independently authenticated operational workflow**, not an escalation flag on this applicant-only structure. Before any real unfreeze: independently retrieve signed revocation and legal evidence and live trust status; validate provider-licensed organization/mandate and current key custody, compare externally published checkpoint and monotonic anti-equivocation high-watermark; independently validate WORM/CAS/object-lock and off-platform immutable anchor; perform real read-only DR restore/incident scope review; enforce sealed break-glass approval using independent identity, nonauthor reviewers and Security/Legal/Operations signatures on protected main/staging. A real cutover also requires source-specific role authorization and audited deployment; **none is available to this phase**.

## Verification and no-write invariants

**27 new Phase 1DY synthetic adversarial Node test groups** are appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`, covering fully internally consistent missing and unverified twelve-gate inventories, rejected evidence, false verified/approval gates, malformed status/time, signed inventory substitution, cross-role operator/key/organization impersonation, use of old DX custody and DU witness keys, dual-source signed forks, stale/expired/GO oversight receipts, replayed or altered previous anchor, signed fake unfreeze, role cloning, copied PEM/signature, review quorum/chronology failures, original history tampering and immutable redacted output.

Both `scripts/phase1bv-build-input-provenance.mjs` and `scripts/phase1bw-review-vendor-intake.mjs` include the new verifier in their governed source path lists. Run the focused suite with `node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs`. **Verified full engineering and initial documentation HEAD** `185af586a2637f5c761e2e5fc40e848bdbc8e8e4`: [push 44890833411](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44890833411) COMPLETED/SUCCESS (7 successful executed jobs + expected PR-only source-merge-lineage skip), [PR 44890837569](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44890837569) COMPLETED/SUCCESS (8/8), including baseline, immutable build/reviewer source custody, GitHub governance, disposable real MySQL and isolated Chromium smoke. GitHub Checks API reconciled **16/16** exact source SHA, check/job IDs, names, completed statuses and conclusions. Push baseline hosted logs contain **27 Phase 1DY synthetic test groups, 0 total Node test failures**. Hostile malformed `recoverySteps.at` input was made fail-closed, and actual cyclical/oversized nested payloads exercised strict input bounds in the final tests. This is **engineering-only** verification, never legal/CA/provider/release evidence. Recording this receipt produces a new documentation-only HEAD; the new exact HEAD push/PR CI must be independently verified rather than substituting 185af586.

**Fixed final output invariants:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'`, `currentExternalIndependentTrustGatesAuthenticated=0`, `independentlyAuthenticatedExternalUnfreezeApprovalVerified=false`, `actualProductionUnfreezeOrAutomaticReleasePossible=false`, `productionMutationOrSourceActivationPossible=false`. Only boolean/counter/anomaly-code metadata are returned; no raw keys, source endpoints, incident identities, hashes, nonce, certificate, evidence contents or signature bytes are exposed.

Production release, provider activation, real signing enrollment, customer/supplier messages, finance/stock/tax/PO/GRN transactions and `main` merge are **forbidden** by this phase. No synthetic test can grant independent organizational trust. PR #1 Draft/unmerged, Issue #2 OPEN, main unchanged until genuinely authorized external requirements are independently satisfied.
