# Phase 1EB — Offline cross-run gossip fork and incident-recovery evidence custody HARD HOLD

**Date:** 21 November 2026 IST. **Only canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`. PR #1 stays **OPEN/DRAFT/UNMERGED**; Issue #2 **OPEN**; `main` unchanged.

## Security purpose and strict limits

Phase 1DU–1DZ check original multi-epoch v2 signed Legal/Registry observer/witness, archive/CRL-status candidate, frozen incident-rehearsal and locally signed anchor continuity. Phase 1EA compares three applicant-provided, role-signed complete 2–4-epoch offline gossip vectors, plus two Legal/Security `CONTINUE_FREEZE_NO_AUTHORITY` signatures. **None of these phases has authenticated a genuine external endpoint, CA issuer, legal mandate, enrolled independent external organization, provider agreement, live signed CRL/OCSP, WORM/CAS storage or protected main release approval.**

**Phase 1EB** does not pretend to resolve those real-world omissions. It adds a **pure read-only, deterministic offline verifier** that binds one original Phase 1EA signed gossip transcript to a subsequent two-run, six-*candidate*-witness freeze/retention chain and two further Legal/Security retention-HOLD receipts. It detects forks, replay and time/order drift *within the submitted candidate packets only*. Replaying identical source histories from two distinct claimed keys is not independently sourced cross-system consensus.

**Implementation:** `scripts/phase1eb-offline-cross-run-gossip-incident-custody.mjs`.

Exports:
- `EB_RUN_ROLES`: `RUN1_ARCHIVE`, `RUN1_REGISTRY`, `RUN1_RECOVERY`, `RUN2_ARCHIVE`, `RUN2_REGISTRY`, `RUN2_RECOVERY`.
- `EB_CUSTODY_ROLES`: `LEGAL_INCIDENT_RETENTION`, `SECURITY_INCIDENT_RETENTION`.
- `assessOfflineCrossRunGossipIncidentCustodyEb(args)`: exact-schema bounded deny-only assessment.
- `gossipHandoffDigestEb(ea)`, `runDigestEb(record)`, `runPeerSigningBytesEb(role,stmt)`, `custodySigningBytesEb(role,stmt)`: canonical, domain-separated SHA-256 and Ed25519 signed-scope helpers, never remotely trusted identities.

## Exact input and original verification

```js
assessOfflineCrossRunGossipIncidentCustodyEb({
  gossipCandidate,      // COMPLETE ORIGINAL Phase 1EA candidate, not a summary boolean
  previousRunAnchor,    // supplied {sequence,digestSha256,observedAt}; not durable
  runs,                 // exactly 2 linked records, each signed by exactly 3 distinct peer roles
  peerPins,             // 6 detached role-specific key/SPKI/operator/org comparison pins
  custodyPins,          // 2 detached Legal/Security candidate custodian identities
  custodyPackets,       // 2 Ed25519 signed NO-UNFREEZE, 30+-day retention claims
  now                   // applicant provided strict canonical UTC; NOT a trusted clock
});
```

Global JSON input size limit **3 MiB**, each run bounded to **47 KiB**, individual signed statement **8 KiB**, signed packet **12 KiB**, handoff proof **26 KiB**. Unexpected keys, cyclic/oversized input or wrong base64/signature/pin fail closed. All signed roles and records have exact version-1 schemas. Original entire Phase 1EA/DZ/DY/DX/DW/DV/DU synthetic packet chain is independently re-evaluated by the validator, not accepted from a user-controlled `verified` flag. The prior EA freeze review set is not omitted: the caller-supplied predecessor handoff digest domain-binds ordered complete **original three EA gossip statements and two freeze review statements**, the original admission denial claim, original verified epoch-view vector and source/incident context.

The supplied `previousRunAnchor` must match **that exact** prior gossip handoff digest and the original Phase 1DZ terminal epoch sequence. Its claimed timestamp must be no earlier than the final prior Phase 1EA Legal/Security review and inside the bounded input UTC window. **The anchor is applicant supplied.** The code cannot detect a real remote rollback if all presented packets are maliciously regenerated, and it does not independently persist or lock the high-watermark.

## Two-run fork/replay and custody guards

Each of **two consecutive cross-run records** has exact `kind='UNTRUSTED_OFFLINE_GOSSIP_REPLAY_FREEZE'` and `decision='HOLD'`. Every record must preserve original source/main SHA, organization, incident, original 1DZ terminal epoch sequence/anchor hash, evidence-bundle SHA and original 1EA entire epoch-vector SHA. It also binds the prior EA handoff digest, one fresh unique nonce, previous-run sequence and exact predecessor digest, strict `sequence=previous+1`, strictly increasing candidate timestamps and a maximum input-clock skew. Every run record is domain-separated SHA-256 hashed. The **six** role-separated Ed25519 observation receipts (three roles per run) must sign the *same exact record* and digest with their own detached signer IDs/SPKI/operator/organization pins, bounded expiry and `disposition='OBSERVE_FROZEN_ONLY'`. Any signed peer split-view, altered anchor, missing peer, duplicated role/signature, changed original source, old witness key, source/nonce replay or re-signed contradictory run denies consistency.

After the two complete runs, require **two** further independent-*claimed* signed incident custody receipts for Legal and Security. These bind original EA handoff, original predecessor, first and final run digests, final run sequence, original organization/source SHA/incident, original epoch vector and evidence bundle, original DY review challenge nonce, strictly later UTC, and `disposition='RETAIN_QUARANTINE_HOLD_NO_UNFREEZE'`. Both receipts must claim the same retentionUntil at least **30 days** after caller `now`; too short, expired, conflicting dates, changed source or terminal digest, copied Legal or Security signatures, or any `GO`/`DELETE`/`UNFREEZE` request is invalid.

All eight new candidate keys, Ed25519 SPKIs, operator IDs and organization labels must be pairwise distinct and different from every prior 1EA, 1DZ, 1DY, 1DX, 1DW, 1DV and historical 1DU Legal/Registry witness identity. This is **purely syntactic separation**; all eight private keys can still be owned by the same test/applicant. A claimed 30-day retention is not an actual WORM lock, CAS, deletion-denial audit, durable anchor, independent DR restoration or incident freeze/unfreeze governance.

### Negative assurances that never change

For **every** caller input, including perfect synthetic cryptographic mathematical consistency, the output is a frozen redacted report with:
- `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision='HOLD'`.
- `realRemoteGossipAndAntiEquivocationGossipPerformed=false`.
- `externallyPersistedSignedHighwatermarkOrCasVerified=false`.
- `actualDurableWormRetentionDeleteDenialOrDrRestoreVerified=false`.
- `realProviderMcaLegalRcaIEdmudhraCcaIssuerTrustVerified=false`.
- `freshLiveSignedIssuerCrlOcspAuthenticated=false`.
- `independentLegalSecurityProductionUnfreezeApproval=false`.
- `productionSourceActivationOrExternalEnrollmentPossible=false`.

No source URL, private/public PEM, signature, nonce, signer identity, archive content or digest is returned; results contain only boolean/count metadata and sorted anomaly codes. No API, browser, external HTTPS, database mutation, upload, deletion, credential enrollment, source activation or production release operation exists in this module.

## Synthetic adversarial suite and CI

**22 new Phase 1EB test groups** appended to `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs` alongside 1DT–1EA fixtures. Tests include positive mathematical six+two signing but HOLD, signed RUN1/RUN2 GO denial, complete re-signed source fork, re-signed sequence jump/rollback, previous handoff/time substitution, run/nonce replay, altered witness signed view, missing/cloned role, old EA key reuse, across-run signer/organization collision, PEM/signature copy, early/stale/future peer, custody DELETE/UNFREEZE and forged first/final hash, short or conflicting retention, missing Legal/Security, signed historic parent mutation, malformed nested history, cyclic/oversized input, exact schema and redacted immutable output. All tests use generated **synthetic** Ed25519 keys and locally supplied clocks; no approved production keys.

Both Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` list `scripts/phase1eb-offline-cross-run-gossip-incident-custody.mjs`.

Focused test:
```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

Required GitHub CI acceptance: exact final code+documentation source SHA, both `push` and `pull_request` workflows COMPLETED/SUCCESS; push 7 executed jobs pass and PR-only lineage expected SKIPPED, PR 8/8 successful. All Checks API records **16/16** reconcile to Actions job ID, exact source SHA, completed status, name and conclusion. Baseline Node, build provenance, reviewer custody, GitHub governance, independent evidence HOLD, production-runtime-scope and disposable MySQL/isolated Chromium must pass. **A prior green SHA cannot establish latest source CI.** Final CI trace belongs in Draft PR #1 and open Issue #2.

## Real external prerequisites still NOT satisfied

Before any real provider onboarding, genuine source validation, WORM retention or production release, responsible authorized external parties must supply via independent approved systems: written provider license/sandbox agreement and credentials in a secrets manager; MCA-verified corporate legal mandate and signatory appointment; CCA/RCAI/eMudhra certificate hierarchy and certificate policy, signed fresh issuer CRL/OCSP/nonce/serial/status; verified separate organizational key custody and enrolled independent identities; actual authenticated allowlisted source HTTPS/TLS/hostname/peer SPKI and byte retrieval with SSRF/redirect prevention; off-platform independently signed anti-equivocation gossip, immutable WORM/CAS high-watermark and delete-denial/DR test; trustworthy independent timestamps; protected-main CODEOWNERS with two genuine nonauthor approvals; real signed Security/Business/Operations staging authorization.

No genuine credentials, private company identity data, secrets, issuer evidence or raw external signing material should be placed into Git, PR #1, Issue #2 or this chat. **Applicant-created signatures and a green synthetic CI do not confer external authority.** No `main` merge, production transaction, deployment, provider activation, issuance, supplier/customer/finance/stock/tax/PO/GRN action or source unfreeze occurs in Phase 1EB.
