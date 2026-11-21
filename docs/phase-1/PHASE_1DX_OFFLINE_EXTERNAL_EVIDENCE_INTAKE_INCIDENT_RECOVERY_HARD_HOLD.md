# Phase 1DX — Offline source-evidence intake and frozen incident-recovery rehearsal HARD HOLD

**Date:** 21 November 2026 IST. **Canonical repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, development branch `chore/phase0-foundation-20261106`. PR #1 remains **OPEN/DRAFT/UNMERGED**; Issue #2 **OPEN**; `main` immutable and unmerged. This phase does **not** perform external onboarding, mutable key enrollment, remote evidence retrieval, trust promotion, production deployment or incident unfreeze.

## Security goal and boundaries

Phase 1DU verifies an applicant-supplied multi-epoch four-way LEGAL/REGISTRY witness rotation and fully signed v2 checkpoints; 1DV compares applicant-supplied two-observer signatures against local archive bytes; 1DW checks separately claimed Legal/Security custodian and Registry/Provider revocation-source signatures. **None of these establish independently authenticated external organizations, keys, endpoints, legal authority or revocation sources.**

Phase 1DX's new `scripts/phase1dx-offline-evidence-incident-recovery.mjs` is a **pure offline, deterministic, fail-closed verifier**. It is intended to stop a plausible-looking collection of *local* source receipts or recovery paperwork from ever being misrepresented as a verified external publication or production recovery approval. Inputs remain caller-generated. Synthetic Ed25519 fixtures in CI are **not** evidence of MCA authority, RCAI/eMudhra/CCA issuer signatures, true TLS connections, WORM retention, independent disaster recovery or external acceptance.

### Exact input and bounded API

```js
assessOfflineEvidenceIncidentRecoveryCandidate({
  custodyCandidate,       // complete 1DW source packet, NOT a boolean summary
  sourceReceipts,         // exactly three domain-separated Ed25519 candidate packets
  sourcePins,             // three detached signer/operator/TLS/endpoint comparison pins
  sourceBytes,            // three canonical base64 *locally supplied* payloads
  previousRecoveryAnchor, // {sequence, digestSha256}, untrusted caller anchor
  incident,               // source-fork FREEZE rehearsal scope
  recoverySteps,          // three SHA-256 linked, read-only simulated steps
  recoverySigners,        // exactly two signatures over final step digest
  recoveryPins,           // distinct Legal and Security recovery custodian pins
  now                     // explicit canonical UTC; caller supplied
});
```

Input JSON limit **1,280 KiB**, canonical per-source bytes at most **16 KiB** (base64 size <=24 KiB), canonical signing statement at most **8 KiB**, signed packet at most **12 KiB**. All top-level fields, source roles, pins, receipt statements, incident, steps, recovery signer statements and anchors use exact schema; foreign `approved`, `GO`, `release` and certificate promotion fields cannot be admitted.

The validator ALWAYS returns `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'` even for fully mathematical consistency. It never logs or returns PEM, signed contents, full archive or revocation bytes, source endpoint/key IDs, nonce, incident identity or detailed internal signers. Report and anomaly code array are frozen.

### Local source-evidence admission (NOT actual retrieval)

Require exactly one signed statement for each role:
- `PUBLISHER_RETRIEVAL`
- `ARCHIVE_RETRIEVAL`
- `REVOCATION_RETRIEVAL`

The first two submitted byte arrays must hash to the **same** original Phase 1DV checkpoint archive SHA-256, and the revocation bytes must exactly equal canonical bytes of the original 1DW previous anchor and current revocation state. SHA-256 and signing bytes are domain separated, with a strict role-ordered three-statement candidate evidence-set digest. The receipt signs source HEAD, main base, organization ID, terminal fully signed v2 checkpoint digest, archive and revocation digest, challenge nonce, detached operator ID/organization/key ID/SPKI, claimed endpoint and TLS-peer SPKI, SHA-256 of the actual supplied bytes, HTTP 200/no redirect claim, observed time/expiry and immutable HOLD. Replaying/duplicating roles, an independently re-signed conflicting byte payload, a changed HTTP redirect/status, mismatched detached pin, expired receipt or modified upstream DU/DV/DW history fails closed.

Key IDs, public SPKI hashes, operator IDs/organizations, endpoint hostname and claimed TLS-peer pins must not collide across new roles, old DW custodians/revocation signers, DV observer identities or history LEGAL/REGISTRY signing identities. These equality constraints are **local syntactic checks**. Even distinct operator labels are NOT proof of actual independent organizations or key custody. There is no HTTPS request, no real DNS/TLS validation, no trusted external source, no certificate policy/issuer/CRL/OCSP validation and no off-platform signed high-watermark.

### Incident freeze, quarantine and recovery rehearsal (NEVER thaw)

- Exact incident kind `UNTRUSTED_SOURCE_FORK_FREEZE_REHEARSAL`, decision `FREEZE`, same source/checkpoint/organization/archive/revocation/challenge and signed three-receipt candidate set digest. The previous recovery sequence/digest is provided by the *applicant*, not an independently durable anchor.
- Require exactly three sequential, strictly increasing UTC steps with unique signed-in-final-chain step nonces and predecessor SHA-256 digests, starting `previousRecoveryAnchor.sequence + 1`: `FREEZE_EVIDENCE` → `QUARANTINE_SOURCES` → `READ_ONLY_RESTORE_REHEARSAL`. Each step has `decision='HOLD'`; any `UNFREEZE`, `GO`, rewind, missing step, reordered clock, fork, duplicate nonce or digest substitution fails.
- Require exactly one detached Ed25519 signature each from `LEGAL_RECOVERY_CUSTODIAN` and `SECURITY_RECOVERY_CUSTODIAN`, over the **final** linked recovery digest and exact incident, evidence-set, source/main/organization, previous recovery digest, sequence, current revocation digest, original challenge and `decision='REHEARSAL_ONLY_HOLD'`. Signed observed time must follow completion of the final rehearsal step. No signatures can authorize deployment, turn a source back on, bypass revocation, or override earlier HOLD.

The simulation is stateless, so it **cannot** persist a freeze, actually quarantine source traffic, perform storage restore, verify remote object locks, observe a live outage, issue credentials or enforce a production unfreeze. A passing local simulated rehearsal is only a cryptographic/formal prerequisite.

### Synthetic adversarial coverage and source-input custody

**23 new 1DX Node test groups**, appended to the existing Phase 1DT/1DU/1DV/1DW signature fixture suite:
- Candidate mathematical valid case never grants GO; primary, mirror and revocation byte tamper; canonical revocation JSON mismatch despite re-signing; duplicate role/signers; HTTP status/redirect/GO fraud; signer key/SPKI/signature swap; source endpoint/transport/operator/key/organization collision with other sources and old observers/DW roles.
- Historical signed DU/1DW mutation; source-fork incident mismatch; recovery previous anchor replay/rollback; stage sequence, stage name, digest, nonce, time and explicit GO/unfreeze tamper; properly re-signed but wrong final recovery claim; missing/copy-pasted recovery signatures; stale/early custodian approval; fake external approval extension; malformed schema; redacted immutable output and all true external-authority flags remaining **false**.

Both Phase 1BV `BUILD_INPUT_PATHS` and Phase 1BW `GOVERNED_INPUTS` now include `scripts/phase1dx-offline-evidence-incident-recovery.mjs`.

Run focused tests:
```sh
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Engineering CI acceptance:** after the final code *and documentation* commit, independently confirm the exact HEAD source SHA matches both completed GitHub-hosted push and PR workflows; baseline, build/review source custody, governance, production runtime, disposable MySQL and isolated Chromium smoke all pass. The push-only `source-merge-lineage-hold` skip is expected. Do not substitute previous commits or call a failed intermediate workflow green. See the PR #1 and Issue #2 final external trace for the final HEAD and run IDs.

## Real external authority prerequisite handoff — NOT COMPLETED

Only a named authorized operator with a written provider agreement, independent Legal/MCA verified appointment and approved secrets manager credentials may initiate separate authenticated external intake. It requires all of:

1. **Identity and legal mandate:** out-of-band independent MCA corporate registration and signatory authority verification, current mandate and revocation status, independently enrolled Legal/Security/Registry/provider/custodian SPKI identity and documented separation of duty.
2. **Trust provider:** eMudhra/CCA/RCAI certificate chain, signed and current issuer-sourced CRL/OCSP (or scoped trusted responder chain) with status, nonce, this/next-update, serial and policy/KU/EKU checks; live CA enrollment explicitly provider-approved. Do not treat a generic signed JSON list as CA revocation evidence.
3. **Actual independent retrieval:** allowlisted HTTPS host from trusted enrollment record, bounded read-only fetch with SSRF/rebinding/redirect prevention, independent TLS chain/hostname and peer SPKI checks, exact retrieved bytes, real source-owning organizations and independently verified external publication/anchor/CAS/WORM and anti-equivocation high-watermark.
4. **Real incident governance:** trusted time and independently persisted freeze/high-watermark, compromise notification, signed independent restore and delete-denial test, RTO/RPO evidence, cross-source loss-of-trust escalation, no auto-unfreeze and new out-of-band Legal/Security approval.
5. **Release governance:** protected `main` with enforceable ruleset/CODEOWNERS/two nonauthor reviewers, verified signed OIDC/SLSA CI, official Security/Business/Operations staging signoffs and documented organizational release authority. Production remains HOLD until all real external gates independently pass.

Never commit credentials, private signatures, company identity artifacts, supplier/customer/finance records or raw external evidence to this repository/chat. Redacted external receipts belong only in approved external custody. **Synthetic CI signatures cannot be promoted to real authority.**

**Nonnegotiable:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`, no source activation or production transaction, PR #1 Draft/unmerged, Issue #2 OPEN, `main` unchanged.
