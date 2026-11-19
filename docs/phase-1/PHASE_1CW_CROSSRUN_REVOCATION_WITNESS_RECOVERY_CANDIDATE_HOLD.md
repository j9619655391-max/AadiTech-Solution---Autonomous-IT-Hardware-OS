# Phase 1CW — Candidate key enrollment, revocation, cross-run checkpoint and recovery hardening (HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Engineering branch:** `chore/phase0-foundation-20261106`  
**Governance:** PR #1 remains Draft/unmerged, Issue #2 OPEN, protected `main` not modified.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Scope and security boundary

Phase 1CV verifies that two **operator-supplied** Security/Business Ed25519 signatures match a frozen pair of GitHub `main` protection observations and a **locally supplied** monotonic checkpoint. Cryptographic consistency is narrower than legally authenticated enrollment, genuine live revocation publication, independently witnessed high-watermarks or a tested offsite recovery.

Phase 1CW adds a candidate-only cross-run continuity and recovery preflight. Its `assessCrossRunRecoveryCandidate` re-runs Phase 1CV's detached candidate check and requires the **next checkpoint** to chain exactly from the preceding Phase 1CV signed digest and epoch. It validates distinct role-key SPKIs and claimed pins, a signed revocation statement with a strictly monotonic version/previous digest, two separate signed witness assertions on the identical checkpoint+revocation+nonce, and a signed recovery auditor claim tied to the object version, archived policy digest and separate recovery region. All claims are checked mathematically against local source objects only. This is not an external authority verifier.

## Explicit operator mode

After external Security, Business, revocation, witness and DR authorities are genuinely onboarded through approved independent processes, an authorized person may perform **offline inspection of a candidate file**:

```sh
node scripts/phase1cw-crossrun-revocation-recovery-candidate.mjs \
  --inspect-offrepo-candidate /approved/offrepo/phase1cw-candidate.json
```

It only accepts a regular non-symlink file up to 256 KiB; no GitHub, external provider, storage, PKI or issuer network requests are made. It refuses `GITHUB_ACTIONS=true`. This step does **not** collect or confirm any external authorization by itself. No API keys, company signing private keys, reviewer logins, legal artifacts or passwords should be supplied in chat or committed to Git. The CLI returns nonzero if the candidate is mathematically inconsistent.

The candidate object has precisely these top-level logical inputs:

- `cvEvidence`: Phase 1CV `before`, `after`, `statement`, `signatures`, `registry`, `checkpoint` raw source records. The Phase 1CV validator independently re-verifies their two detached Ed25519 role signatures and exact source, main, policy fingerprint, run IDs, clock, epoch and previous digest.
- `roster`: six role-named public key records with `keyId`, `publicKeyPem` (Ed25519 SPKI), `spkiSha256`, `validFrom`, `validUntil`. The two Security/Business roster keys **must match** Phase 1CV's actual verified candidate key records. Keys must be distinct, unexpired and not actively listed as revoked.
- `operatorPins`: six operator-supplied SPKI SHA-256 fingerprints matching the roster, exactly one per role. **They are not authenticated just because they were submitted separately in the JSON.** True out-of-band independent enrollment must happen outside this code.
- `previous`: supplied prior high-watermark `epoch`, `checkpointDigest`, `revocationVersion`, `revocationDigest`, `observedAt`. Previous epoch and digest must match the exact previously signed Phase 1CV candidate. This is *local continuity*, not persistent external CAS.
- `checkpoint`: schema version, exact repo/head/base, frozen Phase 1CV policy fingerprint and candidate signature digest, push/PR run IDs, `epoch=previous.epoch+1`, `previousDigest`, nonzero unique challenge nonce, object version, archived policy digest, primary region, canonical `issuedAt`/`expiresAt`. Its digest is over domain-separated canonical JSON.
- `revocation`: `statement` + signed detached `signature` by `REVOCATION_AUTHORITY`. Statement includes exact current checkpoint digest, `version=previous.revocationVersion+1`, signed previous revocation digest, bounded sorted distinct revoked key IDs and fresh issuance/expiry. Revoking **any** active key used by the chain denies the candidate.
- `witnesses`: **exactly two** separately signed statements (`CHECKPOINT_WITNESS_A` and `CHECKPOINT_WITNESS_B`) claiming different endpoint hostnames but the same current source SHA, checkpoint digest, revocation digest, epoch, challenge nonce and valid time window. If any differs, the chain is held as fork/stale/corrupt. Distinct hostname claims alone are **not TLS or organizational independence proof**.
- `recovery`: separate `RECOVERY_AUDITOR` signed statement claiming exact checkpoint and revocation digest, same archive/object version, a recovery region different from the primary, successful restore/hash match and delete denial, and a future retention date. These remain **claimed** facts until independently measured against a real WORM storage provider and DR drill.

Six exact role names are required: `SECURITY_WITNESS`, `BUSINESS_WITNESS`, `REVOCATION_AUTHORITY`, `CHECKPOINT_WITNESS_A`, `CHECKPOINT_WITNESS_B`, `RECOVERY_AUDITOR`. Each is a distinct nonrevoked Ed25519 SPKI. Current operator-pinned roster keys must not have duplicate IDs or reused fingerprints. Detached signatures use canonical base64 and role-specific domain-separated signed bytes:

```text
aaditech/phase1cw/checkpoint/v1\n
aaditech/phase1cw/revocation/v1\n
aaditech/phase1cw/observation/v1\n
aaditech/phase1cw/recovery/v1\n
```

Signature roles are limited to publisher revocation, witness A, witness B and recovery auditor; Security/Business are revalidated via the original Phase 1CV candidate. Fresh canonical timestamps (milliseconds in UTC) and expiry protect only the mathematical acceptance window. The clock is still locally supplied and is not a trusted timestamp authority.

## What the tool cannot claim

A successful result means only `candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent=true` for a **synthetic or externally supplied offline candidate**. It does not imply any of the following:

- That SPKI pins, corporate Security/Business mandates, reviewer permissions or revocation publisher keys were independently authenticated, legally enrolled, or checked against an approved PKI/TSA.
- That a revocation statement came from a genuine server with pinned TLS identity, authenticated RCAI/CCA/eMudhra CRL or OCSP signature, freshness, signer authorization, unrevoked issuing CA and accepted certificate policy.
- That the `previous` high-watermark was fetched from immutable off-repo storage, checkpoint compare-and-swap was atomic, double-spend/fork gossip happened or all offsite witnesses independently observed the event.
- That an actual S3 Object Lock COMPLIANCE object version, denied delete, offsite restore, independently measured RTO/RPO or legally accepted retention was executed. Boolean claims in a signed fixture are **not an operational test**.
- That production staging, real provider credentials, MCA legal identities, independent Security/Business acceptance, signed GitHub Actions OIDC/SLSA supply-chain provenance, live quote/finance/stock authorization or release governance passed.

A revoked or expired role key, conflicting witness, old challenge nonce, changed source SHA, stale checkpoint version, unsigned recovery, missing or denied evidence, or untrusted input must fail closed. The result deliberately retains `keysAndPinsIndependentlyEnrolledAndRoleMandated=false`, `independentlyRetrievedDurableMonotonicOffsiteAnchorVerified=false`, and all other external acceptance fields false, with **production HARD HOLD** regardless of mathematical validity.

## Implementation and tests

`scripts/phase1cw-crossrun-revocation-recovery-candidate.mjs` implements the bounded candidate input and pure verifier; `tests/phase1cw-crossrun-revocation-recovery-candidate.test.mjs` has **20 adversarial Node test groups**, using *ephemeral process-local* generated Ed25519 keys only. It exercises actual Phase 1CV candidate binding, stale head/base/run, reused/expired/revoked pins, version rollback/gap, wrong revocation authority and signature, missing or forked witnesses, duplicate host, false cross-region/retention/delete-denial/restore, malformed packet, and assurance that the printed report cannot leak private keys or authorized production states.

Exact Phase 1BV build inputs and Phase 1BW vendor-intake custody include the new script and tests. This phase makes **no changes** to `.github/workflows/ci.yml`, pinned third-party actions, permissions, GitHub admin rules, `main`, PR merge state, secret management or production service operations.

After pushing, verify the **new final commit's** GitHub Actions push and PR runs, baseline JS+TS+staging-security suites, frozen audit, disposable MySQL and Chromium MFA/role smoke, and official GitHub Check Runs vs Actions Jobs reconciliation. Previous Phase 1CV green runs are **not** evidence of Phase 1CW's code. Record exact new run IDs and any failures in PR #1 and Issue #2.

**Current real blockers at phase start (20 Nov 2026):** GitHub submitted PR reviews **0**, installed rulesets **0**, actual `main` CODEOWNERS unavailable; no independently approved corporate Security/Business nominator keys, live revocation source, offsite immutable checkpoint/DR, provider authority, MCA/CCA/eMudhra onboarding or external staging approvals. No real off-repo candidate verified or external key enrollment claimed.

**Release remains HARD HOLD — no live customer/supplier/provider actions, finance posting, merge or deployment.**


## Initial GitHub CI failure record — retained, never relabel green

The first Phase 1CW commit `6cc8112a69713748dfcecee1dc3c9c79bdc90df3` triggered push run [44632315888](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44632315888) and PR run [44632328257](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44632328257). Both initial **baseline** jobs FAILED the Typecheck stage. Hosted log reported `TS1005`/`TS1002` syntax failures at line 186 of `tests/phase1cw-crossrun-revocation-recovery-candidate.test.mjs`: the single-quoted test description had an unescaped apostrophe in `signer's`. The runtime verifier did not grant external GO; this was a test parser typo, not a verified successful baseline. Corrective action changes only that test description to `CV signer pinned public key`. New exact-commit push+PR CI must pass separately before declaring Phase 1CW internal engineering verified. Do not suppress, reinterpret or overwrite the initial failed results.
