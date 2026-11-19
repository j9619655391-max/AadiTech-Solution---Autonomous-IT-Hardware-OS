# Phase 1CV — Sampled policy freeze + detached candidate evidence intake (HARD HOLD)

**Recorded:** 19 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; development only: `chore/phase0-foundation-20261106`  
**Protected:** `main` remains untouched; PR #1 Draft/unmerged; Issue #2 OPEN.  
**Production:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Why this phase

Phase 1CU correlates genuine GitHub live read-only PR approvals, named reviewer permissions, effective protected-main ruleset details, CODEOWNERS and exact finished push+PR checks. All of these observations have **time-of-check/time-of-use** (TOCTOU) risk: a reviewer approval may be dismissed, `main` rules edited, CODEOWNERS altered or the PR HEAD updated after an otherwise accurate read. Separate historic green CI does not prove current protection or external provenance.

The Phase 1CV operator preflight performs **two independent full Phase 1CU read-only governance handoffs**, each with additional actual ruleset list/details and exact main CODEOWNERS Git blob metadata/byte verification. It computes a SHA-256 fingerprint over head/base SHA, completed workflow run IDs, Phase 1CU custody checksum, sorted actual ruleset IDs and *full* observed detail records (including bypass actors), and verified CODEOWNERS SHA/content digest. Both fingerprints must be **identical** before accepting any candidate signature.

The second live observation happens **after** the operator's detached candidate packet has been loaded from a local approved off-repo file. No single cached policy object is reused across observations. **Limits:** this is a sampled read-only drift detector; a transient policy change and complete reversion (ABA) between samples may be invisible. Only independently durable off-repo logs, anchored high-watermarks, append-only witnesses and admin event records can materially close that residual risk.

## Two approved operator commands

The tool never runs in GitHub-hosted Actions (it refuses `GITHUB_ACTIONS=true`). Actual reviewer account names must come only from **verified corporate Security/Business appointments**, never from a synthetic fixture or guessed label. Read-only GitHub credentials must be injected securely as `GITHUB_READ_TOKEN`. Do not paste tokens, keys, personal or company credentials into Git, chat, PR comments, CI artifacts or shell history.

First, after installing and independently verifying the actual `main` ruleset/CODEOWNERS and obtaining real latest-head reviewer decisions, collect the current candidate fingerprint:

```sh
node scripts/phase1cv-policy-freeze-detached-candidate.mjs \
  --capture-fingerprint PUSH_RUN_ID PR_RUN_ID AUTHORIZED_SECURITY_GITHUB_LOGIN AUTHORIZED_BUSINESS_GITHUB_LOGIN
```

This command performs a fresh complete Phase 1CU handoff and reads actual main rulesets/CODEOWNERS again. It returns only a **local unsigned observation checksum** and HOLD flags. In the repository's current state (zero approved reviews and zero installed rulesets), it exits **nonzero**. Never generate a signature based on a failed snapshot.

Second, after external personnel with **independently authenticated** Security and Business signing authority have prepared a detached candidate file in an approved off-repo evidence store:

```sh
node scripts/phase1cv-policy-freeze-detached-candidate.mjs \
  --verify-signed-freeze PUSH_RUN_ID PR_RUN_ID AUTHORIZED_SECURITY_GITHUB_LOGIN AUTHORIZED_BUSINESS_GITHUB_LOGIN \
  /approved/offrepo/phase1cv-candidate.json
```

A signed candidate file is JSON with four exact top-level logical records: `statement`, `signatures`, `registry`, and `checkpoint`. Its format is **candidate-only**; none of these values becomes a trusted external enrollment merely because a cryptographic verification succeeds.

```text
statement:
  schemaVersion: 1
  kind: CANDIDATE_OFFREPO_POLICY_FREEZE
  repository: exact repo
  sourceHeadSha, mainBaseSha: exact 40-char lowercase Git commit SHAs
  pushRunId, prRunId: positive safe integer workflow run IDs
  policyFingerprintSha256: SHA-256 of the exact Phase 1CV snapshot
  nonce: unique, nonzero 64-char lowercase hex
  epoch: strictly previous checkpoint epoch + 1
  previousDigest: exact previous checkpoint lastDigest
  issuedAt, expiresAt: canonical millisecond Z timestamps
  releaseDecision: HOLD

signatures: exactly two records
  role: SECURITY_WITNESS or BUSINESS_WITNESS (one each)
  keyId: exact claimed registry keyId
  algorithm: Ed25519
  signature: canonical base64 of 64 detached signature bytes

registry: exactly the two role-named claimed public key records
  keyId, publicKeyPem (SPKI Ed25519), spkiSha256,
  validFrom, validUntil, revoked:false

checkpoint: epoch, lastDigest, observedAt
```

Signed bytes use domain separation:

```text
aaditech/phase1cv/policy-freeze-detached-candidate/v1\n
+ canonical JSON of the statement, with recursively lexicographically sorted keys
```

Strict verification requires a second independent live fingerprint identical to the first, full candidate schema, source/base/run/nonce/policy digest binding, unexpired issue window (max 15 minutes), monotonic epoch and prior digest, canonical base64 Ed25519 signatures, distinct SPKI key fingerprints for the two roles, no revoked/not-yet-valid/expired keys, and GitHub-sourced technical prerequisites. **All responses are still a HOLD.**

## Hard trust boundaries

- The `registry` is supplied by the operator. SPKI hashing and detached signature verification demonstrate that **someone controlling the corresponding test/candidate private keys** signed the stated bytes; they do **not** prove independent corporate appointment, public-key authenticity or revocation status with a trusted authority.
- The `checkpoint` is supplied by the operator. Local `epoch+1` and previous-digest consistency does **not** prove remotely persisted, monotonic, atomic CAS or globally witnessed anti-replay. Cross-run offsite gossip, prior checkpoint retrieval, signed time and trust-anchor lifecycle are still needed.
- The `issuedAt` / `expiresAt` check relies on local operator time. Local timestamps are **not** independently timestamp-authority authenticated.
- Actual GitHub REST is used only for read-only technical source observation. It is **not** an independent cryptographic GitHub Actions OIDC/SLSA workload signature or a no-admin-bypass guarantee when GitHub hides `bypass_actors`. Any hidden field causes a HOLD.
- The script does not fetch an off-repo signed object or authenticate TLS peer identity. A user-supplied local file, even one named "external", is not independent durable WORM Object Lock evidence. It does not create, sign, upload or mutate credentials.
- No completion of candidate cryptographic consistency changes `productionReleaseAuthorized=false`. Genuine eMudhra/CCA/RCAI certificate/revocation authority, MCA/GST company/signatory records, independent Security/Business mandates, staging approvals, OIDC/SLSA and WORM/DR remain prerequisites.

## Internal engineering tests and evidence custody

The following code is selected in both Phase 1BV immutable source inventory and Phase 1BW review/vendor intake HOLD:

- `scripts/phase1cv-policy-freeze-detached-candidate.mjs`
- `tests/phase1cv-policy-freeze-detached-candidate.test.mjs`

**19 adversarial Node test groups** validate deterministic canonical/domain-signing input, ephemeral generated test-only Ed25519 keys, strict two-role signatures and unique SPKI fingerprints, signed-field tampering, replay/rollback/gaps, expiry/clock reversal, optional disabled source/withheld bypass, ruleset ID/parameter drift, changed CODEOWNERS bytes, older CI run/head/base, fake prior Phase 1CU acceptance, missing tokens and invalid operator inputs. Phase 1CU now additionally reports only verified base SHA and current push/PR run IDs; its regression test checks these new fields. All generated test keys are ephemeral in the test process and must **never** be enrolled as real company keys.

The existing GitHub Actions workflow `ci.yml`, jobs, pinned third-party actions, token privileges, release gates and upstream patch acceptance are unchanged.

**Evidence status at phase start:** No genuine appointed Security+Business reviewers, real main CODEOWNERS/rulesets, eMudhra/MCA approval, external attestation credential or trusted off-repo high-watermark is available. The operator commands have **not** been run with genuine external authority. New hosted push and PR CI must be verified at the final Phase 1CV commit before this document can claim this implementation passed hosted CI.

**Final standing decision: production HARD HOLD.**
