# Phase 1DB — External mandate-source, conditional-CAS and sealed recovery candidate HARD HOLD

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106` only  
**Governance:** `main` untouched; PR #1 Draft/unmerged; Issue #2 OPEN.  
**Production:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`, `quarantineRequired=true`.

## Engineering objective and precise assurance boundary

Phase 1DA mathematically validated a four-stage signed incident log and an operator-proposed previous high-watermark. An applicant-supplied previous digest is not an offsite immutable, compare-and-swapped ledger state. A cryptographically valid applicant-signed source is not independently enrolled corporate legal authority.

Phase 1DB adds a *strict offline, read-only, operator-only* candidate preflight for four separately proposed external source public keys, a signed corporate mandate-source observation, two conditional-CAS source receipt claims on the same previous/new ledger digests, and a separately signed sealed archive/recovery package. It **does not** contact registries, GitHub, trust providers or storage, execute any CAS, create a WORM object, fetch offsite witnesses, or grant incident recovery/release. In particular, no source organization key, host, TLS pin, mandate registration, CAS outcome or Object Lock claim is independently authenticated by this assessor; every record is operator-supplied.

Even an internally consistent candidate retains `quarantineRequired=true`, `automaticRecoveryOrUnquarantineAllowed=false`, `productionReleaseAuthorized=false`, `releaseDecision=HOLD`.

## Exact operator command

Only an independently authorized officer may inspect a locally supplied candidate file:

```sh
node scripts/phase1db-external-mandate-cas-sealed-recovery.mjs \
  --inspect-offsite-cas-candidate /approved/offrepo/phase1db-candidate.json
```

The script refuses `GITHUB_ACTIONS=true`, requires a regular nonsymlink local JSON file of at most **256 KiB**, overrides the applicant's proposed verification clock with the operator's current local clock, and only prints a bounded key-free HOLD receipt. It makes **no network requests, filesystem writes, provider or GitHub mutations**. A mathematically invalid candidate returns nonzero. No actual operator-approved external candidate, private signing key, root credential, bank/customer/financial secret or provider sandbox credential has been used or placed in Git/chat.

For deterministic synthetic tests, the pure `assessSealedOffsiteCasCandidate` function allows explicit verification clock injection. That is **not** a trusted timestamp or remote issuer proof.

## Required candidate input

The top-level JSON has `daEvidence`, `sources`, `authorization`, `casReceipts`, `sealedRecovery`, `dispute` (plus optional `now` only for pure tests). The assessor directly reruns `assessAppendOnlyIncidentReplay` on the raw Phase 1DA evidence, thereby rereading the Phase 1CZ corporate-root/multi-officer signatures, previous witness high-watermark, four append-only events and denied replay. It refuses any substituted success boolean, changed source head, previous anchor, incident or archive version.

### Four candidate source identities

Exactly four role-specific source entries must exist: `MANDATE_REGISTRAR`, `JOURNAL_PRIMARY`, `JOURNAL_REPLICA`, `ARCHIVE_AUDITOR`. Every entry contains exact `role`, `organizationId`, `host`, `keyId`, `publicKeyPem`, `spkiSha256`, `tlsSpkiSha256`, `authorityEvidenceSha256`, `validFrom`, `validUntil`, `revoked`. Each public signing key must be a valid Ed25519 SPKI whose DER SHA-256 matches the proposed fingerprint and whose validity includes the verification clock. The four must have distinct proposed organizations, public hostnames, signer key IDs, signing SPKI fingerprints and TLS SPKI fingerprints. Reuse of a proposed corporate root, Security/Business/Incident/Recovery officer SPKI or previous/current witness SPKI causes HOLD. Invalid hosts, private/IP-literal URLs, key mismatch, expired/revoked signer, collision and extra unknown metadata fail closed.

This is a **syntax and mathematical distinctness gate**, not legal proof of separate corporate ownership. Even a legitimate TLS fingerprint is **not authenticated merely because someone pasted its hash into a manifest**; no live TLS connection is performed by Phase 1DB.

### Candidate registrar mandate receipt

`authorization` is an exact `statement` plus `MANDATE_REGISTRAR` Ed25519 signature. The statement has `kind:EXTERNAL_MANDATE_EVIDENCE_CANDIDATE_HOLD`, repo, exact current source HEAD/base, incident, the rechecked Phase 1CZ root-signed candidate mandate digest and full four-officer roster SHA-256, root SPKI, proposed registrar evidence digest, nonce, bounded canonical UTC issue/expiry and `decision:HOLD`. Its signature uses domain-separated canonical bytes. An arbitrary applicant-created registrar key may sign a mathematically valid packet but **cannot authenticate the actual registrar, corporate appointment, MCA record or legal signatory**.

### Two source-proposed conditional CAS receipts

`casReceipts` contains exactly **one** detached signed `JOURNAL_PRIMARY` receipt and **one** `JOURNAL_REPLICA` receipt. Both must agree on every substantive field (role and observation time are the only permitted differences). Statements bind:

- `kind:CANDIDATE_CONDITIONAL_CAS_RECEIPT`, repo/source SHA, incident, ledger store ID and the exact current source nonce.
- Exact `expectedVersion` and `expectedDigest` from the original Phase 1DA prior ledger high-watermark. Every rollback/stale, skipped generation or alternate previous digest is denied.
- Exact `committedVersion=expectedVersion+4` and `committedDigest` recomputed by the Phase 1DA validator after its four-stage append-only signed chain; the same claimed archive hash and recovery object version.
- `precondition:IF_MATCH_EXACT_DIGEST`, `outcome:CANDIDATE_CONDITIONAL_COMMIT`, and `decision:QUARANTINE`, each with bounded canonical observation timestamp after the signed Phase 1DA replay and registrar receipt.

A fork, contradictory primary/replica receipt, wrong signer or timestamp is refused. Both results are **candidate claims only**: this code does **not** perform a real conditional HTTP request, compare-and-swap, durable write/readback, immutability check or independent fork gossip. Even two apparently valid signatures cannot prove that any provider committed a write.

### Sealed recovery package

`sealedRecovery` is a separately signed `ARCHIVE_AUDITOR` receipt with `kind:SEALED_RECOVERY_PACKET_CANDIDATE_HOLD`. Its exact source/head, incident, store ID, committed version/digest, object version and archive evidence hash must match both signed CAS receipts and upstream Phase 1DA. A **domain-separated SHA-256 content digest** binds the same ledger digest, archive evidence, object version, source SHA and incident. Proposed `retentionUntil` must equal Phase 1DA's prior candidate retention (more than 30 days ahead), `lockMode` must be `COMPLIANCE`, and `legalHoldClaim`, `deleteDeniedClaim`, `restoreHashMatchesClaim` must be true. Audit observation must be no earlier than either CAS receipt. Decision must remain `HOLD`.

Those signed Boolean claims **are not actual measurements** of S3 Object Lock COMPLIANCE, legal hold, denied DELETE, sealed snapshot bytes, restore hash, geographic independence, RTO/RPO or corporate retention policy. A real independent auditor must verify the storage provider's authenticated APIs, exact object version, trusted timestamps, privilege boundaries and offsite recovery trial externally.

### Incident and fork quarantine

`dispute` must be exactly:

```json
{
  "status": "QUARANTINED",
  "forkReports": [],
  "compromisedKeyIds": [],
  "rollbackObserved": false,
  "releaseRequested": false,
  "manualOverrideRequested": false
}
```

Any reported fork, compromised source key, observed rollback, unquarantine or manual override request is an explicit **quarantine/failure** signal. A clean applicant-supplied dispute array is **not proof** that no real fork exists; external immutable cross-run incident state and independently verified witness gossip are required. All receipt outputs unconditionally keep `quarantineRequired=true` and production HOLD.

## Cryptography and test coverage

All four detached candidate source signatures use Ed25519, strict 64-byte canonical base64, SHA-256 pinned SPKI and role-separated canonical JSON. Signed domains:

```text
aaditech/phase1db/offline-cas-and-sealed-recovery/v1/mandate/MANDATE_REGISTRAR/v1\n
aaditech/phase1db/offline-cas-and-sealed-recovery/v1/cas/JOURNAL_PRIMARY/v1\n
aaditech/phase1db/offline-cas-and-sealed-recovery/v1/cas/JOURNAL_REPLICA/v1\n
aaditech/phase1db/offline-cas-and-sealed-recovery/v1/sealed-recovery/ARCHIVE_AUDITOR/v1\n
aaditech/phase1db/offline-cas-and-sealed-recovery/v1/sealed-content/v1\n
```

Source code: `scripts/phase1db-external-mandate-cas-sealed-recovery.mjs`. Adversarial tests: `tests/phase1db-external-mandate-cas-sealed-recovery.test.mjs` (**23 groups**) with process-local synthetic Ed25519 keys, and reusable `tests/helpers/phase1db-candidate-fixture.mjs` using the prior DA fixture. Test-only private keys never leave process memory. Test cases include prior DA forgery, registrar mandate drift, unauthorized source organization/key reuse, stale/skip/rollback CAS, primary/replica forked outcome, forced GO or invalid storage claims, missing recovery signature, incident dispute override and secret leakage.

All three new paths are registered in Phase 1BV/BW exact input custody; the M01–M30 completion plan contains the checklist. No GitHub Actions YAML, action SHA pins, CI token privileges, GitHub rulesets, `main` or production workflow has been changed.

## Required independently obtained acceptance before any production change

The actual authority prerequisites remain outstanding: independently authenticated and legally valid corporate registrar records, appointed and current Security/Business/Incident/Recovery officers, approved signing/SPKI/TLS pins with recorded revocation, real externally executed conditional CAS in at least two separately authenticated approved source stores plus durable read-after-write and fork-gossip, actual offsite immutable WORM COMPLIANCE retention/delete denial and observed DR restore/RTO/RPO, genuine MCA/eMudhra/RCAI/CCA CA and certificate-policy/CRL/OCSP evidence, signed workload OIDC/SLSA, independently accepted Security/Legal/Ops/Owner staging, and an enforceable `main` CODEOWNERS + bypass-free ruleset + latest-head nonauthor reviews.

At Phase 1DB start, GitHub API showed **0 submitted PR reviews, 0 installed main rulesets and main CODEOWNERS 404**. No authenticated offsite provider/registrar evidence has been supplied or independently validated. The technical result is **a candidate HOLD**, not a production signoff or release authorization.

After pushing the final Phase 1DB source HEAD, separately confirm **both** hosted push and PR GitHub CI, baseline JS/TS/staging-security suites, frozen Bun advisory audit, disposable real MySQL migration/integration, Chromium MFA/role smoke and official GitHub Check Runs / Actions Jobs cross-API check suite and exact source matching. Report actual failed runs and fixes, without borrowing previous CI successes. Only when done, update Draft PR #1 and Issue #2.

**Production and incident quarantine are ALWAYS HARD HOLD.**


## Initial GitHub-hosted CI failure and corrective record (NOT green)

Phase 1DB first commit `c37811b32c3ba94951335dc4864152d125acb246` started [push CI 44671077087](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44671077087) and [PR CI 44671082298](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44671082298). Both original baseline jobs **FAILED**. Hosted push baseline log showed **750/751 JavaScript tests passed**. The only failed positive synthetic test, `DB: mathematically signed four candidate sources produce HOLD, never independent enrollment`, correctly reported `DB_SOURCE_PIN_ENROLLMENT_PACKET_INVALID_ARCHIVE_AUDITOR`. Cause: the synthetic test fixture generated `authorityEvidenceSha256:String(i+7).repeat(64)`; at index 3, `String(10).repeat(64)` is a **128-character** string and fails the intentional exact **64-hex-character** SHA-256 schema. The verifier **correctly rejected** this malformed applicant record. Corrective action only fixes the test fixture to `['7','8','9','a'][i].repeat(64)`. No SHA-256 requirement, independent source identity, revocation, CAS, Object Lock or production-HOLD check is weakened. These original CI runs must remain recorded as **FAILED**, not relabeled green. Only a *new corrective-commit* dual-event hosted CI + exact-head official Check Runs/Actions Jobs reconciliation can mark Phase 1DB internal engineering verified.
