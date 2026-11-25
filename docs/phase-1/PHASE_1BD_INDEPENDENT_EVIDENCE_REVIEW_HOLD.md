# Phase 1BD — Independent Witness Enrollment, Object-Lock Receipts & DR Review HOLD

**Engineering date:** 2026-11-16  
**Correct repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Governance:** PR #1 Draft/unmerged; Issue #2 open; `main` unchanged; **production HARD HOLD**.

## Scope and negative assurance

Phase 1BD is **OFFLINE cryptographic and transactional engineering**. It implements candidate-signature review and local digest history only. It has no approved third-party credentials, live API adapters, KMS/HSM access, real compliant storage, PKIX/CCA/RCAI/eMudhra signatory validation, MCA corporate authority, or actual encrypted disaster-recovery execution.

An applicant-supplied Ed25519 public key and signature establish only **local mathematical consistency**, not independent identity, legal control, provider-issued Object Lock enforcement, trusted telemetry or approval. Missing true external authorization **cannot** be supplied by CI fixtures, chat messages, Git, an environment variable or a signed self-declaration. No production-release path exists in this phase.

## Implemented components

### 1. Witness-key enrollment prerequisites

`scripts/lib/phase1BdEvidenceReview.mjs` accepts exact domain-separated, bounded, canonical UTC Ed25519 candidate enrollment envelopes. The two witness signers must match existing Phase 1AZ witness organization and SPKI fingerprints **and** the Phase 1BB signed intake key IDs. Each binds the AZ packet, BB batch, candidate enrollment receipt digest, independently controlled channel *claim*, custody policy digest and key-rotation sequence. Duplicate witness administrators and key identities, forged proof-of-possession signatures, unexpected fields, stale registration, claims of live authority or unapproved rotation fail closed.

Separate `scripts/lib/phase1BdAuthorityRotation.mjs` checks candidate **old/new** witness handover envelopes, dual old/new witness co-signatures, trusted-role-reviewed continuity between two locally signed append-only Merkle heads and candidate WORM/DR audit hashes. A signed local handover is **not** independently authorized external key rotation.

### 2. Provider versioned retention and denial claims

A separately signed candidate storage-provider envelope binds the same AZ archive object, storage account, exact object version ID, retention policy, legal hold and key identifier. It includes nonzero digests for claimed provider create/policy responses, delete denial, overwrite denial and readback; `complianceLock=true`, `deleteDenied=true`, `overwriteDenied=true`. Retention chronology and separate administration are checked.

This never executes an actual provider API call or independently authenticates the server, event log, client nonce, retention policy or denied delete operation. **Provider-issued WORM evidence is still unverified.**

### 3. Witnessed encrypted recovery claim consistency

SECURITY, OPERATIONS and OWNER independently sign an identical candidate recovery envelope binding an encrypted backup, source/restored manifests, revocation snapshot, KMS recovery receipt claim, isolated restoration receipt claim and telemetry receipt claim. The three public SPKI pins are constrained to Phase 1BB signers and Phase 1AZ reviewer organizations. Derived RTO/RPO measurements are compared to the predecessor dossier. Signing disagreement, unauthorized key substitution, revocation mismatch, missing MFA or outbound HOLD, and wrong recovery chronology all block internal consistency.

No actual encrypted backup was decrypted/restored; measurement is derived solely from untrusted signed timestamps and not from separately authenticated operational telemetry.

### 4. Transactional review history — migration 0032

`database/migrations/0032_bd_external_evidence_reviews.sql` adds InnoDB candidate-review heads and append-only-at-the-application-layer forensic attempts. `scripts/migrate-bd-evidence-review.ts` refuses production and requires checksum-matched migrations 0001–0031 before applying 0032 on **disposable CI** or explicitly approved isolated TLS staging, with idempotent rerun and a migration mutex.

`server/evidenceReview/durable.ts` requires all three predecessor held histories, Phase 1AZ packet, Phase 1BB evidence batch and Phase 1BC candidate witness Merkle-head/pin-set continuity, before accepting a review digest. Row locks serialize competing revisions; fork, stale revision, gap, predecessor mismatch and changed upstream digests quarantine the log. Exact replay is idempotent. Readback detects broken accepted chains, missing head matches and illegal trust-promotion flags.

MySQL is **not** immutable independent storage: a sufficiently privileged DB actor could alter or delete records. These tables never persist raw signed receipts, signer PEMs, legal records, personal data, bearer tokens or encrypted backup keys.

### 5. Test and CI

`tests/phase1bd-evidence-review.test.mjs`, `tests/phase1bd-authority-rotation.test.mjs` and `tests/bd-review-mysql.integration.ts` cover synthetic signing, unsigned/forged evidence, shared control, stale or rotated keys, WORM policy substitution, recovery telemetry disagreement, precise RTO/RPO mismatch, real disposable MySQL concurrent review forks and rollback, upstream predecessor gating, and isolated head tampering.

`scripts/phase1bd-evidence-review-preflight.mjs` and rotation preflight allow **only** `--ci-hold`. `.github/workflows/ci.yml` runs them, migration 0032 and checksum rerun, real disposable MySQL tests, and previous baseline/MFA/browser/staging checks. `scripts/lib/stagingPreflight.ts` reports held/quarantined Phase 1BD review counts, rejects impossible external-trust fields and incomplete accepted local chains, and explicitly lists external gates as `NOT_VERIFIED`.

## External acceptance prerequisites — all pending

1. **Provider/legal authority:** Fully executed eMudhra/provider sandbox agreement, explicitly approved credentials and scopes, independently authenticated RCAI/CCA trust anchors/CP-CPS, authenticated signed CRL/OCSP, MCA company and signatory verification.
2. **Issuer/witness independence:** Out-of-band legal and operational witness-enrollment verification; externally governed pinned SPKI; separate independent KMS/HSM key custody and issuance audit; cryptographically signed, out-of-band append-only transparency and anti-split-view gossip; revocation/rotation authorization procedures.
3. **Real Object Lock/WORM:** Approved isolated compliant object-store account, versioning and retention enforcement, legal-hold policy, independent source-of-truth receipt retrieval, permitted deliberate delete/overwrite denial tests and immutable remote audit with retention expiry controls.
4. **Real DR:** Approved fresh isolated TLS staging and genuine encrypted backup restore, separately witnessed key recovery, data reconciliation, revocation continuity/MFA, real instrumented RTO/RPO under adverse conditions, three independently authorized review signatures.
5. **Release:** Current legal, OWNER, SECURITY and OPERATIONS decision through a separately authenticated approval process. No synthetic dossier, stored fingerprint or passing CI can authorize production, procurement/dispatch/GRN posting or finance.

## Release invariant

For both internally consistent and malformed/missing candidate evidence:
`productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

A latest-HEAD successful GitHub Actions run confirms **internal engineering tests only**. External/production acceptance remains **BLOCKED**, without exceptions.
