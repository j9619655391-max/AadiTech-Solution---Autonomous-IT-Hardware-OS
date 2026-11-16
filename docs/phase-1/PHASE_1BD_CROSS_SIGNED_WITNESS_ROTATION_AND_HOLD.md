# Phase 1BD — Cross-signed candidate witness key rotation, storage audit and DR acceptance HOLD

**Engineering scope:** OFFLINE, synthetic-key validation of an untrusted witness key-rotation handover. No external identity, cloud storage provider or encrypted restore has been independently authenticated. Production must remain **HOLD**.

**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`
**Branch:** `chore/phase0-foundation-20261106`
**Governance:** PR #1 Draft/unmerged; Issue #2 open; `main` unchanged.

## Complementary Phase 1BD controls

The pre-existing `scripts/lib/phase1BdEvidenceReview.mjs` and `scripts/phase1bd-evidence-review-preflight.mjs` inspect candidate witness enrollment key possession, storage provider Object Lock denial/retention receipt claims and DR telemetry/signatures against Phase 1AZ/1BB evidence. These are internally consistent **claims only**, never authenticated external authority.

This phase further adds `scripts/lib/phase1BdAuthorityRotation.mjs` and its `tests/phase1bd-authority-rotation.test.mjs`, with a specific requirement that new signing keys cannot silently replace existing locally observed ones:

- Two previously enrolled *candidate* witness organizations must show distinct new Ed25519 SPKI fingerprints. Their witness refs, claimed organizations and claimed administrators stay bound to the old and next Phase 1AZ packet revisions. A different authority is **not** enrolled implicitly.
- The *old* and *replacement* witness sets each verify a pair of signed Merkle heads, inclusion proofs, RFC 6962 append-only consistency proofs, exact checkpoint receipt, archive digest and candidate source-key bindings via the existing Phase 1BC validator.
- The last signed old-key tree head must be the **exact** first signed new-key head (same tree size and root). The replacement must be a strictly larger append-only tree, never a re-signed same-size root.
- A canonical domain-separated rotation envelope binds the Phase 1AZ predecessor and successor packet SHA-256s, both Phase 1BC witness evidence and pinset digests, handover root/size, new root/size, archive object SHA-256, **claimed/unverified** Object Lock audit SHA-256, **claimed/unverified** encrypted-restore audit SHA-256, narrow issued/effective/expiry times and `releaseDecision=HOLD`.
- Both retiring keys and both replacement keys sign that exact envelope, not just a rotation request text. A SECURITY, OPERATIONS and OWNER triad of claimed independent reviewers also signs. Duplicate/missing/forged signatures, cross-role administrative overlap, changed archive/DR dossier, missing AZ packet revision chain, mismatched historical head, stale claims, reused keys, injected credentials and release GO are denied.
- Independently generated synthetic Merkle fixtures test fully signed **divergent historical trees** (not merely tampered signatures), invalid or missing old/new quorum, re-key reuse, reviewer collisions, expired handover and evidence fingerprint changes. No key private material or provider token is written to Git.
- `scripts/phase1bd-authority-rotation-preflight.mjs --ci-hold` is zero-input only. CI runs **both** the independent Phase 1BD evidence-review HOLD gate and the dual-signed rotation HOLD gate before baseline tests. Neither command reads credentials, networks, user-provided files or cloud resources.

## Production-blocking limitations

An internally valid signature from an applicant-supplied public SPKI is **not proof of externally authenticated witness control, company authority, valid provider authorization or independent key custody**.

A digest labeled Object Lock audit cannot verify a real bucket policy, retention/versioning, deletion/overwrite denial, legal hold, auditable permissions or KMS operations. A digest labeled encrypted-DR audit cannot establish backup authenticity, real restore into fresh isolated staging, measured RTO/RPO, recovered data integrity, revocation continuity or independently signed operational acceptance.

**Genuine prerequisites** to revisit in a separate authorized phase:

1. Provider contracts/approved sandbox credentials through the enterprise secrets manager; legal organizational and signatory verification through independently authenticated MCA records.
2. Named independently controlled witness organizations with out-of-band verified public-key pins, approved key-rotation and emergency-revocation channels, publisher-signed append-only heads, a trusted time source and independent gossip/split-view alerting.
3. Signed, independently fetched cloud Object Lock retention configuration and actual negative delete/overwrite proofs with policy, versioning and legal-hold audit.
4. Authorized encrypted backup restoration into isolated TLS staging, independently observed measured RTO/RPO, restored checkpoint and active CRL/OCSP validation, authentic RCAI/CCA/eMudhra CP/CPS verification and separate SECURITY, OPERATIONS, OWNER final signoffs.

No such external authority/operation is simulated as trusted or activated. Existing Phase 1BC MySQL evidence ledger remains quarantined on unapproved witness pin changes; **this new offline Phase 1BD module does not automatically change a persisted pinset, lift quarantine or authorize production.**

**Non-negotiable policy:** every Phase 1BD output sets `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD` regardless of cryptographic fixture consistency. No deployment, financial posting, dispatch, privileged external provider action, release of genuine credentials or merging the Draft PR.

**Internal acceptance:** exact development SHA with latest baseline and MySQL integration GitHub Actions jobs both successfully complete. Historical failed test runs are diagnostics, not acceptance.
