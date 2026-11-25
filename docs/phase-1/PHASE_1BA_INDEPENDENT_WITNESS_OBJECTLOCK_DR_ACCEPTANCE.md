# Phase 1BA — Independent Witness Identity, Object-Lock Enforcement & Encrypted Restore Acceptance

**Status:** Internal offline engineering, not actual externally authorized enrollment. **Production RELEASE HOLD.**  
**Source repo:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Branch:** `chore/phase0-foundation-20261106`. Keep PR #1 Draft/unmerged and Issue #2 open.

## Trust boundaries

Phase 1AZ has strict digest-only applicant claims and an internal MySQL quarantine ledger. Phase 1BA adds signature and consistency checks against those claims without granting legal, operational, CA, cloud-storage or third-party authority. A signer public key supplied by the claimant does **not** establish genuine witness identity. A signed cloud-deletion-denial statement does **not** prove the provider actually enforced Object Lock. Synthetic recovery timestamps do **not** prove an encrypted backup was restored.

Do not accept provider credentials, encrypted backup keys, private SPKI keys, legal KYC records, signed contracts or production deployment approvals in chat, repository, test fixtures or a generic CI invocation. Approved secrets manager and separately authenticated onboarding are prerequisites.

## Implemented components

- `scripts/lib/phase1BaAcceptanceEvidence.mjs` validates a Phase 1AZ packet before inspecting three separately signed domains. Canonical payloads have exact fixed field sets, bounded IDs/UTC times, SHA-256 fingerprints, Ed25519 SPKI pins, domain-separated signing bytes and release decision `HOLD`.
- **Witness-attestation domain:** two or more applicant-claimed witness organizations must have independently named administrative authorities, unique reviewer/key identities and keys bound to the Phase 1AZ witness registry SPKI digests. Each signed observation binds the packet SHA-256, log/receipt/archive hashes, tree size/root/index, timestamp and a Phase 1AY Merkle inclusion proof. Same-size disagreeing roots, forged signature, shared admin/key, missing quorum or mismatched key pin block acceptance. Authentic source enrollment and **out-of-band append-only consistency proof** remain explicitly unverified.
- **Storage-attestation domain:** a separately signed statement binds the same packet/log/checkpoint/archive identities to storage-account/version, retention-policy and encryption-key-identifier digests. Applicant claims for Object Lock COMPLIANCE, retained version, legal hold, denied deletion probe and provider receipt digest are checked for internal consistency. Archive deletion-denial **must be demonstrated from a real independently authenticated provider API** before acceptance; this code cannot verify its provenance.
- **Recovery-attestation domain:** SECURITY, OPERATIONS and OWNER must have separate claimed public keys and reviewer authority. Three independent signed observations bind source/restored manifest, revocation snapshot and backup identifier digest with checkpoint/archive and AZ packet hashes. Actual timing is recomputed from failure/recovery completion and latest recovered backup timestamps, then checked against the Phase 1AZ rehearsal event and RTO/RPO objectives. A caller cannot supply an alternative completion time or measured RPO unnoticed; isolation, MFA re-verification, revocation rechecks, credential recovery and outbound HOLD are mandatory claims.
- Witness/storage/recovery administrative overlap is rejected. All three domains are permanently marked **not externally authenticated**, even when synthetic signatures and Merkle roots are cryptographically consistent.
- `scripts/phase1ba-acceptance-preflight.mjs` accepts only `--ci-hold` and refuses arbitrary credentials, files, network endpoints or activation flags.
- `tests/phase1ba-external-acceptance.test.mjs` covers valid *synthetic* cryptography and adverse cases including forged witness keys, Merkle tampering, conflicting roots, duplicate administrative control, altered archive Object Lock claims, forged storage signature, recovered time/RTO/RPO mismatch, compromised/duplicate reviewer identities, unknown fields and CLI input injection.
- `.github/workflows/ci.yml` runs Phase 1BA zero-input HOLD preflight; existing `bun run test` automatically collects new unit tests. No new SQL migration is needed: Phase 1AZ's checksum-bound transactional digest history remains the internal audit store; no raw receipts or external secrets are persisted by Phase 1BA.

## External acceptance matrix — pending real authority

| Workstream | Evidence required for genuine acceptance | Current |
|---|---|---|
| Witness identity | Signed agreements, independent corporate legal control, authenticated CA/publisher keys, out-of-band nonce verification | **NOT VERIFIED** |
| Transparency | Independently published signed tree heads, inclusion + append-only consistency proofs, separate witness gossip/alerting, timestamp sources | **NOT VERIFIED** |
| WORM / immutable archive | Actual compliant storage account, object version/retention/legal-hold policy, independently witnessed failed deletion and retention expiry tests, cloud audit receipts | **NOT VERIFIED** |
| Encryption | Approved KMS/HSM key ownership, encryption and restoration key recovery, audit isolation and secret escrow | **NOT VERIFIED** |
| DR acceptance | Approved fresh TLS staging, real encrypted restore, measured independent RTO/RPO, MFA recovery, authenticated live revocation and independent review | **NOT VERIFIED** |
| Provider/legal | Signed eMudhra provider agreement, independently authenticated RCAI/CCA chain, live signed CRL/OCSP, MCA corporate/signatory authorization | **NOT VERIFIED** |
| Release | Explicit independent owner, security and operations approvals with verified legal authority | **HOLD** |

## Limits and negative assurances

This phase does not contact third-party services, provision storage accounts, authenticate real public keys against external authorities, enroll or rotate production witness keys, retrieve provider evidence, execute a real encrypted recovery, migrate production databases, release stock/finance/dispatch or merge `main`.

`offlineClaimsConsistent=true` means *only* that applicant-supplied fixture evidence agrees within the fixed cryptographic contract. It never means verified WORM enforcement, independent external witnesses, validated RCAI/CCA/eMudhra revocation, MCA legal authority or production readiness. All exit paths retain `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Verification evidence

Latest GitHub Actions run on the current branch must be checked independently. Historical Phase 1AZ success at run `43907889156` is a baseline, not a Phase 1BA pass. Update Issue #2 and PR #1 after CI completion; keep both open/Draft and do not merge or deploy.
