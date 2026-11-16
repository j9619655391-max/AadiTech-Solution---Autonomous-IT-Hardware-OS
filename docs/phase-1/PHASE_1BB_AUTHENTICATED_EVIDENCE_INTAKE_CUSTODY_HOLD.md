# Phase 1BB — Authenticated Evidence Intake Prerequisites, Witness-Key Custody and DR Acceptance Holds

**Status:** Offline, digest-only engineering. No provider-authorized ingestion, live external witness enrollment, cryptographically verified immutable archive retention, or real encrypted restoration took place. All interfaces preserve **production release HOLD**.

**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`; PR #1 Draft/unmerged against `main`; Issue #2 open.

## Security objective

Phase 1BA introduced applicant-supplied Ed25519/Merkle/WORM/DR receipt interoperability. Phase 1BB adds stricter **source-separated intake manifests** and transactional **nonce custody** that will prevent a future external adapter from quietly accepting stale signatures, shared authority claims, duplicate nonces, conflicting batches or unauthorized releases. This is **not** a provider API adapter. No secrets or private documents are ingested.

Green CI demonstrates that a synthetic signed manifest is **internally consistent**. The caller still supplies its own challenge nonce and public SPKI pin, so neither signer identity nor independent challenge issuance is authenticated. No internal result can set a provider/witness/storage/DR authorization flag to true.

## Implemented engineering

- `scripts/lib/phase1BbEvidenceIntake.mjs`: exact, bounded, signed `BB_PURPOSE` evidence bodies with SHA-256 packet/subject/evidence/challenge digests; Ed25519 SPKI fingerprint verification; canonical expiry; domain-separated message signing; release decision `HOLD`.
- Six separate synthetic signer domains are required: **WITNESS (two separate organizations/admins), STORAGE_AUDITOR, SECURITY, OPERATIONS, OWNER**. Cross-domain overlapping administrative refs, signer refs, key IDs, or challenge digests cause internal failure. Two WITNESS pins/organizations and three DR reviewer identities are matched to the Phase 1AZ digest-only enrollment dossier; storage attestation remains explicitly untrusted. All evidence subjects and report digests bind to the Phase 1AZ checkpoint, archive and reviewer data.
- Unknown fields, bearer tokens, private keys, raw evidence bodies, noncanonical UTC, unsigned or all-zero SHA-256 references, mismatched Ed25519 signatures, expired/future challenges, forged legal approval/status and malformed role combinations are rejected. Claimed independent challenge issuance cannot be asserted by this code.
- `database/migrations/0030_bb_evidence_intake_holds.sql` adds **offline-only** stream heads, forensic attempt records, and **globally unique** SHA-256 challenge claims. Internal columns are constrained to `NO` external authority and `HOLD` release.
- `server/evidenceIntake/durable.ts` uses InnoDB stream row locks and unique challenge inserts with a transaction savepoint; failed nonce batches roll back partially inserted nonce rows and quarantine the competing stream. Conflicting sequence, replay, rollback, gaps and predecessor mismatch are held; exact current-head retries are idempotent.
- `scripts/migrate-bb-evidence.ts` checks SHA-256 checksums of migrations 0001–0029 before applying 0030, allows checksum-matched idempotent reruns, and refuses production databases. Only disposable `aaditech_ci` or explicitly approved isolated TLS staging targets are supported.
- `tests/phase1bb-evidence-intake.test.mjs` checks contract, cryptography and injection/replay challenges; `tests/bb-evidence-mysql.integration.ts` checks real disposable MySQL races, single-use nonce claims, global cross-stream replay, exact replay, rollback/fork/gap quarantine and database head-tamper detection.
- `scripts/phase1bb-evidence-intake-preflight.mjs` only accepts `--ci-hold`. No credentials, URLs, private evidence paths, arbitrary inputs, internet requests or user-supplied production flags are accepted in CI.
- `.github/workflows/ci.yml` runs zero-input hard HOLD, new 0030 migration and idempotent rerun, actual MySQL adversarial tests, existing baseline and browser/MFA tests. `scripts/lib/stagingPreflight.ts` independently marks all external evidence `NOT_VERIFIED` and treats unresolved staging quarantine or digest/nonce anomalies as readiness blockers.
- `tests/support/phase1bbFixture.mjs` generates **ephemeral CI-only Ed25519** fixture material. Never upload live secrets, production reviewer credentials, external provider certificates, signed legal records or backup keys to Git.

## Evidence needed before external acceptance

1. **Authority and contractual provenance:** Signed eMudhra/approved provider agreement, verified CCA/RCAI PKIX and certificate-policy hierarchy, MCA corporate and authorized signatory authentication, scoped provider sandbox authorization, and independently verified live CRL/OCSP.
2. **Approved custody and issuance:** Out-of-band authentication of each third-party witness's legal and operational independence; trusted SPKI fingerprints distributed via a governed registry; owner/security review of authorized key rotation, revocation and KMS/HSM custody. A self-supplied pin must never be promoted.
3. **Provider-issued challenges:** Nonce issuance from an independently controlled verifier, durable request ID binding, freshness enforcement, anti-replay across tenants and explicit revocation. Current synthetic nonce claims do not establish these facts.
4. **Transparency:** Independently obtained signed tree heads and verifiable inclusion **and append-only consistency** proofs; witness gossip, time synchronisation, issuer outage/error classification, replay alarms and fork-quarantine testing.
5. **Object Lock/WORM:** Independently observed provider-issued versioned retention/legal-hold policies and *actual* denied overwrite/delete results from a compliant storage service, protected audit trail, tenant separation, time-policy verification, lawful retention policy and encryption key custody.
6. **Real encrypted recovery:** Separate approved fresh TLS staging target; independent integrity checks of encrypted backup, manifest, MySQL reconciliation, revocation recheck, KMS key recovery, MFA/access isolation, actual RTO/RPO from trustworthy telemetry, and distinct SECURITY/OPERATIONS/OWNER witnessed approvals.
7. **Promotion gate:** A new independent release governance decision after external onboarding, legal/security review and measured staging acceptance. This engineering phase has no path to production GO or access to real supplier, dispatch, inventory/GRN, finance, live certificate issuance or external notifications.

## Known limitations and non-claims

InnoDB is not external immutability, WORM retention or a transparency log. A privileged database operator can still alter these records; the internal readback audit identifies some anomalies but does not provide independent immutable proof. No encrypted backup was restored, no provider-signed nonce challenge was issued, no external credential was accessed and no service was activated. The six-source fixture merely exercises cryptographic format and isolation checks.

**Acceptance:** Phase 1BB *internal engineering* can be marked CI validated only after both baseline and disposable-MySQL jobs succeed for the latest branch SHA. External trust and production readiness remain **UNVERIFIED / HOLD** regardless of CI status.
