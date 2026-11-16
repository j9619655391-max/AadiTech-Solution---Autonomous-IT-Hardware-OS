# Phase 1BC — Provider-Authorized Adapter Protocol, Issuer Custody, Object Lock and Witnessed DR (HOLD)

**Date:** 2026-11-16  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Release governance:** PR #1 remains Draft/unmerged against `main`, Issue #2 open, production **HOLD**.

## Scope and trust boundary

This phase implements **offline interoperable cryptographic envelope checks**, not live, authorized external adapters. A user-supplied verifier public key, Ed25519 signature, claimed provider receipt or timestamp does **not** establish genuine provider authorization, independent challenge issuance, authenticated witness custody, Object Lock enforcement or actual encrypted restoration.

Credentials, provider agreements, private PKI, client TLS certificates, legal records, backup keys and live evidence must come from approved authorities through the secrets manager and an independently authenticated onboarding process, never from chat, CI logs or Git. **No live network client, storage mutation, sandbox login, production migration or deployment** is added in Phase 1BC.

## Engineering delivered

- `scripts/lib/phase1BcExternalAdapterProtocol.mjs` defines strict, bounded and domain-separated Ed25519 envelope contracts for externally issued **challenge requests**, storage-provider **Object Lock receipt claims**, and **encrypted DR observer receipts**. All schemas require `releaseDecision=HOLD`, refuse unknown/raw/secret fields, and include canonical UTC, SHA-256 fingerprint and Ed25519 SPKI checks.
- **Issuer custody:** six separate Phase 1BB signed response challenges each require their own matching signed issuer claim; two separately named challenger administrations must sign three each. Each challenge issuance must precede the signed response and remain valid when answered; stale, future, duplicated or mismatched claims are rejected. Source administrative authorities cannot also be challenge issuers.
- **Provider claim envelope:** signed archival receipt includes Phase 1AZ readiness packet hash, log and object version hash, retention policy and legal hold digests, claimed request/response digests, explicit versioning and compliance-lock flags, denied delete and overwrite flags, and bounded retention/time checks. The signer must be distinct from issuers and the six Phase 1BB signers. A mathematically valid receipt is not independent proof the storage provider actually enforced retention.
- **DR observer envelope:** three SECURITY, OPERATIONS and OWNER attestations must match Phase 1AZ's reviewer roles and claimed authorities. Signed data binds checkpoint, encrypted-backup reference, original/restored manifests, revocation snapshot, isolated recovery and MFA/revocation/dispatched-held controls. RTO is derived as `completedAt - failureAt`, RPO as `failureAt - latestRecoveredAt`; both are compared against Phase 1AZ objectives and claimed measurements. Signed evidence remains an **unverified rehearsal** until a real encrypted restore is independently observed.
- `tests/phase1bc-external-adapter.test.mjs` exercises valid *synthetic* six-plus-one-plus-three envelopes and adversarial signature forgery, nonce misbinding, premature/expired challenge issuance, issuer common-control, retention tampering, forged Object Lock response, authority collisions, backup and revocation mismatch, misreported RTO/RPO, raw credential fields and production activation attempts.
- `scripts/phase1bc-external-adapter-preflight.mjs` permits **only** `--ci-hold`. The baseline GitHub Actions workflow runs this gate. It does not take provider URLs, certificates, credentials, evidence files, trust-bundle overrides or arbitrary CLI arguments.
- **Candidate witness continuity ledger:** `database/migrations/0031_bc_witness_continuity_holds.sql`, `scripts/migrate-bc-witness-continuity.ts`, and `server/witnessCustody/durable.ts` extend Phase 1BB's `0030` nonce custody with a separate, additive InnoDB historical tree-head ledger. The checksum-guarded, disposable-only migration, transactional per-stream updates, signed append-only consistency proofs and pin-set/rollback/fork quarantine are tested in `tests/bc-witness-mysql.integration.ts`. These are locally held candidate proofs, **not** externally immutable or independently authenticated log evidence. An isolated CI/staging readback can detect some SQL tampering but cannot prove WORM guarantees.

## External trust acceptance checklist (not satisfied)

1. **Signed legal and sandbox authorization:** Confirm eMudhra/provider agreement, permitted endpoints/scopes, organization and signatories via authoritative independent channels; record effective dates, revocation and expiry and approve least-privilege credentials via a secure secrets manager.
2. **Independently pinned challenge issuers:** Verify publisher/issuer organizational control, role separation, KMS/HSM key ownership, key rotation/revocation, independently authenticated SPKI fingerprints, request signing and audit. Current internal issuer fixtures do not constitute authority.
3. **Provider-issued and verified Object Lock:** Confirm versioning, compliance-mode retention, effective legal hold, enforced delete/overwrite denial and immutable storage audit **by executing authorized provider API operations** on isolated storage. Record independently verified signed server responses and nonces under legal retention policy.
4. **Transparency append-only:** Verify signed tree heads with trusted third-party publisher keys, RFC 6962-style inclusion **and consistency** proofs, cross-organization gossip and signed checkpoint continuity over multiple epochs. Authenticated external log audit is still pending.
5. **Real encrypted recovery:** Restore a provider-authorized encrypted backup into approved fresh TLS staging; independently reconcile record counts, stream checkpoint, keys, MFA, live signed CRL/OCSP and authorized reviewer identities; measure RTO/RPO from separately authenticated telemetry, test rollback and incident revocation.
6. **Release governance:** Require separate current SECURITY, OPERATIONS and OWNER approvals plus legal/provider and SOC validation before any new production release decision. Earlier green CI cannot replace this review.

## Explicit non-claims

No external publisher key was enrolled or authenticated. No provider-issued challenge, signed Object Lock receipt, approved sandbox credential, provider certificate validation, real WORM storage, real encrypted restoration or MCA signatory verification took place. No code in this phase sets `productionReleaseAuthorized` to true. All results maintain `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

**Verification:** CI green on the latest development branch SHA demonstrates offline engineering consistency only. Retain Draft PR #1 and Issue #2 open, `main` unchanged and production release HOLD.
