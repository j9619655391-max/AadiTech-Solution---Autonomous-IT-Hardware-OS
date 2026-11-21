# Phase 1DR — Key-ID-bound v2 offline registrar-witness signatures (HARD HOLD)

**Scope:** Candidate-only engineering, no trusted registrar identity or production permissions. Repository: j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS. Development branch: chore/phase0-foundation-20261106. PR #1 remains Draft/unmerged; Issue #2 remains open. Never update main or trigger deployment.

## Root cause and versioning

Phase 1DQ established that historic Phase 1DO v1 signatures cover only the canonical manifest. The derived checkpoint hash additionally includes unsigned witness keyId labels. Label rehashing can change the checkpoint without any signed-content fork. **Never reinterpret or silently upgrade v1 signatures.**

New source: scripts/phase1dr-offline-keyid-bound-witness-v2.mjs. Signature domain: aaditech/phase1dr/key-id-bound-registrar-witness/v2/. Each LEGAL_WITNESS and REGISTRY_WITNESS Ed25519 signature now covers a canonical role-separated v2 envelope containing the exact manifest, role, keyId and SPKI SHA-256. V2 checkpoint hashing includes these signed witness identity fields and signatures. V1 manifest schema and signature bytes are explicitly rejected by this verifier.

The exact v2 manifest requires source HEAD/main-base, organization, registrar fingerprint, registry evidence SHA-256, signed appointment SHA-256, nonzero nonce, monotonic sequence and prior checkpoint, canonical UTC issuance and expiry (max 15 minutes), and explicit HOLD. The candidate verifier checks separate pinned Ed25519 witness identities, explicit now, 2–8 bounded observations, exact schemas, source/sequence context, both role-separated signatures and checkpoint claims. **All comparison pins and clocks remain applicant supplied and untrusted.**

## Integrity and fork classification

- Re-labeling keyId without re-signing invalidates the v2 role signature, even if an attacker recomputes the claimed checkpoint. Invalid packets never contribute to fork counts.
- Different correctly re-signed key IDs over the same signed manifest produce signed-identity fork quarantine (DR_SIGNED_WITNESS_IDENTITY_FORK_QUARANTINE), NOT signed-manifest equivocation.
- Different correctly dual-signed manifest contents at the same source, sequence and predecessor produce signed-content fork quarantine (DR_DUAL_SIGNED_MANIFEST_FORK_QUARANTINE); mixed signed-content and signed-identity forks report both.
- Duplicated identical receipts cannot prove independent publication. Stale/future time, swapped roles, bad pins, forged GO, extra fields, malformed or forged signatures, changed source, genesis/rollback/overflow and claimed digest mismatch fail closed.
- No output leaks raw nonce, key ID, public PEM or signatures. All outputs are HARD HOLD: productionReleaseAuthorized=false; productionReleaseBlocked=true; releaseDecision=HOLD.
- This standalone candidate mathematical comparison does **not** recheck Phase 1DN's original ephemeral GitHub/officer HMAC session. It cannot be substituted for that required chain.

## Tests, custody and exact-head verification

Tests: tests/phase1dr-offline-keyid-bound-witness-v2.test.mjs, 19 adversarial Node groups covering v2 signing/duplicate receipt, unsigned label change, signed label rotation, signed manifest fork, mixed forks, digest forgery, tamper, v1 nonmigration, GO/unknown fields, missing/stale/future clock, expiry, wrong roles/key collision/SPKI/signatures, source/nonce/organization drift, predecessor rollback/overflow, observation bounds, domain separation and output secrecy/HOLD. Both new source and test are listed in scripts/phase1bv-build-input-provenance.mjs and scripts/phase1bw-review-vendor-intake.mjs.

Final docs-inclusive development commit needs both GitHub Actions push and pull_request workflows completed/success with *the same exact head SHA*. Check mandatory individual jobs; the PR-only source-merge-lineage skip on push is not a successful job. Incomplete or stale-SHA jobs must not be reported green.

## External evidence blocking real acceptance

Genuine independent legal/MCA corporate registrar and Security/Business mandate/identity validation, externally enrolled Legal/Registry witness keys and trusted key revocation/rollover, independent packet origins and trusted time/previous checkpoint, WORM/CAS/DR, real no-bypass protected-main rules/CODEOWNERS and nonauthor HEAD reviews, RCAI/CCA/eMudhra approved chains and signed live CRL/OCSP, OIDC/SLSA and independent Owner/Legal/Security/Ops staging approvals remain **unverified**.

No provider credentials in Git or chat. No main changes, merge, real reviewer requests, external messages, provider enrollment, PO/GRN, financial/stock/tax postings or production deployment.

**HARD HOLD: productionReleaseAuthorized=false; productionReleaseBlocked=true; releaseDecision=HOLD.**
