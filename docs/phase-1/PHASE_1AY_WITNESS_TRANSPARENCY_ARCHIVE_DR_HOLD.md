# Phase 1AY — Witnessed Transparency, Archive Integrity and Independent DR Acceptance

**Status:** OFFLINE ENGINEERING ONLY. External witness enrollment, WORM/object-lock retention, approved encrypted restore and genuine security/operations/owner attestation have **NOT** occurred. Production release **HOLD**.  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Branch:** `chore/phase0-foundation-20261106`; PR #1 remains Draft/unmerged and Issue #2 remains open.

## Threat model and explicit non-authority

Phase 1AX gives per-log MySQL serialization, deterministic signature checks, quarantine and local readback verification. A local database administrator can still alter/delete stored rows, so the ledger is **not** independent immutable transparency evidence. Witness keys supplied by the same applicant can mathematically validate a receipt but **cannot** prove independent organizational authority. Cryptographic consistency alone does not establish RCAI/CCA trust, eMudhra provider access, MCA records or a production launch.

## Phase 1AY offline acceptance components

- `scripts/lib/phase1AyWitnessArchiveRecovery.mjs`: strict bounded schemas, domain-separated Ed25519 proof verification, independently named witness organization claims, canonical SHA-256 fingerprint checks and quorum holds.
- Merkle inclusion proofs use RFC 6962-style SHA-256 leaf/node domain prefixes. The leaf binds `logRef`, Phase 1AW checkpoint receipt SHA-256 and archive object SHA-256. A signed tree head is bound to `treeSize`, `leafIndex`, `rootSha256`, validity window and `HOLD`.
- Detect invalid signatures, stale/future anchors, mismatched archive/checkpoint digests, invalid/truncated paths, witness identity duplication and conflicting same-size roots. **A valid proof is not proof of immutable retention or authentic witness operation.**
- Signed disaster-recovery claims bind incident ID, source/restored checkpoint and backup manifest digests, revocation snapshot digest, wall-clock restoration times, target RTO/RPO, measured RPO, and `outboundHeld=true`. Three distinct claimed SECURITY, OPERATIONS and OWNER signers are required. Synthetic reviewer signatures **never** count as an independent DR signoff.
- `scripts/phase1ay-witness-recovery-preflight.mjs`: a CI-only zero-input `--ci-hold` command; no secrets, provider certificates, legal documents, external requests, credentials, unredacted backup data or live storage access are accepted.
- `tests/phase1ay-witness-recovery.test.mjs`: synthetic positive interoperability cases and negative tests for forged signatures, merkle proof tampering, archive substitution, witness collisions/equivocation, replay-prone timestamps, fake recovery, measured target breaches, self-approval and release-flag injection.
- `.github/workflows/ci.yml`: run zero-input HOLD check and include tests in `bun run test` automatically.

## Required genuine evidence before any external acceptance

1. A signed provider contract, least-privilege sandbox authorization and independently authenticated RCAI/CCA/eMudhra trust roots and certificate policy (not website screenshots or synthetic chain).
2. Authenticated CRL/OCSP, MCA company/signatory legal verification and revocation lifecycle, approved reviewer-key ownership and verified independent witness organizations and signatories.
3. Signed checkpoint publication to **two or more genuinely independently administered** transparency/witness services with out-of-band authenticated key material, consistent append-only log roots, durable published inclusion/consistency proofs, real alerting and incident quarantine.
4. Versioned, independently configured WORM/Object-Lock-capable archive with tested retention legal hold, immutable checkpoint ledger snapshots, independent access audit and deletion/retention enforcement evidence. Internal SQL or CI artifact hashes are not immutable retention.
5. Independently authorized **encrypted backup restore to fresh isolated staging**, including verified MySQL credentials/TLS, restored manifest comparison, physical authenticator recovery, authenticated CRL/OCSP recheck, measured RTO/RPO, rollback, post-incident revocation and separate security/operations/owner signoff.
6. Production release needs new explicit written approval and a full release-gate review. No earlier CI success overrides HOLD.

## Go/no-go

`productionReleaseAuthorized=false` and `productionReleaseBlocked=true` for every Phase 1AY path. Any missing pin provenance, signer role, timestamp, SHA-256 binding, quorum, recovery measurement, independent witness, immutable retention or staging approval remains **BLOCKED**, not inferred as complete.

**No external witness registration, WORM bucket creation, provider credential operation, staging migration, real restoration, deployment, stock posting, finance posting, supplier dispatch or main merge** is authorized by this phase.
