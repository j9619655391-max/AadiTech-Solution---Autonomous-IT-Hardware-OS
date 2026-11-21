# Phase 1BB — RFC 6962 append-only witness consistency and nonce-custody concurrency

**Status:** INTERNAL, OFFLINE SECURITY ENGINEERING; no independent source authenticated. Production remains **HOLD**.
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Branch:** `chore/phase0-foundation-20261106`. PR #1 Draft/unmerged; Issue #2 open; `main` unchanged.

## Why this additive control exists

Phase 1BA and the original Phase 1BB implementation validate synthetic signed witness receipts, Merkle **inclusion**, a digest-bound source enrollment dossier and six-domain challenge receipts. An inclusion proof alone cannot establish that a newer advertised Merkle tree preserved an earlier signed tree. Also, Phase 1BB's global six-nonce custody may deadlock when two *different* streams simultaneously insert overlapping unique nonce keys on an InnoDB server.

This patch addresses these discrete internal engineering gaps, but does not claim to complete external provider onboarding or deploy real witness operations.

## Appendix A — append-only Merkle consistency verification

- `scripts/lib/phase1BbWitnessConsistency.mjs` exposes `phase1BbVerifyConsistencyProof` with RFC 6962 §2.1.2 SHA-256 Merkle consistency logic: domain-separated node hashing (`0x01 || left || right`), monotonic bounded tree size, strict 64-hex node encodings and bounded audit-path length.
- For equal tree sizes, accept **only** an empty proof and identical root. For expanded trees, reconstruct the advertised old and new roots from the proof and reject a truncated/extra/tampered path or rolled-back size.
- `assessPhase1BbWitnessConsistency` checks every claimed witness across an **identical** Phase 1AZ digest dossier and Phase 1BA signed witness schema. It verifies historical **and** new Ed25519 signatures, the public SPKI digest and claimed administrative identity against the corresponding AZ witness candidate, and the archive-entry inclusion proof in both heads.
- The same proof must bind exactly one log/checkpoint receipt/archive digest, a nondecreasing tree size, chronological observations and a common old/new root across separately administered witness candidates. Duplicate authorities, missing witness, known-key substitution, same-size divergent roots, forged signatures, incomplete path and missing historical evidence fail closed.
- The protocol deliberately treats self-supplied AZ candidate records and caller-provided public SPKI pins as **unverified**. Neither mathematical proof correctness nor two claimed different organizations authenticates a publisher or proves a real operator's independence.
- `tests/phase1bb-witness-consistency.test.mjs` contains an independent recursive Merkle-tree/subproof generator tested across historical sizes 1–16, altered-path vectors, source/authority substitution and cross-witness conflicting tree heads.

The mathematical reference is the IETF <https://www.rfc-editor.org/rfc/rfc6962#section-2.1.2>. This phase is *not* a complete RFC 6962 certificate-transparency implementation: the real signed-tree-head protocol, audit/gossip network, authenticated publication, storage operations and external witnesses are not active.

## Appendix B — MySQL global challenge custody

- `server/evidenceIntake/durable.ts` now acquires a bounded **server-local** MySQL `GET_LOCK('aaditech-bb-global-nonces',15)` before any stream-row lock and before allocating the six global challenge nonces.
- This lock serializes potentially overlapping unique-key inserts across **different** log streams, preventing interleaved InnoDB nonce-claim deadlock cycles seen in CI. A failed lock acquisition aborts without release or trust promotion. The connection releases the advisory lock in `finally`, after commit/rollback, on every normal completion or error.
- Per-log InnoDB head locking and existing exact replay/fork/quarantine/nonce collision controls stay intact. The global nonce lock does not transform the internal database into multi-region distributed consensus, external immutable storage, or a production security boundary. Privileged MySQL operators can still modify rows.
- `tests/bb-evidence-mysql.integration.ts` adds six repeated concurrent, cross-log shared-challenge races. Each pair must yield exactly one **HELD unverified** acceptance and one nonce-replay quarantine; all readback forensic history must remain locally consistent.
- No actual production database is accessed, and only disposable CI or explicitly authorized isolated TLS staging is allowed. No migration or release authorization is needed for this **code-level** lock ordering change.

## CI verification / release gates

`scripts/phase1bb-consistency-preflight.mjs --ci-hold` accepts **zero input**, no real witnesses, credentials or private evidence, and emits machine-readable release HOLD. `.github/workflows/ci.yml` runs it before baseline tests. Standard test discovery loads the new security unit suite and the preexisting real disposable-MySQL integration suite.

**Acceptance criteria:** all latest HEAD baseline tests, production-HOLD CLI checks, repeated cross-log nonce race and MySQL integration steps must complete successfully. Do not assert CI success until the new HEAD workflow finishes.

**Still blocked:** signed provider sandbox authorization and credentials, independently authenticated witness keys/administrations, verified append-only publisher operation and gossip against *actual published* heads, genuine WORM retention/deletion-denial audit, independently approved encrypted restore with measured RTO/RPO, independently validated RCAI/CCA/eMudhra/MCA chain/revocation, and legal/security/operations approval.

Every outcome remains `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No deployment, provider credential issuance, external trust-anchor promotion, PR merge, stock/financial posting or dispatch.
