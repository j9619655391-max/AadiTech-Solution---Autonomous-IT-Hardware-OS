# Phase 1AX — Independent reviewer-key rollover, checkpoint anti-equivocation and incident recovery

Status: ENGINEERING SPECIFICATION / NOT EXTERNALLY AUTHORIZED. Production release HOLD.
Branch: `chore/phase0-foundation-20261106`. PR #1 remains Draft; Issue #2 remains open.

## Trust boundaries
No fixture, local signer, test certificate, synthetic approval, CI success, or internal recovery drill is evidence of external reviewer identity, eMudhra sandbox authorization, RCAI/CCA chain validity, signed live CRL/OCSP, MCA corporate authority, or independent staging acceptance. Fail closed on unknown issuer, untrusted key, unavailable revocation, missing evidence, or disputed checkpoint.

## Reviewer key lifecycle contract
- Registry entries: reviewer_id, organization_id, key_id, algorithm, public_key_fingerprint, validity window, provenance/evidence URI and digest, authorization scope, status, generation, predecessor_key_id, created_at and independent approver identities.
- States: PROPOSED -> VERIFIED_PENDING_ACTIVATION -> ACTIVE -> RETIRING -> RETIRED; any state -> QUARANTINED/REVOKED with durable incident reference. Never reactivate a revoked generation.
- Rotation proposal must be signed by the currently active authorized reviewer key and independently approved by a distinct authorized reviewer. If the old key is compromised, use a separately authenticated break-glass governance quorum; never accept old-key proof alone.
- Require signed canonical payloads with domain separation, algorithm allowlist, exact tenant/organization scope, nonce, monotonic generation, validity interval and prior registry digest. Reject duplicate keys, overlapping unauthorized activation, clock-skew violations, stale generations and self-approval.
- Old signatures remain verifiable against their historically valid key and revocation effective time; they do not authorize new actions after retirement or compromise. Record emergency key revocation and propagation confirmation.

## Signed checkpoint / anti-equivocation
- Canonical checkpoint fields: log_id, tenant_id, tree_size, root_hash, sequence, previous_checkpoint_digest, issued_at, signer_key_id, signature_algorithm and signature.
- Verify domain-separated signature against independently pinned reviewer trust roots; enforce sequence and tree-size monotonicity, same-size same-root, valid append-only consistency proofs, previous-checkpoint linkage and bounded clock policy.
- Persist latest accepted checkpoint and independent witness observations in durable transactional storage with uniqueness constraints. Two valid signatures for the same log/sequence/tree-size but different roots are an equivocation incident, not last-write-wins.
- On fork, missing consistency proof, rollback, stale checkpoint or invalid witness quorum: quarantine log, freeze trust promotion and all dependent release approvals; preserve both conflicting signed artifacts and verification metadata.
- Witness quorum policy must specify independently operated witnesses, threshold, rotation, timeout and outage behavior; never count multiple keys under one administrative authority as independent witnesses.

## Incident recovery rehearsal
1. Start in an isolated disposable environment with synthetic fixtures explicitly labeled TEST ONLY; capture baseline signed checkpoint and key registry.
2. Simulate lost reviewer key, stolen key, replayed rollover, unauthorized dual approval, checkpoint rollback, same-size conflicting roots, witness outage, corrupt snapshot and partial restore.
3. Confirm fail-closed quarantine, alert emission, idempotent incident creation, immutable evidence retention and inability to promote a release.
4. Restore verified backup to a fresh environment; validate checkpoint continuity and key revocation against independent evidence before any controlled resume.
5. Require separate security and operations sign-off; document evidence hashes, timestamps, actors, recovery time and observed data loss. Never claim RTO/RPO compliance without measurements.

## Test and acceptance matrix
- Valid rollover with two independently authenticated approvers: PASS required.
- Self-approved rollover / compromised predecessor / replay / generation rollback / wrong tenant: DENY required.
- Invalid checkpoint signature / conflicting root / truncated consistency proof / stale witness: QUARANTINE required.
- Witness outage and unavailable revocation: HOLD required.
- Restart, concurrent submissions, durable replay and isolated restore: no lost incident, no unauthorized state transition.
- Each test must link to code commit, CI run, fixture provenance and reviewer; externally dependent cases remain BLOCKED until genuine evidence is available.

## Release gate
ProductionReleaseAuthorized = false; ProductionReleaseBlocked = true until signed provider authorization, authenticated reviewer trust anchors, independently verified RCAI/CCA/eMudhra certificate policy and live revocation evidence, MCA legal/signatory evidence, independently approved staging/DR drill and explicit owner/security/operations release sign-off. Do not merge PR #1 or deploy as part of this phase.
