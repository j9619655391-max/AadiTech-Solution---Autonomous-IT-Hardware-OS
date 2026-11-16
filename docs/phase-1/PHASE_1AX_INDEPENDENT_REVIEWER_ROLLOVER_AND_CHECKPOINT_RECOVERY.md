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


## Phase 1AX additive engineering implementation (2026-11-16)
- `scripts/lib/phase1AxIndependentGovernance.mjs`: domain-separated offline Ed25519 rollover and witness checks; no externally authenticated keys.
- `server/checkpointGovernance/durable.ts`: isolated-CI/disposable-TLS-staging-only InnoDB write path. Per-log transactional row lock serializes adversarial concurrent observations, unique receipt index makes exact retries idempotent, signed checkpoint claims and reviewer SPKI pin digests are checked before persistence, and fork/rollback/gap/unapproved key substitution permanently quarantine the stream for this release gate.
- `database/migrations/0028_ax_checkpoint_governance.sql`: new stream/observation evidence tables; `scripts/migrate-ax-checkpoints.ts` enforces checksum-matched 0001-0027 prerequisites, guarded isolated targets, idempotent rerun.
- `tests/ax-checkpoint-mysql.integration.ts`: real disposable MySQL integration tests cover genesis progression, exact retries, simultaneous competing signed writes, unauthorized key substitutions, rollback, gaps, invalid signatures, digest-tamper detection, and isolated **reconstruction** into another synthetic log.
- `.github/workflows/ci.yml`: separately gates the new migration, rerun, and MySQL suite; `package.json` scripts run the same checks.

### Security interpretation and still-open gaps
- `ACCEPTED_UNTRUSTED` means only that a syntactically valid offline Ed25519 evidence record was serialized. It is NOT evidence that journal/policy claims were externally authenticated or that the legal/security signers actually hold those roles.
- The MySQL tables are not WORM storage, a transparency log, multi-organization witness service, or a verified off-site backup. Privileged DBA alteration and deletion remain outside the cryptographic integrity guarantees. Detectable readback inconsistency is not externally immutable proof.
- The isolated reconstruction test is **not** a real encrypted backup/restore disaster-recovery drill. Measured, independently witnessed RTO/RPO, external immutable snapshots and live revocation recheck remain unverified.
- Public-key pin continuity blocks implicit key changes; authorized emergency rollover requires genuine independently authenticated reviewer identity, a provider-approved root of trust and a separate signed governance process before any key can be promoted.
- The service has no externally callable route and deliberately refuses production targets. No stock, finance, supplier dispatch, signed credential issuance, trust-anchor promotion, or release feature flags are enabled.
- CI success establishes internal test correctness only. Actual external authorization, provider onboarding, MCA signatory evidence, RCAI/CCA validation, signed live CRL/OCSP and independent staging approvals stay pending.

### Verification ledger
- Previous Phase 1AX CI run `43884032849`: GitHub reported **success** on `87b6ca48e6573bd1e026e28cf769bed1d312c9a2`.
- Latest 0028 schema and MySQL integration changes: **CI confirmation pending** until a new push and PR run conclude.
- ProductionReleaseAuthorized=false; ProductionReleaseBlocked=true; releaseDecision=HOLD; PR #1 Draft, Issue #2 open; `main` untouched.

### Additional acceptance evidence (2026-11-16)
- CI `43890261491`: baseline and disposable-MySQL integration jobs **success** after migration 0028, key-continuity quarantine, concurrency, retry and corruption tests were introduced.
- CI `43890564972`: baseline and disposable-MySQL integration jobs **success** with read-only Phase 1AX staging preflight. In the staging target, any persisted quarantined checkpoint stream is a readiness blocker. In disposable CI, synthetic incident fixtures remain informational.
- A subsequent unit hardening change requires witness-quorum satisfaction on **each canonical signed checkpoint claim** rather than incorrectly summing separate organizations across unrelated checkpoints. Repeated claimed witness authorities may legitimately sign successive checkpoints but may not count twice within one checkpoint quorum. An unverified/missing prior signed checkpoint or broken chronological linkage is explicitly blocked.
- Independent, externally authenticated witness identity and issuer acceptance remain PENDING; even a locally consistent witness continuity test cannot promote trust, approve operations or unfreeze production.

**Verification caveat:** the per-claim quorum patch and its newer regression cases require fresh completed CI before their status can be marked verified.
