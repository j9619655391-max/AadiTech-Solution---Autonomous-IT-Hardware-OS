# Phase 1AZ — Externally witnessed archive and DR readiness evidence (HOLD)

**Engineering scope:** Digest-only, fail-closed external witness onboarding candidates, immutable archive retention claims, encrypted recovery dossier consistency and monotonic forensic evidence history. This is not actual provider/sandbox authorization, immutable cloud storage or a recovery operation.

**Governance:** `chore/phase0-foundation-20261106`; PR #1 stays Draft/unmerged against `main`; Issue #2 open; `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, release decision HOLD.

## Interfaces delivered

1. `scripts/lib/phase1AzExternalReadiness.mjs` — strict, fixed-shape `AZ_PURPOSE` versioned packets. SHA-256 references only. Rejects raw documents, access tokens, credentials, unknown/GO fields, malformed or all-zero digests, and unbounded timestamps.
2. Candidate witness dossier contains distinct witness, organization and administrative-authority refs, public SPKI key digest, contract digest and transparency publisher policy digest. `scope=CHECKPOINT_WITNESS_ONLY`; `state=CANDIDATE_UNVERIFIED`. Duplicate organizations, administrators and keys are denied; no supplied organization name becomes authenticated.
3. Archive dossier binds a Phase 1AW checkpoint receipt to an object digest, storage-account digest, version-id digest, policy digest, encryption key-identifier digest, legal-hold claim digest and claimed compliance-mode retention window. Retention-duration checks are **internal assertions**, not proof that WORM/Object Lock is configured or legally enforced.
4. Recovery dossier binds source/restored checkpoint hashes, source/restored manifest hashes, the archive digest, revocation snapshot digest, a bounded chronology, claimed RTO/RPO measurements, `encryptedRestoreState=NOT_EXTERNALLY_VERIFIED` and `outboundHeld=true`. It rejects mismatches and claimed objective overruns; it never represents a genuine encrypted restore or an independently measured performance result.
5. Three distinct claimed SECURITY, OPERATIONS and OWNER review references/digests are required. The applicant-supplied approval refs cannot establish authentic reviewer identities or their authority.
6. `database/migrations/0029_az_external_readiness_holds.sql` registers minimal InnoDB evidence-head/attempt history and permanent internal HOLD fields. `server/externalReadiness/durable.ts` serializes competing revisions per log under `SELECT FOR UPDATE`, records conflict/rollback/gap/predecessor/invalid-claim incidents and quarantines the stream. Duplicate exact heads are idempotent; earlier accepted digests reintroduced later are rejected and recorded as rollback incidents. No packet source content is persisted.
7. `scripts/migrate-az-readiness.ts` refuses production targets and requires prior migration checksums and isolated CI or explicitly approved disposable TLS staging; the schema is idempotently rerunnable.
8. `tests/phase1az-external-readiness.test.mjs` and `tests/az-readiness-mysql.integration.ts` cover hostile extra fields, forged status, duplicate administrator scope, retention claims, recovery mismatch, concurrent conflicting revision, replay, gap, rollback and isolated-database tampering.
9. `scripts/phase1az-external-readiness-preflight.mjs` is a zero-input CI HOLD-only command. `.github/workflows/ci.yml` checks it plus migration 0029, checksum/idempotent rerun and real disposable MySQL tests. Staging preflight explicitly reports unresolved quarantine and all external trust gates as NOT_VERIFIED.

## External evidence required before any genuine approval

- Independent provider and witness agreements and named legal entities signed and confirmed through separately authenticated channels, including verified operational/administrative separation and effective authorizations. Keys must be independently enrolled and pinned from trusted source, not self-entered.
- True third-party append-only transparency receipt publication, valid inclusion **and consistency** proofs against authenticated heads, independent time sources, witness-gossip anti-equivocation, outage alerting and irreversibly recorded incidents.
- Independently managed archive with enforced object lock/WORM, specified retention/object versioning, legal holds, encryption key stewardship and key-recovery controls, recorded deletion denial, remote-object audit and read-after-restore verification. MySQL is **not** WORM; privileged database actors may change or delete these tables.
- Provider authorization plus RCAI/CCA/eMudhra validated PKIX/CP-CPS, authenticated live CRL/OCSP, MCA corporate registry and authorized signatory evidence, independently authenticated company and reviewer roles.
- Authorized encrypted backup and actual restoration into fresh isolated TLS staging; independent recovery observers, verified checkpoint/revocation continuity, real measured RTO and RPO, tested failure and partial-restore procedures and separate owner, security and operations approvals.
- No production go-live, external key promotion, stock/GRN posting, finance release, PO dispatch or deployment without explicit later release governance.

## Controls deliberately NOT implemented in this phase

No WORM bucket or storage account creation, no external provider API calls, no third-party trust enrollment, no secret retrieval, no live encrypted restore, no legal verification, no external staging access, no production flag changes, no merging of PR #1. CI can validate self-contained code and disposable database behavior **only**.

## Acceptance gate

**Engineering:** passing CI for the *latest* branch head and green baseline/MySQL checks establish only internal engineering correctness.

**External acceptance:** BLOCKED until independently authenticated organizations and operations, actual immutable cloud audit data, live revocation validation, real DR measurements and legal/security owner approvals are supplied by authorized channels.

**Production:** HARD HOLD regardless of internally consistent packets or green CI.
