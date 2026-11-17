# Phase 1BE — Emergency witness-key revocation freeze, provider audit linkage and encrypted-DR HOLD

**Status:** Internal offline engineering; candidate keys/receipts are **UNVERIFIED**. This is not a provider revocation service, trusted WORM/Object Lock implementation, production change or live encrypted-restore approval. Production release **HARD HOLD**.

**Repository/branch:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` / `chore/phase0-foundation-20261106`. PR #1 Draft/unmerged, Issue #2 open, `main` unchanged.

## Why this phase is necessary

Phases 1BA–1BD prove that *applicant-supplied* Ed25519 signatures, RFC6962 inclusion/consistency paths, claimed provider Object Lock denial receipts and claimed encrypted DR observations fit internally consistent schemas. None of those local proofs authenticates a live witness operator, issued cloud retention/negative delete evidence, an MCA authorized signatory or a licensed CA's revocation data.

A credible incident boundary must prevent the software from continuing to record "normal" witness/reviewer approvals when *one claimed witness key may be compromised*—even when its locally signed evidence is cryptographically valid. Phase 1BE implements a **deny-only, non-reversible candidate freeze**. This does not establish that the suspect key was actually revoked by its provider; an authorized separate process would still be needed.

## Fail-closed signed freeze contract

`scripts/lib/phase1BeRevocationFreeze.mjs` requires an exact, bounded versioned `AADITECH_PHASE_1BE_WITNESS_REVOCATION_FREEZE_V1` envelope that:
- Binds the **exact** Phase 1BD candidate review digest and Phase 1AZ packet SHA-256 to log/incident refs, identified suspected key's Ed25519 public SPKI digest, remaining separately claimed witness and its pinned key, checkpoint and archive object SHA-256s, cloud object version, applicant-reported revocation notice SHA-256 and prior revocation snapshot digest.
- Binds claimed provider negative-delete Object Lock receipt and claimed isolated DR telemetry **only by SHA-256** to Phase 1BD review evidence; neither digest promotes that claim into authenticated provider evidence.
- Requires `reason=SUSPECTED_WITNESS_KEY_COMPROMISE`, `quarantineRequired=true`, `outboundHeld=true`, `releaseDecision=HOLD`, canonical UTC times, prompt (maximum five-minute) claimed freeze activation and a maximum one-hour audit envelope. A compromised key cannot reappear as the trusted surviving cosigner.
- Revalidates the entire upstream Phase 1BD witness/storage/DR claim dossier, then separately validates the *surviving* witness's Ed25519 detached signature and three independent, separately enrolled claimed SECURITY, OPERATIONS and OWNER signatures on **identical** freeze bytes. Rejects replayed source roles, duplicate claimed administrators, wrong SPKI, missing roles, injected fields, forged signatures, stale/future timestamps and changed predecessor data. Witness/reviewer ordering does not change the canonical incident commitment.
- Sets `witnessKeyExternallyRevoked=false`, `independentlyAuthenticatedRevocationSource=false`, `actualObjectLockEnforcementVerified=false`, `actualEncryptedDRVerified=false`, `productionReleaseAuthorized=false`, `productionReleaseBlocked=true` and `releaseDecision=HOLD` even when the applicant-created signature fixture is internally consistent.

`scripts/phase1be-revocation-freeze-preflight.mjs --ci-hold` accepts **zero external inputs**. It has no network, supplier/posting, storage, KMS, CA, MCA, credentials or production release API.

## Local durable freeze and quarantine ledger

`database/migrations/0033_be_revocation_freeze_holds.sql` defines an InnoDB log-level head table and digest-only forensic attempts. The database schema constrains all external authority/actual Object Lock/real encrypted DR flags to `NO` and release to `HOLD`. No unfreeze/GO enum value or endpoint exists.

`scripts/migrate-be-revocation-freeze.ts` validates **all preceding 32 migration SHA-256s**, rejects unknown migration drift, uses the existing advisory migration mutex, and supports only disposable CI or explicitly authorized disposable isolated TLS staging. Production migrations are forbidden.

`server/revocationFreeze/durable.ts` verifies the independently held **local** Phase 1AZ, 1BB, 1BC and 1BD records in transactional lock order (AZ → BB → BC → BD → BE) and checks the Phase 1BD review SHA-256 before a freeze is recorded. The first accepted candidate incident transitions from `HELD_UNVERIFIED` to **`FROZEN_UNVERIFIED`**; exact replay is idempotent, another properly signed incident transitions the same stream to **`QUARANTINED`**, and further attempts remain quarantined. It provides a tamper-evident *local consistency check*, **not an external WORM ledger**: privileged MySQL operators can still modify/delete rows and genuine independent audit is required.

`server/externalReadiness/durable.ts` (Phase 1AZ), `server/evidenceIntake/durable.ts` (Phase 1BB), `server/witnessCustody/durable.ts` (Phase 1BC) and `server/evidenceReview/durable.ts` (Phase 1BD) consult the BE freeze head under `FOR UPDATE` after acquiring their existing stream lock. While the BE incident is frozen or quarantined, **new signed candidate writes and exact prior replay at all four stages** are denied. The acquisition order AZ → BB → BC → BD → BE remains consistent with the BE incident transaction; 1BB's global nonce advisory lock is retained. There is **no automatic key activation, rotation acceptance or freeze clearance**. These guards protect isolated internal evidence workflows, not remote/provider issuance or production activity.

The read-only staging preflight adds Phase 1BE inventory/frozen/quarantine counters, FK/incidence/predecessor integrity checks, explicit external `NOT_VERIFIED` gates and a **staging acceptance blocker** whenever any unresolved freeze is present. CI is permitted to create synthetic frozen incidents for adversarial testing; genuine staging acceptance is not.

## Tests and CI integration

- `tests/phase1be-revocation-freeze.test.mjs`: local Ed25519 signer-quorum, independently claimed reviewer/admin separation, canonical commitment, unrecognized fields, changed archival/DR/revocation digests, compromised key self-signing, forged signatures, expiry/chronology, unauthorized GO and zero-input CLI tests.
- `tests/be-revocation-mysql.integration.ts`: real disposable MySQL tests for missing BD predecessor, sticky freeze/replay, denial of AZ/BB intake replay as well as BC/BD evidence updates, simultaneous conflicting valid freeze notices, post-incident refusal, invalid signature and local privileged head tampering.
- `.github/workflows/ci.yml`: zero-input BE HARD HOLD, migration 0033 + SHA/idempotent rerun, BC/BD suites after BE schema exists and BE real MySQL tests before general staging readiness checks. Release candidate file-hash manifest and migration registry include 0033.
- **Internal verification criteria:** require latest exact development SHA with GitHub Actions baseline and real MySQL jobs successful, no failed steps. Green CI **does not** confer genuine external trust.

## External acceptance remains blocked

1. Approved named provider contract, lawful organization/signatory records verified independently (MCA), approved credentials in a restricted secrets manager **never Git or chat**, independent CCA/RCAI/eMudhra certificate chain/policy/revocation source authentication.
2. Out-of-band named witness organization administration and public-key pin custody verification, current signed revocation CRLs/OCSP/publisher attestations, independent gossip and append-only published tree-head observations. A local applicant-generated emergency notice is insufficient.
3. Authenticated cloud provider-issued Object Lock/retention/legal-hold evidence, authorized auditor witness of actual deletion/overwrite denial, version/scope enforcement and preservation outside the MySQL administrator's control.
4. Provider-approved encrypted backup and isolated staging restore, external KMS authorization, real measured RTO/RPO, updated independently validated revocation snapshot, independent operator controls, three genuine authorized reviewers' signoffs and explicit outbound stop.
5. An independently authorized, audited, non-CI process for incident recovery/replacement key enrollment. **No automatic unfreeze and no unilateral trust reactivation**.

**Release policy:** **HARD HOLD**. Do not deploy, merge PR #1, touch `main`, provision real provider operations, issue external trust, post stock/finance, dispatch products, or send credentials through chat. All synthetic signatures and self-asserted evidence are test data only.
