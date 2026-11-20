# Phase 1DA — Append-only incident custody, two-witness high-watermark, denied rollback replay (HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Branch:** `chore/phase0-foundation-20261106`, **not main**  
**Governance:** PR #1 Draft/open/unmerged, Issue #2 OPEN  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; `quarantineRequired=true` unconditionally.

## Reason for this control

Phase 1CZ's four-role mandate and incident/witness/recovery candidate signatures detect local mathematical contradictions. They **cannot** establish an external corporate mandate or offsite immutable custody. Without a separately enforced high-watermark, an applicant could produce a new internally plausible incident story after dropping old log entries or rolling back a checkpoint. Phase 1DA narrows that local weakness by requiring **deterministic, forward-only event linkage** and dual previous-witness signatures over a proposed new log head, followed by a signed, denied-release replay rehearsal. All input pins, alleged roots, source records, timestamps, store IDs and prior ledger state are still operator-supplied.

No remote storage CAS, append-only WORM writes, source fetching, provider onboarding, corporate identity verification, trusted hardware signing, admin mutation, invoice/stock/customer action or production deployment is executed by this phase.

## Operator-only offline preflight

A corporate-authorized reviewer may inspect a **locally held candidate evidence packet** through:

```sh
node scripts/phase1da-appendonly-incident-replay-ledger.mjs \
  --inspect-incident-ledger /approved/offrepo/phase1da-ledger.json
```

The CLI rejects `GITHUB_ACTIONS=true`, accepts only a regular non-symlink local JSON file up to 256 KiB, checks the current clock itself rather than trusting an applicant's input clock, prints a bounded key-free HOLD receipt, and returns nonzero if candidate mathematical consistency fails. It performs **no network requests or file writes**. Provider signing keys, real employee credentials, private trust keys, contract records or access tokens must never be entered into Git, PR comments, test fixtures or chat.

The top-level candidate fields are `czEvidence`, `anchor`, `events`, `witnessHeads`, `replay`, `replaySignatures`, `incidentState`. In a pure unit test, `now` may also be injected for deterministic fixture validation; the operator CLI always overrides it with actual local time.

## Phase 1CZ predecessor is rechecked in full

The assessor recomputes `assessMandateForkRecoveryCandidate` from the **raw previous evidence**, not a prior success boolean. It requires complete Phase 1CY signed source/old-new pin custody, corporate root's *claimed* signature, exact four officer mandates/signatures, two previous signed fork witnesses, a Commander+Auditor-signed **HOLD-only** recovery dry-run, and `quarantineRequired=true`. Any forgery or break in this upstream chain prevents a locally valid new ledger from being accepted.

This is not independent legal, corporate, PKI, GitHub or external storage authorization: the previous root and keys were all candidate-controlled.

## Exact proposed high-watermark and four-stage log

The applicant-supplied `anchor` must contain exactly `schemaVersion:1`, repository, source SHA, incident ID, `storeId`, `ledgerVersion`, `ledgerDigest`, `checkpointDigest`, `observedAt`, `retentionUntil`. The incident/head/checkpoint must match Phase 1CZ. Version must be a bounded nonnegative safe integer, prior digest an exact lowercase SHA-256, observation fresh, and claimed retention more than 30 days in the future. **It is not authenticated offsite durable state**; no atomic CAS or write-once guarantee is provided.

Exactly four records are accepted in this **fixed order**:

| Sequence | Required event | Required detached Ed25519 signatures | Decision |
|---|---|---|---|
| anchor+1 | `INCIDENT_OPENED` | Incident Commander + Security Officer | `QUARANTINE` |
| anchor+2 | `EVIDENCE_SEALED` | Security Officer + Business Officer | `HOLD` |
| anchor+3 | `RECOVERY_REHEARSED` | Incident Commander + Recovery Auditor | `HOLD` |
| anchor+4 | `RELEASE_DENIED` | Business Officer + Recovery Auditor | `HOLD` |

Each record is an exact `{statement,signatures}` pair. Each `statement` binds schema, stage, repository, source HEAD, `main` base SHA, incident ID, strictly next `sequence`, exact `previousDigest`, current checkpoint and archive evidence digests, exact recovery object version, relevant Phase 1CZ cryptographic receipt digest, monotonically increasing `recordedAt`, and mandatory decision. The previous digest is recalculated as SHA-256 of **domain-separated canonical current event bytes**. No missing/extra/reordered event or duplicate/unknown signer can maintain continuity. Submitted signatures use role-specific signed bytes; source and predecessor hashes are signed along with event and decision.

The three underlying evidence digest sources are `Phase 1CZ unsignedCandidateIncidentDigestSha256`, `unsignedCandidateMandateDigestSha256`, and `unsignedCandidateRecoveryDigestSha256`. These are **candidate integrity hashes**, not signatures proving external company mandates; the fourth release-denial event again binds the incident receipt.

The signature and digest domains include:

```text
aaditech/phase1da/candidate-incident-ledger/v1/event-digest/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/incident-event/SECURITY_OFFICER/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/incident-event/BUSINESS_OFFICER/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/incident-event/INCIDENT_COMMANDER/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/incident-event/RECOVERY_AUDITOR/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/witness-head/WITNESS_A/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/witness-head/WITNESS_B/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/replay/INCIDENT_COMMANDER/v1\n
aaditech/phase1da/candidate-incident-ledger/v1/replay/RECOVERY_AUDITOR/v1\n
```

Every signature must be exact canonical 64-byte Ed25519 base64, verified against its previous Phase 1CZ role-nominated SPKI (or **prior** witness generation). Duplicate signing roles, cross-role signatures and altered event decisions are rejected.

## Two distinct signed witness heads

Exactly two `witnessHeads`, one `WITNESS_A` and one `WITNESS_B`, sign the same repo/source HEAD, incident, **anchor+4 ledger version**, newly recomputed final digest, original anchor digest, exact current checkpoint and challenge nonce. Each witness claims an observation later than the last appended event, inside a short bounded UTC verification window, with decision `QUARANTINE`. Their signatures use the **previous** witness public signing keys from Phase 1CZ's original raw nominated source roster, not replacement keys. Contradictions, missing/extra witnesses or swapped roles hard-fail.

These assertions are **not proof** that independently owned remote witness organizations published the head or that they used independently authenticated TLS endpoints. No gossip or offsite CAS runs in this module.

## Separate denied recovery replay

`replay` states `kind:CANDIDATE_READ_ONLY_REPLAY_HOLD`. It must agree exactly with the prior ledger version/digest, recomputed final version/digest, source, incident, archive hash and object version. A replay must claim a start time **after both** witness heads, a bounded finish time, `rollbackAttempt:false`, `unquarantineRequested:false`, and `releaseDecision:HOLD`. The Incident Commander and Recovery Auditor both sign it. This preflight verifies only the mathematical consistency of the **claimed** rehearsal; it performs no actual restoration, retention inspection, immutable ledger re-fetch or disaster-recovery SLO measurement.

`incidentState` must be exactly `{status:'QUARANTINED',forkReports:[],releaseRequested:false,restoredExternally:false}`. Any contradictory incident/fork or release attempt blocks even local mathematical acceptance; **every result** keeps `quarantineRequired=true`, `automaticRecoveryOrUnquarantineAllowed=false` and production HOLD, even when every signature matches.

## Engineering tests and custody

- Source: `scripts/phase1da-appendonly-incident-replay-ledger.mjs`.
- Tests: `tests/phase1da-appendonly-incident-replay-ledger.test.mjs`, **21 adversarial Node test groups** including one positive *synthetic candidate only*, forged source/corporate root, reordered/duplicated signed events, old/next version gaps, wrong predecessor digest, 12 signature-role checks, stale witness/future replay, fake archive object and release bypass.
- Reused ephemeral Ed25519 test inputs: `tests/helpers/phase1da-candidate-fixture.mjs`, generated at test execution and never enrolled as real company keys.
- All three code/test/helper paths added to Phase 1BV/BW exact source custody, M01–M30 completion plan updated. No GitHub Actions YAML or token permission change, no `main` mutation, no provider credentials or remote writes.

After the final development commit, independently verify *new exact-HEAD* GitHub-hosted **push and PR** CI, baseline JS/TS/security tests, frozen Bun audit, disposable real MySQL migrations and Chromium MFA/role smoke, and official Check Runs/Actions Jobs 16-record cross-API reconciliation. Only after successful verification update Draft PR #1 and open Issue #2, recording any failed runs accurately.

## External gates still not satisfied

At phase start, official GitHub APIs returned **0 submitted PR reviews**, **0 installed main branch rulesets**, and HTTP **404** for `main` CODEOWNERS. Genuinely independent company-root/officer appointments, nonauthor latest-head GitHub approvals, actual no-bypass main protection, verified external eMudhra/CCA/RCAI trust hierarchies and signed live CRL/OCSP, MCA/GST legally verified signatories, durably persisted immutable ledger high-watermark with compare-and-swap, independent offsite source witnesses and fork gossip, actual WORM COMPLIANCE delete denial/DR restore and RTO/RPO, signed OIDC/SLSA CI provenance and Security/Legal/Ops/Owner staging acceptance all remain absent. None can be inferred from a mathematically valid test packet or a green internal CI workflow.

**Production always HARD HOLD: no merge, deployment, stock/financial/customer/supplier/provider live operation, unquarantine or real authority claim.**


## Initial hosted CI failure record — explicit and retained

The first Phase 1DA commit `0f5e58329e4b251738b8c789da440dfa572fc5a2` triggered [push run 44658464775](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44658464775) and [PR run 44658472329](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44658472329). Both **baseline tests FAILED**: **727 of 728 JavaScript test groups passed**; the single failed adversarial assertion was `DA: replayed old sequence, skipped sequence, duplicate version and false predecessor rejected`. The underlying verifier **correctly rejected** a duplicate `RELEASE_DENIED` sequence; the test's expected-error selector looked at the string `events[2]` in an expression that also mutated `events[3]`, and mistakenly expected the `RECOVERY_REHEARSED` anomaly instead of `RELEASE_DENIED`. The corrective commit changes **only the test selector priority** to check `events[3]` before `events[2]`, preserving all predecessor and fail-closed ledger checks. These initial runs **must not be relabeled green**, and the new commit needs two fresh hosted CI completions and exact-head cross-API verification before internal engineering can be declared complete. Production HARD HOLD is unchanged.
