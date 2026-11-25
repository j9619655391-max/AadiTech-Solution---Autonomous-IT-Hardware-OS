# Phase 1CZ — Candidate corporate mandate, fork incident and segregated DR review (HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Branch:** `chore/phase0-foundation-20261106` only; `main` protected/unchanged  
**PR #1:** Draft/unmerged; **Issue #2:** OPEN  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Purpose and trust boundary

Phase 1CX provides pinned HTTPS technical *candidate* intake, Phase 1CY requires operator-proposed old/new pin continuity and two signed prior witnesses. Neither proves corporate signer appointments or a durable independently witnessed offsite incident/recovery outcome.

Phase 1CZ adds a strict **operator-only, offline, read-only and candidate-only** root/mandate/incident/recovery intake. Its goal is to detect contradictions, key reuse, tampered detached signatures and stale/forked checkpoint evidence, while **never** mistaking applicant-supplied keys/mandates for genuine Security, Business, Legal, Owner or provider authority. All output always enforces `quarantineRequired=true`, `automaticRecoveryOrUnquarantineAllowed=false`, `productionReleaseAuthorized=false` and `releaseDecision=HOLD` — including when synthetic cryptographic claims are consistent.

The script makes no network calls, consumes no GitHub/provider credentials, mutates no external system, and cannot install keys, unquarantine, deploy, merge or sign a live release.

## Explicit human-operator candidate inspection

An independently authorized operator may inspect an already approved and separately sourced JSON candidate through:

```sh
node scripts/phase1cz-corporate-mandate-incident-quarantine.mjs \
  --inspect-candidate-quarantine /approved/offrepo/phase1cz-incident.json
```

The local JSON file must be a regular non-symlink, up to 256 KiB, and not a Git or chat attachment containing secrets. The CLI refuses `GITHUB_ACTIONS=true`; it uses the actual local clock to check short-lived claims and ignores any caller-supplied clock. The pure assessor also accepts an explicit `now` for deterministic unit tests, **not** proof from a timestamp authority. Nonconforming evidence exits nonzero. No real operator command has been executed with approved corporate root/mandate credentials or authenticated offsite storage.

The packet contains `cyEvidence`, `authority`, `mandate`, `mandateSignature`, `incident`, `officerApprovals`, `forkWitnesses`, and `recovery`.

### Source continuity

`cyEvidence` is the **raw Phase 1CY packet**, not a single applicant-provided boolean. Phase 1CZ calls `assessOperatorPinLifecycle` and requires full Phase 1CX signed-source math, exact two-opinion previous-witness high-watermark, previous/current roster and rotation checks, two original Security/Business signatures, and prior incident candidate CLEAR before inspecting a new quarantined incident. Any stale/failing prior evidence is a hard anomaly. Actual incident quarantine is **still mandatory in Phase 1CZ**.

### Candidate corporate root and four role appointments

`authority.root` contains the claimed `keyId`, `publicKeyPem`, `spkiSha256`, `organizationId`, `enrollmentEvidenceSha256`, `enrolledAt`, `expiresAt`, and `revoked:false`.

`authority.officers` has exactly four roles: `SECURITY_OFFICER`, `BUSINESS_OFFICER`, `INCIDENT_COMMANDER`, `RECOVERY_AUDITOR`. Each candidate requires an exact role, organization ID, distinct nonauthor GitHub login, mandate digest, public Ed25519 SPKI and key ID, bounded key validity and unrevoked state. Security and Business must be **byte-equivalent to the previously signed Phase 1CY candidate appointments**. The root, all four officers and source witnesses must have no cross-role SPKI collision. The declared root and associated mandate are **operator-provided**; verifying the signature does **not** independently authenticate the root, the company's MCA registry entry or a real officer's appointment.

A root-signed `mandate` statement with `kind:CANDIDATE_CORPORATE_MANDATE_HOLD` binds repository, exact dev HEAD and `main` base, Phase 1CY transition digest, organization and all four officer public-record digest, nonce, short canonical issue/expiry and `decision:HOLD`. The root signs domain-separated canonical JSON; no GO claim or extra field is permitted.

### Incident quarantine and independent segregation

The `incident` statement must be `kind:FORK_OR_COMPROMISE_REVIEW_ONLY`, `decision:QUARANTINE`, and include exact incident ID, repo/head, previous and current checkpoint digests, Phase 1CY digest, current source roster SHA-256, independent claimed archive-evidence hash, same nonce, and bounded issue/expiry. **All four** role-specific detached operator signatures are required; these are additional mathematical acknowledgments, not proof that any reviewer read/approved a GitHub PR.

Exactly two `forkWitnesses`, one `WITNESS_A`, one `WITNESS_B`, each sign the same incident ID, previous/current checkpoint/head/nonce, event time and `decision:FORK_REVIEW_PENDING` using the source's **prior** signing key. A missing/wrong/duplicate prior witness never counts as a quorum. The source and archived evidence hashes are still claimant input, not an authenticated external immutable checkpoint or verified WORM object.

`recovery.statement` has `kind:READ_ONLY_REHEARSAL`, exact incident/head/archive digest, **the exact archive object version reported by both currently signed witness packets**, a syntactically valid restore region, claimed hash match/delete denial, observed-after-witness time and `decision:HOLD`. The statement needs a separate detached `INCIDENT_COMMANDER` and `RECOVERY_AUDITOR` signature. These are claimed rehearsal facts **not** an actual S3 Object Lock retention test, independently recorded restore, accepted RTO/RPO or authorization to lift quarantine. Security/Business and root signatures are segregated from the two recovery signatures.

All signatures use Ed25519, SHA-256 of canonical recursively sorted JSON and unique role/domain separation:

```text
aaditech/phase1cz/mandate-incident-quarantine/v1/mandate/ROOT/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/incident/SECURITY_OFFICER/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/incident/BUSINESS_OFFICER/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/incident/INCIDENT_COMMANDER/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/incident/RECOVERY_AUDITOR/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/fork/WITNESS_A/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/fork/WITNESS_B/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/recovery/INCIDENT_COMMANDER/v1\n
aaditech/phase1cz/mandate-incident-quarantine/v1/recovery/RECOVERY_AUDITOR/v1\n
```

B64 signatures must decode to 64 bytes, match the pinned Ed25519 SPKI and sign exactly the expected role-specific bytes. The reporter emits no operator names, SPKI, PEMs or private key material, and a candidate-only successful result **cannot** authorize an externally observable side effect.

## Real release blockers / independent acceptance

Before any production GO, the owner must obtain verifiable out-of-band corporate root enrollment, real authorized Security/Business and Incident Commander/Recovery Auditor mandate records, named latest-head nonauthor GitHub approvals, installed no-bypass rulesets and actual `main` CODEOWNERS, genuine offsite high-watermark retrieval and signed fork witness authentication, persistent incident quarantine state and separately approved break-glass procedure, actual WORM compliance retention/delete-denial and DR restore evidence, approved RCAI/CCA/eMudhra certificate-policy and authenticated CRL/OCSP, verified MCA/GST legal signatories, independently signed OIDC/SLSA workflow provenance and Security/Legal/Ops/Owner staging signoffs.

At phase start official GitHub API still showed **zero PR reviews**, **zero installed branch rulesets** and **HTTP 404 for `main` CODEOWNERS**. No genuine external corporate authority, signing credentials, offsite checkpoint or provider agreement was submitted. Synthetic signatures in unit tests are never external evidence.

## Implementation and validation

- `scripts/phase1cz-corporate-mandate-incident-quarantine.mjs` — pure read-only assessor plus operator-only bounded local CLI.
- `tests/phase1cz-corporate-mandate-incident-quarantine.test.mjs` — **19** adversarial test groups: crypto-positive **candidate only**, forged root/company mandates, substituted independent officer logins/SPKIs, stale head/base/CY digest, false release, missing fork witness, compromised signature, incorrect recovery object version, false delete-denial, and non-disclosing HOLD receipts.
- `tests/helpers/phase1cz-candidate-fixture.mjs` — extracted **ephemeral locally generated** Phase 1CY signed fixture helper reused by Phase 1CZ tests; no real secret or signer key persisted.
- New code/test/helper files included in Phase 1BV and 1BW explicit immutable source custody inventories; `docs/completion/MASTER_M01_M30_COMPLETION_PLAN.md` updated.
- No CI YAML, GitHub admin permissions, installed production service, `main`, PR merge state or supplier/customer/financial actions were modified. Verify **both** hosted push and PR CI on the exact final Phase 1CZ HEAD; inspect JS/TS/security tests, frozen audit, disposable MySQL and Chromium MFA role smoke. Reconcile distinct Check Runs and Actions Jobs suites; document any corrective failure history and only verified latest-head results in PR #1 and Issue #2.

**Final engineering assurance is not production acceptance. Release HARD HOLD.**
