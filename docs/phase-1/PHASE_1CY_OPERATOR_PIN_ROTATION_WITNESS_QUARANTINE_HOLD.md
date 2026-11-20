# Phase 1CY — Operator pin lifecycle and signed previous-witness high-watermark quarantine (HARD HOLD)

**Date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development-only:** `chore/phase0-foundation-20261106`; protected `main` untouched; Draft PR #1 unmerged; Issue #2 open.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Why Phase 1CY exists

Phase 1CX checks three separate operator-proposed signed revocation/current checkpoint source packets with exact source SHA and monotonic sequence: `REVOCATION`, `WITNESS_A`, `WITNESS_B`. It does **not** establish the independent legitimacy of any public key, TLS pin, certificate-policy root, previous durable checkpoint or corporate reviewer appointment. Simply changing the configured pins could allow a malicious replacement source to self-sign a plausible new high-watermark. Phase 1CY adds a strict offline **candidate-only** change-control gate for these transitions and an explicit fail-closed incident quarantine.

The new script `scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs` accepts **only one** explicit human operator local-file inspection action. It does not access GitHub, DNS, a provider API, S3, CA, WORM, CI or production systems; it does not install sources, request reviews, replace keys, clear incident state, invoke credential managers or deploy. Its synthetic fixtures and operator-supplied public pins must never be promoted to legal or independently authenticated corporate approval.

## Offline operator syntax

After genuine third-party/public-key enrollment and corporate Security/Business mandates have been *independently* authenticated out of band, an authorized operator may run this read-only technical preflight:

```sh
node scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs \
  --inspect-operator-handoff /approved/offrepo/phase1cy-operator-handoff.json
```

The input is a regular non-symlink JSON file (≤256 KiB); GitHub Actions execution with `GITHUB_ACTIONS=true` is explicitly forbidden. This is an **offline evaluation only**. Do not put passwords, approved credentials, private signing keys, authentic personal/organization attestations, trust manager access tokens or real signature secrets into Git, chat, PR comments or test fixtures. Any failed check returns nonzero exit code, `quarantineRequired=true`, and `releaseDecision=HOLD`. A mathematically consistent candidate may have `quarantineRequired=false` but still **cannot clear a real incident or production HOLD**.

## Required candidate JSON structure and roles

The packet contains eight logical top-level fields: `manifest`, `observations`, `previous`, `statement`, `officerSignatures`, `rotations`, `historicalWitnesses`, `incidents` (plus the optional verification clock `now`, if supplied in offline JSON; otherwise a fixed conservative library default applies).

- `manifest` and `observations`: exact Phase 1CX source manifest and signed revocation/witness response records, already validated using `assessCandidateRemoteQuorum`. Both remain **candidate source observations** unless separately retrieved through authenticated approved channels; an offline `status:read` assertion alone is not proof of a network read.
- `previous.anchor`: precise operator-proposed previous `epoch`, `checkpointDigest`, `revocationVersion`, `revocationDigest`, and `observedAt`, byte-for-byte equal to current `manifest.previousAnchor`.
- `previous.sources`: exactly three *previously nominated* `REVOCATION`, `WITNESS_A`, `WITNESS_B` source specifications. Their hosts, paths, TLS SPKI pins, Ed25519 signing SPKIs, key IDs and public keys must satisfy the original Phase 1CX fixed DNS/route/cryptographic syntax. They are **operator-supplied**, not independently enrolled immutable historical pins.
- `previous.officers`: exactly `SECURITY_OFFICER` and `BUSINESS_OFFICER`. Each has `role`, `organizationId`, `githubLogin`, `mandateDigest`, `keyId`, `publicKeyPem`, `spkiSha256`, `validFrom`, `validUntil`, `revoked`. The two nominated GitHub accounts must be distinct, nonauthor, have the same purported organization but different active Ed25519 SPKIs and key IDs. The `mandateDigest` itself is **not independently verified legal appointment proof**.
- `statement`: exact `schemaVersion:1`, `kind:CANDIDATE_OPERATOR_PIN_HANDOFF_HOLD`, repo/current head/main base/Phase 1CV policy and CV candidate digests, current nonce, previous checkpoint+revocation epoch/version/digests, next exact epoch/version/checkpoint and signed revocation digest, SHA-256 of both previous and current three-source pin rosters, canonical UTC `issuedAt`/`expiresAt` (≤15 min) and `decision:HOLD`.
- `officerSignatures`: exactly two role-named canonical base64 Ed25519 detached signatures over the complete handoff statement. A signature from an unappointed/self/duplicate/expired/revoked claimant is denied. The cryptographic proof **does not authenticate the appointment** or confirm either GitHub account actually approved the latest PR HEAD.
- `rotations`: **one exact row for each changed source role**, no row for an unchanged role. Each has `role`, `previousSignature`, and `successorSignature`. The rotation digest binds the complete signed operator handoff, old and new public signer pins, old/new TLS pins, key IDs, actual source host and fixed source paths. Both the previously supplied key and the replacement key must cryptographically countersign. A revoked former source signer or any key used in two different roles forces **quarantine/break-glass**, not a convenient unilateral replacement. For a TLS-only/hostname-only change without signer-key change, the same key still signs both declared old/new assertions and the two officers independently approve the new complete roster.
- `historicalWitnesses`: exactly two statements, one `WITNESS_A` and one `WITNESS_B`, each signed by the *prior* witness source public key. The statement ties prior epoch, prior checkpoint/revocation digest/version, current source SHA, current challenge nonce and a bounded observation timestamp; stale, contradictory, missing or invalid signatures quarantine.
- `incidents`: `{status:'CLEAR',forkReports:[],recoveryRequested:'NONE'}` is the only mathematically consistent candidate form. Any reported fork, `QUARANTINED` state, unknown incident fields or any request such as `UNQUARANTINE` forces a hard quarantine. Recovery requires a **separate**, actual independently authenticated Security/Business/Legal/Ops incident process, externally witnessed high-watermark and signed postincident re-enrollment. This code never auto-unquarantines even if all signatures are valid.

All candidate signatures use Ed25519 with explicitly separated domains:

```text
aaditech/phase1cy/readonly-operator-handoff/v1/handoff/SECURITY_OFFICER/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/handoff/BUSINESS_OFFICER/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/rotation/REVOCATION/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/rotation/WITNESS_A/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/rotation/WITNESS_B/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/historical-anchor/WITNESS_A/v1\n
aaditech/phase1cy/readonly-operator-handoff/v1/historical-anchor/WITNESS_B/v1\n
```

The domain is followed by recursively lexicographically sorted canonical JSON. No two role identities can reuse one SPKI, and no new role can borrow another role's old SPKI. The only permitted rollover key reuse is the **same unchanged source role** retaining its own prior signing key. This is key *collision prevention*, not independent verification of the proposed old-generation key's origin.

## Hard trust boundaries and production prerequisites

Even a fully matching offline six/four signature set and previous witness math never creates actual independent evidence. The output permanently reports these as **false**:

`authorizedCorporateOperatorMandatesIndependentlyAuthenticated`; `independentOldNewSourceKeyAndTlsPinEnrollmentVerified`; `independentlyRetrievedPriorWitnessHighWatermarkVerified`; `durableOffsiteReplayForkQuarantineStateVerified`; `incidentClearanceAndIndependentRecoveryApprovalVerified`; `currentHeadEnforcedGithubRulesetsCodeownersReviewVerified`; `genuineProviderCcaRcaiEmudhraMcaAndStagingVerified`; `independentOidcSlsaWormDrAttestationVerified`; and `productionReleaseAuthorized`.

Actual trust requires independent Security/Business corporate mandates, nonauthor latest-head GitHub reviews, enforceable `main` CODEOWNERS/rulesets without admin/app bypass, authorized operator public keys/rotations and certificate-policy revocation authority, approved eMudhra/RCAI/CCA sandbox chain and signed CRL/OCSP, MCA/GST legal signatories, real source owner and TLS/SPKI enrollment, independently retrieved immutable/offsite prior high-watermarks and fork gossip, persistent incident quarantine, witnessed S3 Object Lock COMPLIANCE delete-denial and DR restore/RTO-RPO, signed OIDC/SLSA CI provenance, and separate Security/Legal/Ops/Owner staging acceptance.

On 20 November 2026, actual GitHub official API still reported zero PR approvals, zero installed rulesets, and 404 for `main` CODEOWNERS. No true officer enrollment, provider approval, offsite prior witness retrieval, or legal external signature has been supplied; no live endpoint, customer/supplier/provider action, quote, PO/GRN, stock/tax/finance or release operation is allowed.

## Implementation/tests/custody

- `scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs` — bounded operator-only, pure detached-signature/roster-digest/high-watermark/quarantine assessor with one offline CLI.
- `tests/phase1cy-operator-pin-lifecycle-quarantine.test.mjs` — **22 adversarial Node test groups**, using strictly ephemeral test-only Ed25519 signing keys. Positive fixtures include unchanged source roster, fully counter-signed changed source signer+host+TLS pin, and a TLS-only key-retaining transition. Negative fixtures exercise missing role, forged signature, stale/changed SHA, old-key revocation, source-key cross-role collision, prior witness fork, time drift, incident, attempt to auto-unquarantine, and report secret minimization.
- Both paths are in exact source build/provenance Phase 1BV and vendor-intake Phase 1BW inventories. `.github/workflows/ci.yml`, existing CI job/action pins/permissions, `main`, PR approval/merge status, provider credentials and production service writes remain untouched.
- Before marking internal work complete, verify exact final code commit's **both push and PR hosted workflows**, Node/TypeScript/security tests, frozen dependency audit, disposable MySQL/Chromium role/MFA smoke, and official GitHub Actions Jobs vs Checks same-ID/suite/source reconciliation. Document any failed CI runs, fixes and true final verification in PR #1 and Issue #2.

**Always production HARD HOLD.**
