# Phase 1BA — Cross-bound independent witness, WORM and encrypted-DR acceptance (HOLD)

**Status:** Internal offline engineering / cryptographic claim consistency only. No external authority authenticated, no real cloud storage verified and no independent DR rehearsal approved. Production **HOLD**.

**Repo/branch:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` / `chore/phase0-foundation-20261106`. PR #1 stays Draft/unmerged; Issue #2 open; `main` untouched.

## Delivery

- `scripts/lib/phase1BaIndependentAcceptance.mjs`: a fail-closed policy composition that re-evaluates the *underlying* Phase 1AZ digest-only dossier and Phase 1AY Ed25519/Merkle witness observations and recovery signatures. It does **not** accept unsupported caller-supplied "verified" booleans.
- Bind the exact versioned Phase 1AZ packet SHA-256 to its log and checkpoint receipt, archive object digest, object version and retention policy digests. Reject packet substitution and incomplete cross-bound evidence.
- A canonical, domain-separated archive probe claim binds the same object/version/policy and claimed retention expiration to a time-bounded pair of `deleteAttempt=DENIED_CLAIMED` and `overwriteAttempt=DENIED_CLAIMED` statements. Two separately named, Ed25519-signed `STORAGE_AUDITOR` and `SECURITY_AUDITOR` roles are mandatory; distinct reviewer identity, key and claimed administrative authority are checked. A local signature **does not** prove a cloud Object Lock denial.
- Prevent one administrative authority or reviewer from being counted as both an independent witness and storage auditor. Retain Phase 1AY's independent claimed witness quorum and Merkle proof verification.
- Re-evaluate the underlying Phase 1AY signed recovery evidence and bind incident checkpoint, restored checkpoint, backup and restored manifest digests, revocation digest, start/finish times, measured RPO, target RTO/RPO, and archive object to Phase 1AZ. Require separately claimed SECURITY, OPERATIONS and OWNER roles and reject overlap with witness and storage auditor administrative authority.
- All assessments return `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`, `independentlyAuthenticatedWitnesses=false`, `immutableRetentionEnforced=false`, and `encryptedDRWitnessed=false` **even if synthetic signatures, hashes and claimed witness administrations are internally consistent**.
- `scripts/phase1ba-independent-acceptance-preflight.mjs` accepts only `--ci-hold`, never input paths, keys, accounts, private documents, network endpoints, provider credentials or release switches.
- `tests/phase1ba-independent-acceptance.test.mjs` exercises a consistent synthetic fixture and hostile mutations: fingerprint/packet substitution, missing witness quorum, Merkle tamper, dual-reviewer signature forgery, administrative-authority collisions, archive version mismatch, DR signatory/snapshot mismatch, RTO overrun, future probe and illegal GO fields.
- `.github/workflows/ci.yml` gates the new zero-input HARD HOLD before baseline tests; the ordinary `bun run test` suite includes the adversarial JS tests.

## Trust boundary and release criteria

The assessor only checks *self-contained inputs and claimed signatures*. Actual external authority would require a signed provider contract and independently verified eMudhra/CCA/RCAI certificate hierarchy and revocation material; MCA company and signatory evidence; authenticated witness operator enrollment and out-of-band key pins; published transparency inclusion **and append-only consistency** proofs; independently operated WORM/Object Lock with deletion denial, retention and legal-hold enforcement evidence; and real encrypted restore to approved isolated staging with witnessed RTO/RPO, revocation recheck, and owner/security/operations signoffs.

No such independent external approval or runtime credential is available to this phase. Do not treat CI fixtures, public reference pages, local database records or claimed "DENIED_CLAIMED" storage responses as real external evidence. No provider network access, WORM bucket creation, staging restore, production deployment, stock/finance posting, supplier dispatch or PR merge is authorized.

**Engineering acceptance:** latest development SHA plus successful GitHub Actions baseline/MySQL checks.
**External acceptance:** blocked until authentic authority and independent evidence are onboarded through an approved secure process.
**Production:** HOLD regardless of internal green CI; Issue #2 remains open.
