# Phase 1CC — Source-bound unsigned CI artifact custody and independent retention prerequisites (HARD HOLD)

**Date:** 18 November 2026 (IST).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`.  
**Engineering branch:** `chore/phase0-foundation-20261106`. `main` must remain untouched; PR #1 Draft/open/unmerged and Issue #2 OPEN.

## Why this increment exists

Phase 1BV produces an unsigned SHA-256 inventory of selected source and build inputs. Phase 1BZ/1CA produces a separate unsigned action-SHA and CI-job-scope report. Phase 1BY verifies the *local Git object* parents of the PR test-merge checkout. Without a cross-report receipt, a copied or substituted report can be mistaken for evidence from the current checkout. Phase 1CC cross-correlates these records but **does not** create external signed provenance, approve branch rules, or retain anything in independently controlled WORM storage.

## Implemented control

`scripts/phase1cc-ci-evidence-envelope.mjs --ci-hold` runs in the existing **build-input-provenance** job after Phase 1BV and Phase 1BZ; no new GitHub job, runner permission, event trigger, action tag or deployment path has been added.

The read-only verifier:
1. Reads the exact local phase1bv and phase1bz reports with size and non-symlink restrictions, and recalculates the selected build-input bundle and per-file SHA-256 digests by reading *each* enumerated checked-out source file. The Phase 1CC verifier and its tests are included in the inventory.
2. Rejects missing, swapped, tampered or self-declared signed reports; verifies the Phase 1CA eight-job and Phase 1BZ exact immutable action-pin local result; checks no release, patch, external WORM, publisher or reviewer acceptance flags are promoted.
3. Uses fixed shell-free `git rev-parse HEAD` and `git cat-file -p HEAD` with command timeouts and bounded buffers. For the PR event, validates source and base identity, expected PR author and number, actual checkout SHA and *exact two ordered Git parents* via Phase 1BY. The PR webhook merge_commit_sha may legitimately lag the checkout; stale metadata does not override actual Git parent proof.
4. For a development-branch push, requires exact branch ref, event repository and `event.after` equality with the actual Git checkout, no deleted/forced event, and a valid Git parent object. No `main` branch, workflow_dispatch, release trigger or alternative repository is authorized.
5. Emits `phase1cc-unsigned-source-receipt-hold.json` containing the observed checkout, base/source commit SHA, Git tree and parent SHA list, selected individual file hashes, report-byte digests, ordered immutable action pins, selected source bundle digest, anomalies and deterministic domain-separated SHA-256 envelope digest. The JSON and checksum can be recomputed externally by a reviewer, but are **not a signature** and are mutable alongside the code.
6. Exits with failure when source/receipt correlation fails. Never writes to GitHub, copies secrets, creates signatures or calls a storage provider. The standard artifact uploader includes this report alongside the BV and BZ reports, all labeled **UNSIGNED** and **HOLD**.

The standalone `verifyUnsignedEnvelopeDigest` checks deterministic checksum consistency and explicit unsigned/HOLD flags; **it cannot establish who authored an envelope**. A SHA-256 digest computed by an untrusted party can be recomputed by that same party.

## Adversarial regression coverage

`tests/phase1cc-ci-evidence-envelope.test.mjs` includes 11 groups of adversarial cases: correct PR source parents and development push, stale event merge SHA, swapped or substituted parent, wrong branch/ref/checkout, forced/deleted push, altered source bytes/omitted files, changed action SHA/job permissions, invented independent signature or WORM claim, invalid/missing report bytes, malformed Git object and altered envelope digest. Tests use **synthetic local fixtures**, never real reviewer private keys, external storage or production provider credentials.

The test suites and hosted CI status must be validated on the **final pushed HEAD** before an execution-success claim. Even when all Phase 1CC tests pass, the mandatory global zero Critical/High dependency security gate remains separate and non-waivable.

## Independent verification required before any future release

A real independent CI provenance acceptance, if later authorized by Security and Operations, must involve all of these genuine external steps:

- Obtain the GitHub Actions run and artifact through an independently authenticated channel; verify the source PR head/base/checkout Git object, workflow identity, job ID, artifact attestation subject and binary hashes independently.
- An **external, identity-bound signing workload** must produce verifiable DSSE/in-toto or comparable provenance, with out-of-band independently enrolled signer identity and trust roots. A repository-supplied Ed25519 test key or self-asserted OIDC subject never qualifies.
- A separate WORM administrator must provide authenticated immutable object version, retention period/mode, legal hold if required, denied overwrite/delete evidence, witnessed audit log and independently verified restore/retrieval from isolated DR. GitHub Actions artifact upload and digest alone do not qualify.
- Independently authenticated named Security and business reviewers must approve the exact last source head, with enforced server-side `main` rulesets/CODEOWNERS/no bypass, approved staging, and Owner/Legal/Operations security decisions.
- The global dependency audit must pass **zero Critical/High/unknown** using genuine vendor-published patched dependencies. Current `picomatch@4.0.7` High `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366` cannot be waived by a production-only dependency tree or by locally consistent signatures.

These preconditions are **not met**. No external WORM or independent signer was contacted; no reviewer key, storage tenant, administrator privilege, genuine eMudhra agreement or MCA signatory authority is asserted.

## Release gate

**`productionReleaseAuthorized=false` · `productionReleaseBlocked=true` · `releaseDecision=HOLD`.** Keep PR #1 Draft/unmerged and Issue #2 open, `main` unchanged. No live customer quotes, supplier PO/GRN, inventory/finance/tax postings, messaging, trusted provider API requests or production deployment.
