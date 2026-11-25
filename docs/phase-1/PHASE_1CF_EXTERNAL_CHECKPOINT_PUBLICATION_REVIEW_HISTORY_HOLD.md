# Phase 1CF — Independent checkpoint publication/retrieval and reviewer-history prerequisites (HARD HOLD)

**Date:** 18 November 2026 (IST)  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Engineering branch:** `chore/phase0-foundation-20261106`; `main` unchanged; PR #1 Draft/open/unmerged; Issue #2 OPEN.

## Motivation and security boundary

Phase 1CE evaluates one pair of externally **claimed** signed checkpoint observations, candidate RFC6962 Merkle consistency, and candidate archive content bytes. Phase 1CF adds a bounded *history* of two epochs with predecessor hash chains, signed independently claimed publication/retrieval channels, and Security/Business signed review claims over the **exact latest source head and final epoch**.

No external source is contacted; all supplied keys, metadata, historical roots, nonces, publication receipts and review logins are **applicant-controlled candidate values**. A cryptographically correct candidate therefore **must not** establish authentic external authority, actual GitHub approvals, storage retrieval, WORM retention or release signoff.

## Implemented

`scripts/phase1cf-checkpoint-publication-review-preflight.mjs` provides `assessCheckpointPublicationHistory` and deterministic domain-separated `historySigningBytes`. It checks:

1. **Immutable-head prerequisites:** Exact Phase 1CC local envelope checksum, checked-out PR test-merge source/head and run identifiers; strict `HOLD` decision and global dependency audit not marked green. It requires a distinct supplied initial high-watermark with prior Merkle root, tree size, epoch number and predecessor digest.
2. **Two sequential epochs:** Each signed checkpoint must bind the same latest source SHA, checkout, run/attempt, external challenge, log name, expected archive object version and envelope digest. Epoch N must equal N−1+1, and its previous digest and previous Merkle root/size must equal those of the prior epoch, with increasing observation time. This catches supplied rollback/replay/forks relative to the supplied initial anchor.
3. **RFC6962 actual Merkle arithmetic:** The previously reviewed Phase 1BB append-only consistency implementation checks bounded strict-hex proof paths for both epochs. Changing a new root, predecessor root, tree size, or proof cannot pass.
4. **Two independently claimed publication channels:** Each epoch requires separate Ed25519 signatures on a domain-separated digest with distinct `CHECKPOINT_WITNESS_A` and `CHECKPOINT_WITNESS_B` roles, organization, login, key and claimed channel (`AUDITOR_CHANNEL_A` / `AUDITOR_CHANNEL_B`). Each signed observation binds the exact checkpoint digest, archive version/content SHA-256 and observation time. Strict SPKI hashes, enrollment times, expiration, claimed revocation and signer separation are enforced. **A string saying the retrieval happened through an independent channel is not verification of TLS, endpoint, provider response or independent organizational control.**
5. **Security + Business latest-source reviews:** Exact latest-epoch digest and source/checkout/run/attempt/challenge must be signed separately by `SECURITY_REVIEWER` and `BUSINESS_OWNER` candidate Ed25519 keyholders. Reused reviewer identity, organization or key, the PR author self-review, stale expiry, roles swapped and extra `GO` fields fail the candidate verifier. These signatures are **not** real GitHub review submissions or verified authenticated reviewers.
6. **Fail-closed, zero-input CI:** `node scripts/phase1cf-checkpoint-publication-review-preflight.mjs --ci-hold` accepts no externally supplied keys, arbitrary paths, endpoints or claims. It reads the existing local Phase 1CC/1CD/1CE HOLD artifacts with strict file size and non-symlink restrictions, checks the actual GitHub run's checkout/repository/job identity, and writes `phase1cf-zero-input-review-history-hold.json` with all external trust flags **false**. The existing `build-input-provenance` job uploads this sixth **UNSIGNED** custody report. No new job, action version/tag, token scope or permission was added.

`tests/phase1cf-checkpoint-publication-review-preflight.test.mjs` contains 14 adversarial test groups, including a valid **synthetic** two-epoch, dual-witness, dual-reviewer Ed25519 signature chain and actual two-step RFC6962 growth proof. Rollback, skipped epoch, fork, tampered immutable anchor, substituted Merkle path, wrong source and archive digest, spoofed publication channel, revoked/expired signer, swapped signature, common signatory administration, self-review, wrong latest-head reviewer, stale review and injected `GO` are denied in controlled fixtures.

Phase 1BV build-input and Phase 1BW reviewer governance selected-source inventories hash both the new implementation and tests.

## Independent evidence needed for an actual approval

| Gate | Required genuine independently authenticated evidence | Current status |
| --- | --- | --- |
| External publisher | Signed log-head publication from a legal issuer, independently pinned key lineage/revocation, authenticated TLS endpoint and publisher logs | **NOT VERIFIED** |
| Cross-run history | Separately managed persistent immutable checkpoint store with monotonic compare-and-set / anti-rollback and fork gossip across independent observers | **NOT VERIFIED** |
| Remote retrieval | Service-authenticated GetObjectVersion response, exact content bytes, Object Lock compliance retention and failed overwrite/delete audit in separate admin custody | **NOT VERIFIED** |
| Security/business reviews | Actual GitHub API identities, latest HEAD **two distinct non-author** approved reviews, verified membership/roles and enforced `main` CODEOWNERS/ruleset/no admin bypass | **NOT VERIFIED** |
| CI provenance | Independently verified GitHub OIDC JWT issuer, workload subject, signed artifact provenance and attestations with approved outside trust root | **NOT VERIFIED** |
| External business authority | Approved eMudhra/CCA/RCAI credentials and signed live revocation, verified MCA/GST legal identities and approved staging/Security/Legal/Ops/Owner signoffs | **NOT VERIFIED** |
| Dependency gate | Real supported vendor-patched Picomatch, frozen production + full build dependency audit with **zero Critical/High/unknown** findings | **BLOCKED** |

As of this phase, `picomatch@4.0.7` remains affected by High `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366`. Do not invent patched `4.0.8`, change overrides, downgrade required checks, or accept isolated production-only dependency scope as global audit success.

**Release remains HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Do not merge `main`, make PR #1 ready, close Issue #2, deploy, post inventory/finance/tax, create real external quotes/POs, or contact live trust providers.
