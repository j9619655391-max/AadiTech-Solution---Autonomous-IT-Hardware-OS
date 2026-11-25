# Phase 1CD — Independent signer enrollment, WORM/DR witness, anti-replay/rollback prereqs HARD HOLD

**Date:** 18 November 2026 (IST). **Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`. **Development branch:** `chore/phase0-foundation-20261106`, PR #1 remains Draft/open/unmerged, Issue #2 open, `main` unchanged.

## Scope and trust boundary

Phase 1CC already binds a SHA-256 selected-source inventory, pinned GitHub Actions references and exact PR test-merge Git parents into a portable **unsigned** local receipt. Phase 1CD validates the mathematical *shape* and authorization preconditions for possible **future** independent signing and WORM/DR witnesses while supplying **zero real external authority** in the hosted CI. **None of these checks independently proves the supplied keys belong to an approved authority, that a GitHub OIDC JWT was issued, or that a WORM service/store or DR restore exists.**

## Implemented

The deny-only `scripts/phase1cd-external-custody-preflight.mjs --ci-hold` uses the already-produced Phase 1CC envelope in the **existing** `build-input-provenance` CI job, after the BV/BZ/CC steps. It checks the report digest, source run/job/ref/checkout correlation, regular non-symlink bounded local file, HOLD flags, and no external claims. It emits `phase1cd-zero-input-external-custody-hold.json` alongside existing three **unsigned** custody files; it has no network, credentials, new CI privileges or production side effects.

Its exported `assessIndependentCustody` and `signingPayload` are a self-contained, deterministic preflight for **caller-supplied** candidate packets only. It constrains:

1. **CI_ATTESTOR**: distinct Ed25519 signing enrollment (SPKI SHA-256, identity and role, enrollment time, non-revoked status in caller-supplied keyring), domain-separated canonical statement, finite 15-minute validity, exact GitHub source-head and test-merge checkout hashes, Phase 1CC envelope SHA-256, run ID/job ID/attempt, issued-at/expiry, nonzero external challenge, workflow path, expected GitHub OIDC issuer and source-bound subject. **OIDC string fields are not JWT signature verification.**
2. **WORM_AUDITOR**: a different key/organization, signed claim bound to the full digest of the prior CI attestor statement, archive bucket ARN and object key, nonempty immutable object version ID, claimed S3 **COMPLIANCE** Object Lock and retention at least 30 days into the future, claimed overwrite/delete-denied outcome, envelope digest and primary region. **The signed claim does not authenticate AWS API records, the Object Lock backend or real denied-delete telemetry.**
3. **DR_AUDITOR**: a third distinct key/organization, signed claim bound to the exact WORM statement digest, the same version ID and envelope content digest and claimed restore time/independent region. **DR claims must be separately witnessed through real authenticated restore retrieval.**
4. **Anti-replay/anti-rollback**: each role's signed claim sequence must be exactly `externally anchored sequence + 1`; previous claim digest must match the supplied high-watermark. Duplicate role packets, stale/expired/future statements, skipped/repeated sequence, older checkpoints, signer reuse, source substitution and cross-claim forks are rejected *relative to the supplied checkpoint*. Actual protection from rollback/equivocation across different parties **requires** a separately authenticated append-only external checkpoint and external trusted clock/state; a forged applicant-controlled high-watermark can always be rewritten.

An apparently valid signature against a **caller-supplied** public key can only set `candidateSignaturesAndClaimChainsLocallyConsistent=true`. It **always leaves false** `outOfBandAuthorityEnrollmentAuthenticated`, `trustedRevocationFreshnessIndependentlyVerified`, `monotonicCheckpointExternallyWitnessed`, `antiEquivocationExternalJournalVerified`, `githubOidcJwtIssuerSignatureAndSubjectVerified`, `ciWorkloadBinaryIndependentlyAttested`, `realS3ObjectLockVersionRetentionIndependentlyVerified`, `realDeniedDeletionAndLegalHoldIndependentlyWitnessed`, `offsiteDrRestorationIndependentlyVerified`, `independentSecurityAndBusinessApprovalsVerified` and `productionReleaseAuthorized`.

`tests/phase1cd-external-custody-preflight.test.mjs` contains 13 adversarial groups: genuinely calculated **synthetic** Ed25519 signatures against temporary test-only keys (never enrolled as live authority), zero-input/zero-nonce, duplicate witnesses, replay/gap/rollback and changed ancestor, forged OIDC subject/repo/source, swapped SPKI/signature, bad role and revoked/expired key, fake WORM retention/mode/version/digests, forged delete denial, mismatched attestor→WORM→DR links, bad DR region/restore, tampered unsigned CI envelope, self-proclaimed GO, out-of-range timestamps and malformed packets.

Phase 1BV and Phase 1BW governance source inventories now cover both new code and tests. The existing eight-job GitHub Actions design, pinned action SHAs, global `contents: read`, and strictly read-only scoped job tokens are preserved.

## Actual external work required (not accomplished)

| Acceptance item | What genuine authorized evidence must be collected later | Current state |
| --- | --- | --- |
| CI signer enrollment | Out-of-band organization identity, approved issuer roots/roles, key provenance and validity/revocation evidence independent of source repo | **NOT VERIFIED** |
| CI workload provenance | Signed verified OIDC identity and subject bound to actual GitHub workflow/job/run/source, artifact or canonical subject digest, revalidated run attempt | **NOT VERIFIED** |
| Replay/anti-equivocation | Independently witnessed monotonic high-watermark and predecessor checkpoint in separate append-only store, concurrent race/fork detection | **NOT VERIFIED** |
| WORM retention | External storage admin-signed S3 Object Lock compliance/version/retention/legal-hold and independently verified denied overwrite/delete audit | **NOT VERIFIED** |
| Offsite DR | Independently authenticated retrieval of exact WORM object version/digest, isolated restore, audit witness and recovery-scope acceptance | **NOT VERIFIED** |
| Repo reviewers | Effective enforced GitHub `main` branch rulesets/CODEOWNERS, two non-author latest-HEAD Security/business approvals | **NOT VERIFIED** |
| Dependency vulnerability | Genuine vendor-published patch for `picomatch@4.0.7` `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366`, fresh lockfile and full strict zero Critical/High/unknown audit | **BLOCKED (HIGH)** |
| External business authority | Genuine eMudhra/CCA/RCAI contract, live signed certificate revocation, MCA/GST signatory records, real staging and OWNER/SECURITY/LEGAL/OPS approvals | **NOT VERIFIED** |

**No fake timestamps, signatures, test keys, public JSON digest or report from this branch should ever be promoted into external approval.** For the actual external flow, an independently trusted Security/Operations administrator must enroll/verify authorities and source-of-truth checkpoints *outside* this repo and separately control storage; no external secret is requested in chat or committed to GitHub.

## Hard release decision

`productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Preserve Draft/unmerged PR #1, Issue #2 open and `main` unchanged. No real quotes, supplier PO, GRN/stock, finance/tax transactions, customer notifications, provider API operations or production deployment.
