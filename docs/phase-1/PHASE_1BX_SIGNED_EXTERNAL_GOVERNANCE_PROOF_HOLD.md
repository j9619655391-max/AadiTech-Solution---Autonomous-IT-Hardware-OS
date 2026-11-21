# Phase 1BX — Exact-head Ed25519 external governance proof prerequisites and HARD HOLD

**Date:** 18 November 2026 (IST)  
**Correct GitHub repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Default branch:** `main` must remain unchanged, Draft PR #1 open/unmerged, Issue #2 open.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision='HOLD'`.

## Actual governance state and limits

The connected GitHub PR-review tool shows **zero submitted reviews** for PR #1 on 18 November. It does not provide a branch-protection/ruleset read action; absence of a checkable ruleset is **unverified**, not evidence that protection is definitely enabled or disabled. No named, separately authenticated reviewer key enrollment, independently retained GitHub admin observation, independent CI workload signed provenance, external retained signed WORM auditor receipt, or Security/Legal/Owner/Operations acceptance exists in the available verified project evidence.

The project must not turn a code-file checklist, invented CODEOWNERS or an ordinary GitHub PR comment into real human approval. A caller may supply a keyring that passes public-key signature validation, but that alone does **NOT** establish its authoritative origin, reviewer employment/identity, branch protection, secure OIDC enrollment, real WORM storage, monotonic audit history or signer's independence.

## Implemented bounded cryptographic controls

`scripts/phase1bx-external-governance-proof.mjs` provides a **pure detached-Ed25519 verifier** and separately a **zero-input CI preflight**. Its evidence format is intentionally closed to five different role-bound statements:

| Signed evidence type | Required distinct role | Claim to be independently verified outside this program |
|---|---|---|
| `branch-ruleset` | `REPOSITORY_ADMIN` | independently observed `main` ruleset, two-person quorum, CODEOWNER, no bypass/force/direct/delete, latest-push approval |
| `security-review` | `SECURITY_REVIEWER` | genuine independently authenticated Security review of exact development HEAD |
| `business-review` | `BUSINESS_OWNER` | genuine independently authenticated business owner acceptance of exact HEAD |
| `ci-provenance` | `CI_ATTESTOR` | externally enrolled CI subject/workload identity and precise build-input digest |
| `external-worm-receipt` | `WORM_AUDITOR` | independent retained WORM receipt, CI digest, monotonic sequence, witnessed retention |

Every signed statement must bind `schemaVersion=1`, correct repository, `main` base branch, PR #1, **exact development HEAD**, **exact base SHA**, **separate GitHub PR test-merge checkout SHA**, an out-of-band 256-bit challenge nonce, a SHA-256 evidence digest, the required role, signer key ID and login, ISO-8601 issue/expiry timestamps and explicit `productionReleaseAuthorized=false`. Signed serialization uses a domain-separated, recursively key-sorted canonical JSON representation, `aaditech/phase1bx/detached-ed25519-evidence/v1`. Signatures are strictly canonical 64-byte Ed25519 signatures; registered SPKI SHA-256 public key fingerprints, algorithms, roles and login must match. Duplicate signer IDs/logins, self-review by the PR author, missing/replayed proof types, unknown roles, cross-branch/HEAD/nonce substitutions, stale/oversized validity windows, wrong CI digest, invalid WORM monotonic index or a relaxed ruleset snapshot fail validation.

**The trust registry is not onboarded in this repository.** `authorities` and signed `evidence` are purely caller inputs, not self-enrolled live identities. Even when all five ephemeral test keys and signatures cryptographically match, `independentGithubRulesetVerified=false`, `externalKeyProvenanceAuthenticated=false`, `realGithubReviewSubmissionVerified=false`, `independentCIWorkloadIdentityVerified=false`, `externallyWitnessedWormReceiptVerified=false`, `productionReleaseAuthorized=false`, and `releaseDecision='HOLD'`. The verifier itself never issues a production GO.

`tests/phase1bx-external-governance-proof.test.mjs` uses only in-memory disposable Ed25519 keypairs (private keys **never committed**) to exercise **11 adversarial tests**, including tampered statements/signatures, fake fingerprints, replay and duplicates, 5-role distinct reviewer custody, PR/base/merge fork or challenge substitution, stale/expired timestamps, unauthorized WORM receipt/digest/sequence, wrong branch protection values, empty actual CI input, tampered self-authorized production claims, and canonical source consistency. These are synthetic cryptographic unit tests, **not evidence of five real signers**.

`.github/workflows/ci.yml` adds a separate **`independent-evidence-hold`** hosted read-only job, running only `node scripts/phase1bx-external-governance-proof.mjs --ci-hold`. It does not request secrets/real reviewer keys/Internet endpoints, generates a **zero-input, zero-valid-signature** truthful JSON artifact `phase1bx-zero-input-independent-hold-report.json` with non-release state and missing proof reasons. The existing Phase 1BS–1BW jobs, frozen production isolation and mandatory zero Critical/High dependency audit remain intact.

## Concrete manual/external onboarding sequence required before considering an actual signed evidence claim

1. Authorized GitHub repository admin and a separate auditor must independently inspect the **server-side** protection/ruleset through privileged read evidence, including direct/force/delete restrictions, required status checks, CODEOWNER approval, distinct non-author reviewers and latest-push stale-review invalidation. A local policy JSON is only desired configuration.
2. Approved independent Security reviewer, approved business-owner reviewer, CI identity issuer and external WORM auditor must enroll authentic, approved, separated Ed25519 keys and signed public-key fingerprints through an independently verified, revocable trust channel; **never commit private keys or paste them into chat**. No applicant-supplied keyring may self-certify its enrollment.
3. Independently captured immutable GitHub evidence must bind the exact PR author, source HEAD, `main` base SHA, PR merge-checkout SHA, status checks, review commit SHA, issued challenge nonce, reviewer role and review timestamp. A newly pushed commit invalidates earlier approvals/evidence and requires fresh validation.
4. Independent attestor must sign the precise source/build-input bundle digest and CI subject identity. A separate off-GitHub WORM auditor must independently sign the receipt, retention policy, monotonic publication index and independently replay/restore witness checks. Local GitHub-uploaded JSON is NOT external WORM or a real signature.
5. Apply genuine supported upstream fix for `picomatch` ReDoS [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf), CVE-2026-112366, affecting versions through `4.0.7`; identify a verified vendor release and independent security acceptance **before** updating `bun.lock`. Re-run adversarial extglob tests, full zero-Critical/High Bun audit, complete JS/TS security, real disposable MySQL, Chromium MFA, all provenance/reviewer hold jobs. Do not invent a `4.0.8` patch or treat the advisory's ambiguous/unreviewed metadata as proof of a fix. As of review, no authentic patched release has been independently verified.
6. Only separately authenticated RCAI/CCA/eMudhra provider credentials/trust, live signed CRL/OCSP, MCA/GST corporate/legal signatories, external WORM witness and DR plus actual OWNER/SECURITY/LEGAL/OPERATIONS approvals could inform a future release review. **None of this work changes the present HOLD decision.**

**Security caveat:** Verifying a signature against a caller-provided key proves only mathematical consistency with that supplied public key. It does **not** verify its legal authority, source-of-truth enrollment, independent signer, actual GitHub protected branch, live signing event or externally retained audit record. The checked-in code never claims otherwise.

**NO production release**: no quote issuance, supplier PO, GRN/stock, finance/tax posting, real provider API access, live customer actions or production deploy; `main` unchanged and PR remains Draft/unmerged.
