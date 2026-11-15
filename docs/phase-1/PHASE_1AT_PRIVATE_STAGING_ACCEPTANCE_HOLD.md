# Phase 1AT — Offline staging acceptance JSON boundary and independent release-gate HOLD

**Date:** 2026-11-15. **Branch:** `chore/phase0-foundation-20261106`. **Production:** HARD HOLD.

This change addresses the *input files* consumed by the operator-only staging acceptance CLI. Phase 1AS hardened the underlying twelve staging evidence artifacts; before Phase 1AT, `scripts/review-staging-acceptance.ts` still called `readFileSync` directly on two operator-supplied JSON paths, accepted inputs without checking ownership, directory isolation, permissions or symlinks, and could emit an exception message containing a private path. A synthetically complete submission could also yield a zero exit code, a misleading signal for automation. This is an internal security-hardening finding, not evidence of a real breach or staging acceptance.

## Implemented controls

1. New `scripts/lib/privateStagingReviewInputs.ts` anchors the checkout boundary to its installed module's canonical location, **never `process.cwd()`**. It rejects input files in the Git checkout regardless of invocation directory and enforces absolute canonical paths.
2. Both review-input JSON files must be **different files in one owner-private directory outside the source checkout**, with 0700-like directory permissions and 0600-like files. Final/intermediate symlinks, hardlinks, nonregular files, foreign owners and world/group-accessible files are rejected. The separately supplied twelve-file evidence root is independently checked by Phase 1AS.
3. Acceptance input max **128 KiB**; manifest input max **32 KiB**. Read through a single `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` descriptor with lstat/fstat device/inode consistency, size+one bounded read, metadata recheck, strict UTF-8 decoding, and JSON parsing. Unsafe or unsupported file access fails closed.
4. Reject unknown or missing top-level/nested JSON fields including undeclared provider token and production-authorization flags. Validate expected probe/recovery and 12-kind evidence schema. Raw private JSON, individual SHA values, file paths, source contents or signer IDs are not echoed.
5. `scripts/review-staging-acceptance.ts` no longer loads `.env` implicitly. Private mode requires **both** `STAGING_ACCEPTANCE_REVIEW=YES` and `STAGING_PRIVATE_JSON_REVIEW_APPROVED=YES` on an authorized nonproduction operator machine; `CI=true`, `GITHUB_ACTIONS=true` and `NODE_ENV=production` deny private input reads.
6. New `--ci-hold` mode reads **no private files or secrets**, always reports `productionReleaseAuthorized:false` and `releaseDecision:HOLD`, and exits 0 only for the read-only no-input preflight. **Any private-mode review exits 2, even if all synthetic fields/hashes match**, because local completeness is not an independent production approval. Errors also exit 2 with generic redacted diagnostics.
7. `tests/phase1at-private-staging-inputs.test.ts` supplies disposable synthetic, never external, files and asserts positive integrity **without** release promotion, bad mode/CI/prod denial, path and symlink exclusion, permissions, hardlink, malformed and oversized JSON, unexpected token/approval fields and output redaction. `bun run test` and `bun run test:staging-security` both run this suite; CI also executes the `--ci-hold` gate.

## Operator-only command (not run against real evidence)

Store all inputs in an approved private review environment, **outside Git and CI**, and create a single owner-private directory containing the two JSON packets:

```sh
STAGING_ACCEPTANCE_REVIEW=YES STAGING_PRIVATE_JSON_REVIEW_APPROVED=YES \
  bun run staging:acceptance-review \
  /absolute/owner-private/acceptance.json \
  /absolute/owner-private/evidence-manifest.json \
  /absolute/approved-evidence-root
```

The operator must **expect exit status 2 / HOLD even if `submittedEvidenceComplete=true`**. Local hash matches are not genuine signatures or witnessed facts. Do not wire this command to a release-enabling pipeline, and never transmit credentials, KYC, signing keys, real supplier/customer records or executed agreements in chat or Git. Secret material belongs exclusively in an approved secrets manager.

The bounded, zero-input CI check is:

```sh
bun run staging:acceptance-review --ci-hold
```

## Remaining independent acceptance gates

| Gate | Independent authority | Verified status |
|---|---|---|
| Executed and provider-confirmed sandbox-specific agreement | LEGAL + independently authenticated provider | NOT PROVIDED |
| Vault provisioned least-privilege sandbox workload credentials | SECURITY + INFRA | NOT PROVISIONED |
| RCAI/CCA anchored policy-constrained CA chain and signer purpose | Independent PKI reviewer | NOT AUTHENTICATED |
| Issuer-bound, signed, fresh genuine live CRL/OCSP and full negative cases | Independent PKI reviewer | NOT VERIFIED |
| Primary-source MCA company and legal signatory delegation | LEGAL + OPS | NOT VERIFIED |
| Actual supplier/warehouse acknowledgments, physical GRN and stock authority | OPS + FINANCE | DISABLED |
| Staging firewall/TLS/MySQL, MFA, encrypted restore, measured RTO/RPO | SECURITY + INFRA + independently witnessing OPS | NOT WITNESSED |
| Source/build provenance reconciliation and production release approval | OWNER + LEGAL + SECURITY + OPS | RELEASE HOLD |

**Safety boundaries:** Internal CI tests use synthetic files only; no live provider call, credential provisioning, supplier contact, payments, stock, production migration, backup restore or deploy. The existing 27 additive migration checksums, 32-file held release manifest, Issue #2 OPEN, Draft PR #1 unmerged and `main` unchanged remain intentional. A malicious privileged operator, filesystem administrator or host kernel is outside the guarantees of this reader.
