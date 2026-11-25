# Phase 1AU — Provider trust-policy drift, evidence review expiry and revocation rollback: HARD HOLD

**Date:** 2026-11-16. **Development branch:** `chore/phase0-foundation-20261106`. **Production:** HOLD. **Evidence quality:** SHA-only local administrative claims, NEVER externally authenticated provider authority.

## Public sources and scope separation

- The Indian Controller of Certifying Authorities (CCA) [eMudhra disclosure record](https://cca.gov.in/e_mudhra.html), checked 2026-11-16, lists **current CPS v4.2.1**. Phase 1AO's old `CCA_CURRENT_CPS_REFERENCE` literal had named a historical v4.2.0 PDF as *current*. Phase 1AU changes that reference to the official CCA disclosure landing page; the software DOES NOT automatically download/accept a CPS, prove the signature of any policy PDF or verify a policy OID. A responsible reviewer must authenticate the current policy out of band before ever selecting service-specific certificate paths.
- [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) records an ongoing global eMudhra WebPKI TLS/code-signing incident. Phase 1AQ's 24 public certificate fingerprints are a **deny-only, non-exhaustive** inventory. This incident must not be conflated with an independently authenticated India CCA DSC root. The Mozilla report's **November 16, 2026 G1 issuance stop was a planned deadline**, not automatically verified as completed by this project.
- The CCA disclosure, a Mozilla incident discussion, CA listing, a SHA digest, and a synthetic reviewer decision do **NOT** provide this application with provider sandbox service rights, RCAI key authentication, legal MCA signer delegation or an approved transaction.

## Implemented security controls

1. `scripts/lib/phase1AuPolicyDrift.mjs` compares **two untrusted** (previous/current) SHA-only inventory snapshots with exact fields, a strictly increasing sequence number, canonical UTC timestamps, matching fixed evaluation provider/scope, 10 artifact hashes, 6 distinct reviewer hashes, and one review/expiry/revocation window for each of those 16 categories. It reuses the Phase 1AP canonical 16-digest validator; unknown keys, fake `verified` flags, secrets and unsupported production-service scopes fail closed.
2. Track drift between prior and current declared CPS versions, the Phase 1AQ incident fingerprint inventory digest and all 16 claimed evidence/reviewer SHA fingerprints. Unknown versions, changed candidate anchors, revised public source references, or incident-list revision require independent manual review. **Even a perfect match is NOT evidence authenticity.**
3. Strict **administrative review freshness caps**, not certificate validity: OCSP snapshot max **1 hour**, CRL snapshot max **24 hours**; claimed RCAI root/issuer chain/CPS policy max **7 days**; MCA corporate record and delegation max **30 days**; remaining evidence/reviewer items max **7 days**. Every record includes an explicit capture time and refresh-due time. The checker detects expiration, due-soon (24h), future timestamps and impossible/overlong review windows. These internal caps do not replace the certificate's actual `thisUpdate`, `nextUpdate`, legal expiry, contractual term or signed CRL/OCSP policy.
4. Record untrusted revocation observations as `NOT_CHECKED`, `UNKNOWN`, `CLAIMED_NOT_REVOKED` or `REVOKED`. The last state requires a revocation timestamp. Revoked-to-unrevoked rollback, changed revocation timestamps, declining sequence or earlier review capture time are explicitly flagged; unknown/not-checked status is always a release blocker. A `CLAIMED_NOT_REVOKED` label is **not** a verified negative revocation response. The code NEVER verifies an actual CRL/OCSP signature and NEVER grants positive trust.
5. New private offline two-snapshot interface `scripts/phase1au-policy-drift-preflight.mjs` requires `PHASE_1AU_OFFLINE_REVIEW_APPROVED=YES` on an approved nonproduction operator host. Two distinct canonical absolute JSON files must be stored in the **same private directory outside Git** (0700-like directory / 0600-like owner files; no symlinks/hardlinks). Open each through an owner-checked, no-follow, nonblocking file descriptor, size bounded to **128 KiB** with strict UTF-8 parsing. CI and production cannot read private snapshots. Output returns only aggregate counters, fixed category/gate reasons, and `HOLD`—no input paths, signatures, individual hashes, private identifiers or secrets.
6. Offline comparison always **exits status 2**, including when no drift or expiry is found, so an automation cannot treat matching synthetic claims as release success. The zero-input/no-network `--ci-hold` mode exits 0 with an explicit HOLD record and no private I/O. GitHub CI executes that mode; `bun run test` executes `tests/phase1au-policy-drift.test.mjs` including negative, rollover and cross-phase Release HOLD checks.

## Operator-only synthetic inspection example (NOT an authorized external integration)

```sh
# On a separately approved private nonproduction workstation ONLY:
PHASE_1AU_OFFLINE_REVIEW_APPROVED=YES \
  node scripts/phase1au-policy-drift-preflight.mjs \
  --offline-pair /absolute/private/previous-claims.json \
                 /absolute/private/current-claims.json
# Exit 2 / HOLD regardless of the administrative diff result.

# Safe in CI, no private data or external access:
node scripts/phase1au-policy-drift-preflight.mjs --ci-hold
```

Snapshot schema v1 requires `schemaVersion`, `providerCode=EMUDHRA_CCA_EVALUATION_ONLY`, `requestedScope=SUPPLIER_WAREHOUSE_EVIDENCE_SANDBOX`, `sequence`, `recordedAt`, `policy`, `artifactDigests`, `reviewDigests`, `windows`; the exact field lists are exported by the library. `policy` consists only of `ccaCpsVersion`, `ccaDisclosureUrl` (the exact CCA public landing URL), `trustDomain=INDIA_CCA_DSC_EVALUATION_ONLY` and `incidentDenylistSha256`. `windows` must contain all 16 evidence kinds with `capturedAt`, `refreshBy`, `revokedAt` (nullable), and `revocationState`.

**Do not place real agreements, certificates with sensitive content, provider tokens, keys, customer KYC, MCA personal records or legal documents in these JSON files or this chat.** Credential provisioning belongs to an authorized secrets manager. This check is local consistency analysis of anonymous SHAs and claimed timestamps ONLY.

## Regression and release governance

- Unit tests exercise no-baseline HOLD; synthetic matching snapshots still HOLD; CPS v4.2.0 vs public v4.2.1 drift; changes to incident policy digest/root SHA; OCSP expiry and CRL revoked states; unknown/unchecked revocation; sequence/review/known-revocation rollback; invalid UTC/time windows; unknown credential/authority fields; malicious input paths; private-file symlink/hardlink/permissions; CI and production denial; no sensitive output.
- Existing Phase 1AP and 1AQ zero-input gates are re-checked against `sandboxServiceAuthorized:false`, `productionReleaseAuthorized:false` and `stockPostingEnabled:false`.
- **No** migrations, provider calls, external CA authentication, contract acceptance, credential writes, supplier contact, GRN issuance, stock/finance posting, deployment or PR merge. The existing **27 registered SQL migrations** and **32-file held release inventory** remain unchanged. CI does not claim live staging approval.
- Genuine external completion still requires executed and provider-confirmed sandbox agreement/service grant (LEGAL+SECURITY), vault credentials, independently authenticated RCAI/CCA PKIX and correct CP/CPS OIDs, authenticated signed/issuer-bound fresh CRL/OCSP (including outage/unknown/revoked handling), primary-source MCA and legal signatory verification, witnessed actual staging TLS/DB isolation and restore/recovery, and separate OPS/OWNER/LEGAL/SECURITY release sign-offs.

**Decision: HARD HOLD.** Keep Issue #2 OPEN, PR #1 DRAFT/unmerged and `main` unchanged. A match of two synthetic inventories can never close external trust or production acceptance gates.
