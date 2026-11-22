# Phase 1EP — OWNER-scoped proof, key possession/rotation and external-trust reviews: HARD HOLD

**23 Nov 2026 IST.** Canonical repo `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` on development branch `chore/phase0-foundation-20261106`; PR #1 Draft, Issue #2 OPEN, main unchanged. No actual external identity, license, legal signatory mandate or release authorization.

## Actual security issue

Three further server REVIEWER route families returned all non-self records: offline proof candidates and signed claims, challenge-based possession and irreversible rotation proposals, issuer registration and signed authority attestations. A REVIEWER role proves neither the submitting OWNER's nomination nor independent, externally authenticated signer authority. Confidential fingerprints, issuer/party evidence and signature material were exposed across owners; known UUID POST could cause review or old-key retirement in the wrong owner's workflow.

## Schema and secured OWNER nominations

Additive `0046_ep_proof_key_trust_review_scopes.sql` appends `PROOF`, `KEY_LIFECYCLE` and `EXTERNAL_TRUST` to pre-existing QUOTES/PROCUREMENT/INTAKE/DISPATCH/EVIDENCE/STOCK/JOURNAL ENUM vocabulary in both grant and event tables. Existing 0043–0045 SQL bytes remain immutable; **no implicit/backfilled grants**. `scripts/migrate-ep-reviewer-scopes.ts` verifies all 45 predecessor SHA256 checksums, denies unknown migration IDs, holds MySQL migration lock, validates checksum and supports rerun following partial non-transactional additive ENUM DDL. Allowed only `aaditech_ci` real disposable CI or *separately explicitly approved* disposable TLS staging with `EP_REVIEW_SCOPE_MIGRATION_APPROVED=YES`. Production targets refused. CI applies and replays schema 0046; staging preflight registry tracks 46.

The authenticated OWNER-only `POST /api/reviewer-scopes` accepts exact new scope, requires CSRF, current-password step-up and existing privileged MFA policy, checks actual active REVIEWER account, writes unique owner+reviewer+scope ACTIVE/REVOKED state and local event history. The nomination is **application-only**, not trust in eMudhra, CCA/RCAI, MCA, a real supplier or licensed accounting approver.

## Route-level authorization and revalidation

- `server/proofFoundation/reviewRouter.ts`: key queue verifies linked supplier/warehouse creator and ACTIVE PROOF grant; signed claim queue joins key creator and correct source type to dispatch preparation/held GRN pack creator. Detail and write load frozen cryptographic source via `readVerifiedClaim` and check exact original OWNER grant. Key and claim POST use `FOR UPDATE` grant row before durable review/HOLD and audit, regardless of known UUID.
- `server/keyLifecycle/reviewRouter.ts`: possession list joins original challenge creator and key author; rotation list checks both old/new key author equal rotation preparer. Detail uses `inspectReceipt` integrity; receipt POST locks active KEY_LIFECYCLE grant. Rotation POST checks both original key owners (also for rejection even if emergency revoked), then locks exact grant before any old-key retirement or internal decision.
- `server/externalTrust/reviewRouter.ts`: issuer list gated by original registrar owner; authority list verifies issuer registrar, local candidate key and attestation preparer match. `inspectIssuer` and `inspectAuthority` still verify cryptographic integrity, untrusted revocation and immutable payloads. Issuer/authority POST lock ACTIVE EXTERNAL_TRUST owner grant in current decision transaction. Foreign/revoked owners get empty queues or 404, not a 409 that confirms private UUID state.
- Shared `server/security/sensitiveReviewScope.ts` checks exact grant/state and live ACTIVE OWNER and REVIEWER accounts, denies self-review, and conditionally acquires row lock in mutation transaction. A read permission is never reused as proof of write permission. Existing short-lived step-up/MFA/CSRF remain required on sensitive POST.

## Genuine disposable MySQL regression

`tests/signed-proof-mysql.integration.ts` creates a second unassigned reviewer, revokes/restores PROOF on a key and signed claim and checks private queue empty, known UUID 404, zero unexpected review. `tests/key-lifecycle-mysql.integration.ts` verifies unrelated receipt list/detail denial; revocation denies known receipt review, pending rotation POST and key retirement, and regrant restores an untrusted-only internal path. `tests/external-trust-mysql.integration.ts` checks unrelated issuer list denial, issuer-review on revoked grant 404, authority attestation read/POST denial and no persisted review before owner regrant. Original mathematical Ed25519 integrity, snapshot binding, issuer/possession, signed cumulative revocation, WAREHOUSE/SUPPLIER consistency and perpetual stock zero controls must remain green. The migration unit test refuses production/unapproved staging and any auto-grant/backfill.

Hosted exact-head push+PR GitHub Actions, database schema 0046 checksum/idempotent replay, Node/TS/staging-security, real MySQL HTTP all three suites, Chromium MFA and official GitHub CheckRuns ↔ Actions Jobs 16/16 identity matching are required; docs receipt creates a later HEAD and needs its own CI. Internal CI **does not prove external CA/legal identity**, physical delivery, authorized supplier sends, company mandate or production readiness.

## Pending release and external gates

Other provider nomination/sandbox/onboarding/bridge reviewer routes must be scoped separately; provider-authorized credentials, independently authenticated RCAI/CCA/eMudhra root chain, signed live CRL/OCSP, MCA corporate/signatory evidence, real legal tenant membership/history reconciliation, product catalog/warehouse access delegation and M01–M30 complete authoritative business modules still pending. Independent protected-main nonauthor CODEOWNERS quorum, signed CI/SLSA, remote WORM/CAS/timestamp, DR and staging Security/Business/Ops approvals remain absent.

**Immutable release HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 Draft/unmerged, Issue #2 OPEN, main untouched. No live migrations, provider activation, real quote/PO/GRN, stock, customer/supplier messaging, invoices, postings or deployment.
