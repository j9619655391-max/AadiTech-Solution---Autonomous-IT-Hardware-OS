# Phase 1FT — M16 high-confidence credential exclusion at internal ticket admission (HARD HOLD)

Date: 24 November 2026 IST. Branch: `chore/phase0-foundation-20261106`. Draft PR #1 and Issue #2 continue tracking real external acceptance.

## Defect and bounded fix

M16 internal service ticket subject, descriptions and status-change audit notes previously allowed any valid-length free text. A person could accidentally paste a password, GitHub personal access token, session cookie, private key or an authorization header into the internal ticket database; subsequent history, unsigned 1FS digest and browser reads would preserve the secret. This is a clear in-scope credential-leak prevention gap.

`server/serviceDesk/validation.ts` now applies `rejectCredentialLikeTicketText()` to all three `textValue()` admission paths (CREATE subject and description; PATCH status note). It rejects **high-confidence** indicators before any CREATE INSERT; status note validation runs inside the transaction before version UPDATE and audit INSERT, rolling back on validation failure. Validation only reports a generic failure and never echoes credential values or logs raw notes. Patterns include PEM PRIVATE KEY header, AWS `AKIA`/`ASIA` IDs, GitHub token prefixes, Slack `xox*` tokens, `aaditech_session=` cookie, Authorization Bearer/Basic headers, JWT-shaped token triplets, and explicit `password=`, `api_key=`, `client_secret=`, access/refresh token assignment of sufficiently long value. Safe diagnostic prose like “password reset loop; do not collect passwords” remains allowed.

M16 UI explicitly warns against passwords, tokens, private keys, session cookies and other sensitive identifiers. **This is narrow admission validation, not complete DLP**: arbitrary secrets, passwords without recognizable labels or shorter/unusual formats, supplier/customer personal data, existing stored rows, other modules or hidden attachments are not comprehensively detected. Never claim all confidential content is blocked. Do not store/rewrite rejected input; requester must redact or omit and retry.

## CI-only adversarial verification

- Unit tests exercise fake token patterns across subject, description and status note; ordinary diagnostic support descriptions still pass.
- Real **disposable** MySQL HTTP tests ensure rejected CREATE returns 400 with zero new tickets/audit rows and no secret echo. A separate valid synthetic ticket denies secret-bearing PATCH notes, leaving status version 1/audit count 1 unchanged; a normal diagnostic PATCH then succeeds, preserving existing 1FR continuity and 1FS unsigned fingerprint semantics.
- Credential tests use dummy invented strings only; do not place actual credentials in GitHub, tests, chat, logs or UI fixtures.
- Validate integrated push + Draft-PR workflows against **exact dev HEAD** and retain any honest CI failure logs. Test results are software-engineering evidence, never real supplier/customer authorization.

## Independent gates unaffected

M16 remains `SERVER_INTERNAL_HELD`: actual customer consent, service order, SLA/AMC, technician authority, repair completion and legally accepted closure remain unverified. SHA-256 fingerprint is not external signed WORM or non-repudiation. External eMudhra/CCA/RCAI/MCA trust and live signed CRL/OCSP, separately provisioned DBA/Security/Business-approved staging and independent reviewers, signed WORM/DR and M01–M30 gates remain OPEN.

`productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 Draft/unmerged, `main` unchanged, Issue #2 OPEN. No production deployment, actual customer/supplier sends, official quote/PO/GRN, stock/finance/tax posting, provider activation or remote Windows execution.

Related: [Phase 1FN service ticket foundation](PHASE_1FN_M16_INTERNAL_SERVICE_TICKETS_HARD_HOLD.md), [Phase 1FS unsigned fingerprint](PHASE_1FS_M16_BOUNDED_UNSIGNED_AUDIT_FINGERPRINT_HARD_HOLD.md), [M01–M30 master plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
