# Phase 1FU — M16 read-side masking for pre-existing credential-like ticket notes (HARD HOLD)

Date: 24 November 2026 IST. Development branch `chore/phase0-foundation-20261106`. Release-control source remains Draft PR #1 / Issue #2 / M01–M30 master completion plan.

## Threat model and engineering boundary

Phase 1FT rejects high-confidence credential material **in new CREATE/PATCH text**. It cannot undo pre-existing unreviewed ticket records whose subject, description or versioned internal audit note already contains a recognizable password, access token, secret or private key. Sending those fields unchanged to an authenticated OWNER operator may still expose secrets, including on an older audit page. The safety objective is to avoid that additional **read-side exposure** while preserving the original synthetic/real audit source for an eventual independently controlled remediation procedure.

In `server/serviceDesk/validation.ts`, `maskCredentialLikeTicketText(value)` reuses the 1FT high-confidence matcher; a suspicious field becomes the **entire** literal `[REDACTED: possible credential in legacy internal text]`, with a distinct `redacted:true` flag. It does **not** echo any prefix or suffix, does not mutate the database and fails closed on corrupt/non-string projection values. Benign troubleshooting prose stays unchanged and is marked `redacted:false`.

In `server/serviceDesk/router.ts`, the owner-scoped ticket LIST projects both subject and description through `maskedTicket()`. Detail GET projects both text fields and each bounded audit note; older keyset-history GET projects every note through `maskedAuditHistory()`. These protections run **after** existing OWNER session checks, CRM customer creator provenance and the 1FR read-only snapshot/transition-chain checks. `subjectRedacted`, `descriptionRedacted`, and per-event `noteRedacted` fields signal why the display differs from stored source. M16 UI shows an explicit legacy-secret warning. All API responses remain `mode:'INTERNAL_HELD'`, `externalDispatchEnabled:false`, `Cache-Control:no-store`; unauthorized IDs return 404, anonymous/reviewer denied.

The 1FS optional fingerprint reads the **original** internal audit notes within its own authenticated, bounded read-only snapshot and returns **only SHA-256/count/flags**, never the notes. This permits local comparison without claiming that masked displayed notes reproduce the digest. The digest remains `APPLICATION_UNATTESTED`, `signatureVerified:false`, `externalAnchorVerified:false`, `customerConsentVerified:false`. No DB row is purged, redacted in storage or promoted to signed WORM. This matters for traceable future legal/Security/DBA-led evidence handling.

## Disposable CI-only verification

- Unit tests verify complete-field masking for fake private keys, long secret labels, synthetic GitHub tokens and authorization header strings; safe diagnostic text passes unchanged, invalid database projection types fail closed. Source contracts check list + detail + history masking.
- MySQL integration deliberately inserts **synthetic** credential-like legacy values into a disposable `aaditech_ci` ticket and its CREATE audit note via direct CI SQL, bypassing admission logic only to model old rows. OWNER list/detail/keyset-history all return full-field placeholder and flags, and no raw test-secret substring appears in response JSON. Unauthorized OWNER and REVIEWER requests continue to deny. The unsigned fingerprint changes when the underlying synthetic audit note changes, but never exposes note content. Direct SQL confirms the source database row still has the fake value, and finally restores each original value; safe subsequent reads are unmasked. No real credentials, customer records or external systems involved.
- Integrated success claim requires both **exact-head** push and Draft-PR CI COMPLETED/SUCCESS, including MySQL, baseline/browser MFA/governance. Historical failing runs must not be represented as green.

## Limitations / unresolved external acceptance

This is a **narrow indicator-based masking layer**, not complete DLP, malware detection, data classification, legal retention/remediation, privileged-DBA access control or secret rotation. A secret without a recognized indicator can still appear, and credentials already stored elsewhere or copied outside this service are not removed. Existing exposed secrets require independently authorized incident review, revocation/rotation, safe archival/retention and tenant/customer legal handling; not an automatic application delete. Internal reviewers still must avoid entering sensitive personal data. This does not prove consent, SLA, repair or audit immutability.

M16 remains `SERVER_INTERNAL_HELD`. Provider-authorized eMudhra/MCA/CCA/RCAI, live signed CRL/OCSP, approved real separate-principal TLS staging, independently authenticated DBA/Security/Business/Legal reviewers, signed WORM/DR custody, original customer consent, technician and operational service evidence remain OPEN, as do remaining M01–M30 external gates.

`productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged and Issue #2 open; `main` unchanged. No production deploy/migration, actual supplier/customer communications, official quotes/PO/GRN, stock/finance/tax postings or remote Windows execution.

Related: [1FT admission guard](PHASE_1FT_M16_CREDENTIAL_LEAK_ADMISSION_HARD_HOLD.md), [1FS unsigned fingerprint](PHASE_1FS_M16_BOUNDED_UNSIGNED_AUDIT_FINGERPRINT_HARD_HOLD.md), [M01–M30 master](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
