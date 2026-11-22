# Phase 1EO — Deny-by-default stock release and journal reviewer access

**Date:** 23 November 2026 IST. Canonical repo: j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS, `chore/phase0-foundation-20261106`. All controls are internal app engineering only, not physical inventory or financial authority. Draft PR #1, Issue #2 remain open; main unchanged and production release HARD HOLD.

## Actual privilege flaw

The `STOCK` reviewer endpoints used `prepared_by<>reviewer` to list private held GRN/release intent evidence and to authorize review of any other person's release by ID. `JOURNAL` reviewer endpoints likewise exposed draft double-entry evidence and serial ownership candidates from unrelated OWNERs, despite no declared workflow assignment. Basic REVIEWER role does not establish consent from each relevant OWNER, nor independent financial regulator/legal authorization.

## Additive schema and authorization boundaries

- Checksum-locked additive `0045_eo_stock_journal_review_scopes.sql` extends prior app-local workflow scope ENUM in both owner→reviewer grant and grant/revoke audit-event tables from QUOTES, PROCUREMENT, INTAKE, DISPATCH, EVIDENCE to additionally STOCK and JOURNAL. Previously granted roles are unchanged. No automatic STOCK/JOURNAL grants, no addition of production tenancy, ownership or accounting authority, no historical data modification.
- `scripts/migrate-eo-reviewer-scopes.ts` requires all 44 prior registered SQL byte hashes match; unknown migrations are denied, MySQL advisory lock acquired, the two safe/repeatable additive ENUM statements applied and a new immutable 0045 checksum recorded. Only disposable CI `aaditech_ci` or explicit approved isolated TLS staging; never production. Registry/staging preflight now checks 45 schemas; CI runs 0045 twice before real MySQL suites. `tests/eo-reviewer-scope-migration.test.ts` rejects unapproved targets, unexpected grants or retroactive DML.
- OWNER `POST /api/reviewer-scopes` continues to require CSRF, actual active target REVIEWER, current-password step-up, privileged MFA policy and bounded grant/revoke reason. Two new scope values `STOCK` and `JOURNAL` are accepted only as internal workflow nominations. They never establish legal finance approver credentials or release authorization.

## Server-side source identity and write-time revocation

Stock review queue derives private release rows from `inv_stock_release_intents`, original held GRN, pack, supplier acknowledgment, dispatch preparation and original purchase request. It confirms original pack owner and source request creator match the release preparer, then requires exactly ACTIVE owner→reviewer `STOCK` grant. Release detail calls `checkReleaseIntent` for original held source readback and independently checks active grant before exposing serial lines. Release decision transaction again checks the same trusted original owner and locks the scope row `FOR UPDATE` prior to any review, zeroPosition or release-HOLD write. Revocation is serialized; known UUID never bypasses.

Journal review queue joins the original stock release, warehouse site, held GRN and purchase request; preparer must match the original request/pack, site owner and source release author plus ACTIVE `JOURNAL` grant. Journal detail uses `checkJournal` immutable original source to bind reviewer to precise owner. Journal decision locks current `JOURNAL` grant in transaction before writing local unposted review/hold or audit. Unknown or REVOKED scope returns an empty queue or 404, never a foreign record or synthetic financial posting.

Existing role separation, privileged MFA/step-up, source hashes, immutable schema constraints, zero availability/reservations, unposted accounting candidate and disabled posting stay intact. Stock `availableToSell=null`, postingState DISABLED and no verified supplier, legal GRN or real inventory ledger.

## Adversarial acceptance

`tests/stock-foundation-mysql.integration.ts` and `tests/journal-foundation-mysql.integration.ts` seed real disposable MySQL held source and one explicit in-app reviewer nomination each. Separate independently authenticated but unassigned REVIEWER sees no foreign record or detailed source by UUID. OWNER revokes via authenticated step-up and CSRF API, original reviewer loses queue/list and known-ID POST review rights immediately (404) with **zero decision/held outbox**. OWNER regrants and valid stock/journal evidence-only HELD review flows continue. Unit tests check 0045 schema and no auto-grants; Phase1BV/BW local source-custody inventory includes all modified controls.

Both hosted push and PR exact-head CI, checksum rerun, full Node/TypeScript security tests, real MySQL HTTP integration, isolated Chromium and official GitHub Actions Checks↔Jobs 16/16 exact source are required for **internal engineering acceptance**. A later docs receipt demands its own CI. No synthetic fixture is a legal warehouse receipt, ownership proof or independent auditor signature.

## Explicitly still pending: production/business/third-party readiness

Genuine MCA verified corporate identity, signatory mandate, licensed eMudhra access and provider-issued trust chain/CRL/OCSP, approved supplier/customer consent and dispatch, real legal quote/PO/GRN issuance, actual inventory opening balance certification, transferred ownership, ERP finance and statutory tax posting, fully server-authoritative M01–M30 modules (AMC, tickets, sales, forecasts, campaigns/agents included), independently reviewed route BOLA across other provider/security domains, protected main CODEOWNERS quorum, off-platform WORM/CAS and restore, signed CI/SLSA and independent Security/Operations/Business staging approvals. The local reviewer grant does not satisfy any of these.

**Unchanged release invariant:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; Draft PR #1 not merged, Issue #2 open, main untouched. Never deploy or import legacy destructive schema; no customer/supplier sends, provider credential traffic or real stock/finance/tax postings.
