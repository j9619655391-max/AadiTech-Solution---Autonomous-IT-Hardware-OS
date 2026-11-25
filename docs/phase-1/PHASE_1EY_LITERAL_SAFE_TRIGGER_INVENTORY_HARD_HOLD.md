# Phase 1EY — SQL literal-safe trigger verification and BEFORE-trigger quarantine (HARD HOLD)

Date: 2026-11-23. This is **development-only defense-in-depth** on 1EX/1EW, not independent SQL attestation, staging acceptance, release authorization or permission to change production.

## Confirmed comparator gaps

The 1EX comparator removed backticks everywhere in `ACTION_STATEMENT` including *inside SQL string literals*. A malicious trigger body with `state='REV`OKED'` could therefore compare equal to the required `state='REVOKED'` even though the database literal differs. The information_schema query also filtered to AFTER UPDATE, making unexpected BEFORE UPDATE triggers on `auth_users` invisible to the checker.

## 1EY containment

- Tokenize single-quoted SQL literals, simple backtick-quoted identifiers and unquoted text separately. Preserve string-literal bytes exactly. Normalize only non-literal whitespace/operator spacing and quoted **simple** identifier delimiters; reject malformed quoting.
- Enumerate **all** `auth_users` UPDATE triggers from real `information_schema.TRIGGERS`. Require exactly the two pinned AFTER UPDATE names and their matching SQL bodies; fail on any missing, unknown, duplicated, BEFORE-timed, or altered body.
- Retain checksum-locked migration `0048_ew_role_cycle_quarantine.sql` unchanged. First installation and already-applied verification both use the same installed trigger checker; never auto-drop, repair or promote a drifted database.
- Extend the existing 1EX adversarial test suite with literal backtick, literal-space, malformed identifier and BEFORE UPDATE trigger cases; register this source and test in the 1BV/1BW unsigned local source-input inventories.

## Evidence and operator response

1. Verify the exact development SHA and **both** push and Draft-PR CI receipts; inspect real disposable MySQL migration rechecks as well as Node/TS unit results.
2. Execute only in existing `aaditech_ci` with `CRM_TEST_DB=1` and `NODE_ENV=test`, or under separately authorized disposable TLS staging approval. Never run 0048 on production.
3. On installed trigger drift, **HOLD**, preserve non-sensitive query metadata, investigate with an independent SQL/Security reviewer, and do not auto-repair or waive the mismatch.

This is only a point-in-time application-controlled check. Privileged DBA changes after verification, compromised DB privileges or metadata views, untested adversarial interleavings, missing independent timestamped WORM attestation and absent external identity authority remain unsolved.

**Unresolved release acceptance:** Issue #2/M01–M30 server-authoritative business workflows, MCA legal signatory/tenant mandate, licensed eMudhra sandbox and current CCA/RCAI chain/live CRL/OCSP, two independent nonauthor approvals, effective protected-main/CODEOWNERS, external WORM/CAS/DR, signed workload provenance, isolated TLS staging and human business/security/operations signoff.

**HARD HOLD:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged and `main` unchanged. No live provider onboarding, customer/supplier dispatch, quote/PO/GRN, stock/finance/tax posting, or production deployment/migration.
