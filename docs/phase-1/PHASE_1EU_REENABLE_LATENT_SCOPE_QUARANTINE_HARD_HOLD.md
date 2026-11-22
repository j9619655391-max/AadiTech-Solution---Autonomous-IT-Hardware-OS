# Phase 1EU — latent reviewer scope quarantine on re-enable (HARD HOLD)

Date: 2026-11-23. Internal development branch only; no production migration, provider enrollment, deployment or real customer action.

## Confirmed source gap

Phase 1ET revoked app-local ACTIVE reviewer scope grants when its own `PATCH /api/security/reviewers/:id/status` action disabled a REVIEWER. But if a database administrator or another out-of-band operation set `auth_users.status='DISABLED'` without running this API, those ACTIVE grant rows could remain. Existing role/status filters denied reviewer actions while disabled; the old re-enable path then set the status back to ACTIVE without clearing those dormant grant rows, potentially restoring unauthorized historical scope access.

## Implemented internal correction

- The existing OWNER-validated and reviewer-row-locked security-admin transaction now revokes *all* ACTIVE nominations for either status transition, ACTIVE **or** DISABLED, **before** changing account status. This happens in the same MySQL transaction as invalidating sessions and writing the preexisting reviewer-lifecycle security event.
- Re-enable never automatically regrants a nomination. The existing distinct OWNER grant path (role checks, MFA, password step-up, CSRF and audited reason) remains mandatory for a future appointment. No automatic external action, new schema or expansion of delegated authority is introduced.
- The 1ET Node source-contract regression now rejects a DISABLED-only cleanup branch and asserts revocation-before-status-update and commit ordering. Existing disposable CI MySQL/HTTP tests exercise the normal disable/enable lifecycle but **do not yet** simulate the new out-of-band SQL suspension scenario. That targeted independent MySQL HTTP regression is still pending; do not claim it passed.

## Limits and future acceptance

Direct SQL write authority is not controlled by the application. An out-of-band REVIEWER→OWNER→REVIEWER role cycle can still leave a dormant grant that may reappear without a status transition; identity-epoch binding or approved reconciliation and adversarial MySQL interleavings require a separate verified increment. Already-DISABLED duplicate status changes retain the existing 409 behavior, not a standalone repair endpoint. Existing reviewer-scope audit events are not independent externally certified revocation evidence.

Real tenant/corporate mandates, actual CCA/RCAI/eMudhra issuer and live signed CRL/OCSP, MCA authorized-signatory verification, provider sandbox agreement and secrets, nonauthor Security/Business witnesses, branch rules/CODEOWNERS, signed CI/SLSA, immutable WORM/CAS/DR, isolated staging, full M01–M30 authoritative business workflows and all Issue #2 external release signoffs remain unresolved.

**HARD HOLD:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 stays Draft/unmerged, `main` unchanged; no production database action, customer/supplier messaging, quote/PO/stock/finance/tax posting or deployment.

## Evidence

Source and source-contract commits must be checked against the final docs-inclusive development HEAD. Hosted push and Draft PR runs should be inspected separately; their success, source-hash linkage and any external approval are **not** presumed by this document.
