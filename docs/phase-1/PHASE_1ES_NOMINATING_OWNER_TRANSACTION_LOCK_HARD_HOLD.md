# Phase 1ES — nominating OWNER transactional identity lock (development HARD HOLD)

Date: 2026-11-23. Applies only to first-party internal OWNER→REVIEWER workflow nominations on the existing development branch.

## Confirmed race boundary

The /api/reviewer-scopes POST route already enforces a live OWNER session, CSRF, privileged MFA, password step-up, explicit workflow scope, independent REVIEWER identity, and an audit event. Its transaction previously locked only the target REVIEWER and grant row. A concurrent administrator action disabling/demoting the originating OWNER after request middleware but before the grant write could permit a stale privileged nomination or revocation event. The session check is not a transactional identity check.

## Change

- Inside the same nomination transaction, select the originating OWNER from auth_users using FOR UPDATE, require exactly one row with role=OWNER and status=ACTIVE, and deny 403 plus rollback if not satisfied.
- Acquire that row lock before the reviewer and grant row locks, preserving audited GRANT/REVOKE and existing target REVIEWER validation. No new scope, automatic grant, migration, legal authority, provider call or production action.
- Include the source-contract regression in CI plus the existing disposable MySQL procurement HTTP integration with temporarily disabled/demoted owner sessions and zero new QUOTES grant/event assertions. The direct HTTP tests validate suspension denial; the order/locking source contract validates the transaction guard. These do not constitute a formal concurrency/interleaving proof.
- Add the new regression to the 1BV/1BW governed source-input inventories. Verify both hosted push and Draft PR workflow runs against the exact committed SHA before describing CI as passed.

## Explicitly still pending

Independent live corporate/legal mandates, genuine provider credentials, RCAI/CCA/eMudhra issuer chain and signed live CRL/OCSP, outside WORM/CAS continuity and independent DR, protected-main CODEOWNERS/rulesets and independent reviews, staging penetration testing and owner/security/operations acceptance, and server-authoritative M01–M30 business workflows.

The production gate is unchanged: productionReleaseAuthorized=false; productionReleaseBlocked=true; releaseDecision=HOLD. No merge, production deploy, live supplier/customer messaging, financial or stock postings.
