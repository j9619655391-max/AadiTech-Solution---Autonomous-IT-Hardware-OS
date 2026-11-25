# Phase 1EW — database role/status transition quarantine (HARD HOLD)

Date: 2026-11-23. Applies to **disposable MySQL 8.0 CI** or separately authorized, isolated TLS staging only. No deployment or production migration authorization.

## Threat and correction

Prior 1ET/1EU/1EV API lifecycle repairs could not detect an out-of-band `auth_users.role` cycle REVIEWER→OWNER→REVIEWER if `status` stayed ACTIVE. Since reviewer grants bind a user ID, not a separate independently verified identity epoch, a historical ACTIVE QUOTES nomination could silently become effective again after the role returned to REVIEWER. Reusable session cookies were also at risk if both changes were performed outside the HTTP lifecycle.

New forward-only, checksum-registered `0048_ew_role_cycle_quarantine.sql` installs two AFTER UPDATE triggers on `auth_users`: whenever role **or status actually changes**, one revokes all currently ACTIVE app-local reviewer grants for that user; the second deletes that user's sessions. This is database-side coverage for **ordinary SQL updates through the trigger-bearing schema**, including a no-status role cycle. Grants are not auto-restored on returning to REVIEWER; a fresh OWNER-authenticated explicit nomination is required. Account changes that do not alter role/status are not session-revocation events.

The security-admin HTTP status route also deletes sessions *before* the account status UPDATE, retaining a truthful `revokedSessions` count despite the new trigger. All changes remain one row-locked transaction with step-up, CSRF, active acting-OWNER checks and production HOLD. The earlier 1EV hostile SQL test deliberately injects a latent grant *after* direct SQL suspension to retain coverage of explicit re-enable cleanup even when a privileged SQL actor tampers with grants.

## Migration and tests

- `db:migrate:ew-role-cycle` rejects production, unapproved staging and unknown schemas. Only `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test` or explicitly approved `aaditech_staging_*` + TLS + disposable confirmation are accepted.
- Before DDL, migration checks the 47 prior checksums and refuses any preexisting ACTIVE grant assigned to an inactive/non-REVIEWER. It **never silently repairs legacy grants**.
- MySQL trigger DDL is independently committed by MySQL. An interrupted partial migration is not automatically dropped/replaced: stop and inspect the disposable target. Rerun verifies both trigger names and checksum when migration is recorded.
- CI installs and reruns migration before `test:mysql`. The integration test creates an ACTIVE nomination/session, cycles the reviewer role through OWNER using **direct SQL**, proves scopes become REVOKED and stale sessions 401, and checks no grant reappears after role restoration. Unit tests guard migration target and API transaction ordering.

Do not mark this complete until **both exact SHA push and Draft PR GitHub Actions runs** successfully execute the real disposable MySQL job. Independently witnessed concurrent transactions and cross-process SQL interleavings remain untested. Trigger existence checks do not prove that a high-privilege SQL administrator cannot alter/drop a trigger, replace grants, or impersonate an OWNER.

## Unresolved release gates

No verified nonauthor Security/Business reviewers, written eMudhra agreement, authenticated RCAI/CCA trust chain and live signed CRL/OCSP, MCA signatory proof, external WORM/CAS independent witness, signed build provenance, isolated-approved production staging, completed M01–M30 server-authoritative operations or full Issue #2 acceptance. Database triggers are app-local safeguards, not independent authority or immutable audit evidence.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged, `main` unchanged. No production SQL/deployment, real business postings, external messaging or provider credentials.
