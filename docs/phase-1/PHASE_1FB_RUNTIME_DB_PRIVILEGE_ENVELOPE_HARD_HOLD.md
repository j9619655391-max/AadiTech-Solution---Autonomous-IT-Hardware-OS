# Phase 1FB — runtime MySQL grant envelope preflight (HARD HOLD)

Date: 2026-11-23. Scope: offline adversarial code tests and a **separately approved isolated TLS staging runtime database account**. This feature does not change production SQL, install database permissions, rotate secrets, grant users access, authorize deployment or claim independent Security/DBA approval.

## Observed risk

The Phase 1EW database triggers and Phase 1EZ installed-trigger integrity checks provide app-controlled defense-in-depth. If an application runtime DB principal is overprivileged (global grants, DDL/TRIGGER, GRANT OPTION, administrative role delegation) a compromised connection can modify the enforcement mechanism. Phase 1FA's deterministic transaction ordering does not itself restrict privileged SQL actors.

## Implemented technical observation

- scripts/phase1fb-runtime-db-privileges.ts runs **only** with RUNTIME_DB_PRIVILEGE_PREFLIGHT=YES, STAGING_DISPOSABLE_CONFIRMED=YES, NODE_ENV=staging, DB_SSL=true, a database named aaditech_staging_*, and without CRM_TEST_DB=1. By default it refuses to connect. Uses the existing trusted TLS database settings and requires an explicit database principal.
- Performs SELECT CURRENT_USER(), DATABASE() and SHOW GRANTS FOR CURRENT_USER() on **the authenticated connection**. No DDL/DML/revocation/permission change.
- **Updated in Phase 1FE:** deny-by-default grant classifier allows only global USAGE and explicit target **table-level** SELECT/INSERT/UPDATE/DELETE (with protected authority-table writes blocked). Phase 1FF additionally forbids schema-wide SELECT, not just DML. Phase 1FH now refuses **both explicit table reads and writes** on the named authentication, reviewer authority, event and MFA state tables, including SELECT+UPDATE mixed grants. Only non-protected table-level grants can pass; the privilege observer does not repair existing auth workflows. The source does not provision an alternate trusted writer. It rejects global DML, CREATE, ALTER, DROP, TRIGGER, dynamic/unknown privileges, excessive scopes, GRANT/ADMIN OPTION, unexpanded role delegation, malformed/surprising quote or grant syntax, missing DML and unidentified connection schema/principal.
- The machine-readable receipt contains only a truncated SHA-256 fingerprint of the observed account, counts and generic denial reasons, never the full username, connection string, password or raw grants. Technical result PASS does **not** enable production. It still prints productionReleaseAuthorized=false, releaseDecision=HOLD, outsideDbaControlVerified=false and independentSecurityApproval=false.
- tests/fb-runtime-db-privileges.test.ts exercises safe and hostile grant syntax, strict target opt-in and deny-only CLI contract. package.json registers db:runtime-privileges:preflight. The source and tests are tracked in 1BV and 1BW inventories, and unit tests run in the standard baseline without staging credentials.

## Explicit operator handoff (NOT run in CI)

1. Independently provision an approved **disposable** TLS staging MySQL instance, a dedicated runtime account and separate migration/DBA identities. Never put credentials in Git or test receipts.
2. Under secured operator custody, ensure DB_NAME matches the isolated schema and DB_SSL=true with a trusted CA; then set the explicit observation guard flags and run the new command using that **runtime principal's credentials** (not a privileged migrator's).
3. Independently compare the bounded technical receipt against DB administrative grant inventory and effective/current roles with a different appropriately authorized DBA. Capture outside-app timestamped evidence and signed witness approval. Do not treat app-produced output as an external audit.
4. If the command reports HOLD, preserve evidence; change privileges only under separately authorized DBA change control and re-run. Do not weaken the classifier to accept unexpected grants as a shortcut.

## Residual risk / release hold

This is conservative text classification of MySQL SHOW GRANTS, not cryptographically authenticated account authority or a complete privilege graph. Database roles, definer routines, proxy users, alternate sessions, account changes after observation, MySQL privilege metadata tampering and compromised DB administration can evade or invalidate a point-in-time check. Phase 1FE rejected schema-wide DML and protected-table mutations; Phase 1FF rejected schema-wide SELECT; Phase 1FH additionally rejects protected-table SELECT. **This remains only a read-only grant observer, not MySQL authorization reconfiguration**. Existing application code may require writes to these same tables and will need independently designed, separately credentialed controlled authority operations. Role activation, column-level privileges, routines/definers and database grants changed after observation still need independent DBA verification. Until a real staging writer/read separation and functional HTTP tests prove both security and availability, staging acceptance remains **unverified**.

Likewise, Issue #2 and M01–M30 operational workflows, actual legal/MCA corporate authority, licensed eMudhra/CCA/RCAI trust and CRL/OCSP, protected main/CODEOWNERS, independent nonauthor Security/Business/Operations signoffs, signed workload provenance, WORM/CAS and independent encrypted DR, provider agreements, and isolated staging business acceptance remain OPEN.

**HARD HOLD:** productionReleaseAuthorized=false; productionReleaseBlocked=true; releaseDecision=HOLD; PR #1 Draft/unmerged; main unchanged. No production migration, actual customer/supplier communication, quote/PO/GRN, stock/finance/tax posting or live provider activation.
