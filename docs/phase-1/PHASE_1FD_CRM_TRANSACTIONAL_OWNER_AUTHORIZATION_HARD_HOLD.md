# Phase 1FD — transactional ACTIVE OWNER revalidation for CRM writes (HARD HOLD)

Date: 23 November 2026. Scope: M03/M01 **server-internal engineering**, exclusively on the development branch with disposable CI coverage. This is not legal tenant authority, production deployment acceptance or permission to send messages/issue documents.

## Actual gap identified

The CRM Express router runs `requireOwner` before the repository starts a MySQL transaction. A direct SQL role change or OWNER suspension can race that first authentication decision. Previously the `MySQLCRMRepository` create/update/soft-delete transaction performed no active role/status locking of its actor and could mutate records while an owner was concurrently demoted or disabled. Audit CREATE provenance and version/CSRF protection do **not** close a transaction-bound authorization race.

## Changes and enforced invariant

- `server/crm/repository.ts` exports `lockActiveCrmOwner` and `CRMOwnerInactiveError`. At the start of **all three** CREATE, PATCH and soft DELETE transactions, after `BEGIN` and **before** fetching/mutating records or creating audit events, the repository issues `SELECT role,status FROM auth_users WHERE id=? FOR UPDATE` and requires **exactly one** identity with role OWNER and status ACTIVE. The lock persists to COMMIT/ROLLBACK, serializing this write with account status/role transitions.
- Failure throws `CRMOwnerInactiveError`, rolls back, creates **no** record, update, delete or audit entry. `server/crm/router.ts` returns an explicit generic HTTP **403** without leaking SQL details.
- A transition that gets the row lock first must complete before the CRM transaction can proceed; the subsequent CRM transaction observes the new status and rejects the write. A CRM transaction that gets the lock first serializes its already-authorized change ahead of a subsequent disable/demotion. This is linearizable for this row-lock boundary, not proof of independent corporate authority.
- Existing creator-audit scope and server-side optimistic version checks remain in place; no new table, tenant membership, release, provider send, quote/PO/GRN or stock/finance posting is introduced.
- `tests/fd-crm-owner-race-mysql.integration.ts` creates disposable randomized OWNER and CRM rows. It tests **all three write types** after DISABLED or REVIEWER role transitions, checks unchanged CRM row/version and unchanged audit count, then rechecks positive ACTIVE OWNER operations. Its second test holds a real InnoDB disabling transaction and requires `ER_LOCK_WAIT_TIMEOUT` from competing CRM CREATE, followed by a real rejection after disable commits.
- `package.json` registers `test:fd-crm-owner-mysql`. GitHub MySQL integration workflow runs it after migrations. BV/BW source review inventories include the updated router/repository and new test.

## Evidence still required

1. Record **both** exact development HEAD push and Draft PR workflow completion, including TypeScript, all unit/source governance and the dedicated 1FD real MySQL step. Retain historical failed intermediate runs.
2. A real approved isolated TLS staging session/demotion concurrency exercise must be separately authorized; the CI fixture intentionally refuses any non-disposable DB.
3. Independently prove effective DB runtime least privilege against actor status, audit event forgery, ownership data changes, and direct writes to protected grants. A DBA or compromised schema-wide DML account can defeat app-level checks unless stronger DB isolation exists.
4. Implement verified business tenancy, actual historic CRM migration/data reconciliation, identity-provider enrollment and object-level BOLA review before claiming M03 complete. OWNER identity is not evidence of a legally authorized organization or customer record.

## Residual HOLD

The CRM API still uses creator CREATE audit provenance for first-party owner scoping rather than a separately vetted corporate tenant membership ledger; some historical/foreign rows are purposely invisible. This change does not grant external supplier/customer authority or prove full M03 tenant/object acceptance, signed WORM evidence, independent eMudhra/MCA/CCA/RCAI legal trust, third-party governance, protected main, provider onboarding, successful real DR restore or production release.

**HARD HOLD:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Keep PR #1 Draft/unmerged and main unchanged; original Issue #2 M01–M30 external acceptance OPEN. No production migration/deployment, customer/supplier dispatch, official quote/PO/GRN, stock, bank or tax posting.
