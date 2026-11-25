# Phase 1FJ — MySQL runtime view-grant quarantine (HARD HOLD)

Date: 24 November 2026 (IST). **Internal development control only.** This phase neither provisions credentials nor confirms independent staging/security acceptance.

## Previously unclosed attack path

Phase 1FH denies direct SELECT on protected auth, session, MFA and reviewer-authority tables, and Phase 1FF denies wildcard schema grants. However a table-scoped `GRANT SELECT ON schema.object` can name a **VIEW** rather than a base table. A MySQL `SQL SECURITY DEFINER` view may allow its invoker to read sensitive base-table data under its definer's privileges. Textual SHOW GRANTS parsing alone does not show the object's type. A compromised general runtime DB identity could therefore bypass the protected-table grant policy via an explicitly granted view.

## Engineering increment

- The 1FB grant classifier now returns only the normalized names of granted explicit data objects (never prints or exports account names or raw grant SQL).
- The read-only 1FB command and the 1FC staging preflight both classify those object names against `information_schema.TABLES`, fetched **on the same authenticated connection** after `CURRENT_USER(), DATABASE(), CURRENT_ROLE()` and `SHOW GRANTS FOR CURRENT_USER()`.
- Every grant target must be observed exactly once as `TABLE_TYPE='BASE TABLE'`. `VIEW`, `SYSTEM VIEW`, missing metadata, duplicated/case-colliding names, malformed metadata, and SQL denial all fail closed. The query never executes the view, reads confidential rows, or edits grants.
- Existing strict isolated-staging TLS, no-roles, no-wildcard, no-authority-table reads/writes, and protected-trigger checks remain mandatory. A positive metadata result is technical scope only, not a source-independent privilege graph.
- `tests/fb-runtime-db-privileges.test.ts` adds pure adversarial object classification. `tests/staging-preflight.test.ts` verifies the third same-session read and rejected view/metadata ambiguity. `tests/fc-runtime-db-privileges-mysql.integration.ts` creates and removes a randomly named disposable CI `SQL SECURITY DEFINER` view over the synthetic `auth_users` table. A SELECT grant on that view must fail; after revoke, a normal base-table CRM SELECT must recover. **No staging or production identity/table is modified.**

## Remaining acceptance blockers

The observer is point-in-time and depends on the current connection's metadata visibility. It **does not** review every definer routine, function, trigger, execution context, default role, cross-schema dependent object, stored-program execution privilege, or time-of-check/time-of-use privilege change. The standalone CLI's and preflight's technical PASS cannot be promoted to independently authorized staging or production. A real DBA and independent Security reviewer must independently inventory view/routine definers, grant paths, actual service/authority credential separation and effective privileges, then demonstrate real login/MFA/reviewer/CRM functionality under the restricted credentials on approved TLS staging.

Original Issue #2 acceptance items and M01–M30 remain OPEN. No MCA/eMudhra/CCA/RCAI independent trust, signed live CRL/OCSP, external reviewer mandates, signed provenance, WORM/DR, or provider/customer/supplier acceptance is proven by synthetic CI.

**Immutable release posture:** PR #1 remains Draft/unmerged; `main` unchanged; `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No production deployment/migration, external sends, actual quotes/PO/GRN, stock, bank, finance or tax posting.

See also: [1FH protected authority table READ quarantine](PHASE_1FH_PROTECTED_AUTHORITY_TABLE_READ_HARD_HOLD.md), [1FC staging privilege gate](PHASE_1FC_STAGING_RUNTIME_PRIVILEGE_GATE_HARD_HOLD.md), [master M01–M30 plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
