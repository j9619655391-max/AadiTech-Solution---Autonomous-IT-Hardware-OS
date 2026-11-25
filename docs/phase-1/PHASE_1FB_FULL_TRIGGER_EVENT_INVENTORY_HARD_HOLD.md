# Phase 1FB — full auth_users trigger-event inventory (HARD HOLD)

Date: 2026-11-23. Development and disposable-CI/approved isolated staging scope only.

## Gap, implementation and tests

Phase 1EZ queried only `auth_users` UPDATE triggers. An additional malicious INSERT or DELETE trigger could be invisible to that check. This is a potential bypass in trigger-inventory coverage, **not** an assertion a malicious trigger existed.

- Both checksum-locked 0048 migration rerun and standard read-only `staging:preflight` now select `EVENT_MANIPULATION` for **all** installed triggers on the current database's `auth_users` table. They do not filter the event kind in SQL.
- The shared literal-safe comparator requires exactly two known named AFTER UPDATE triggers with exact pinned enforcement statements. Wrong/missing event labels, any extra INSERT/DELETE/UPDATE trigger, BEFORE trigger and body drift deny readiness.
- The preflight target classifier additionally rejects `NODE_ENV=production` even when a staging-like DB name is supplied.
- Existing unit fixtures now include MySQL event-kind metadata; new adversarial checks cover unexpected INSERT/DELETE and wrong-event labels, including read-only SQL observation. The migration 0048 SQL and checksum are unchanged; no DDL, repair, grants, status change or release authorization is performed.

## Verification and unresolved acceptance

Run `bun run lint` / `bun run test` and check *new exact-HEAD* push and Draft PR workflows; disposable MySQL must execute migration rerun and `STAGING_PREFLIGHT=1` including full event-inventory comparison. Preserve all failures and don't call CI passing an external audit.

This is **point-in-time in-band metadata**. A privileged DBA can still alter triggers after checking or manipulate query results, grants, definers and transaction scheduling. Real independent privileged-SQL boundary assessment, controlled concurrency tests, external WORM/signatures, verified legal/eMudhra/CCA/RCAI/MCA authority, approved staging and Issue #2 M01–M30 acceptance remain pending.

`productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 Draft/unmerged; `main` unchanged. No production SQL, real provider onboarding, customer/supplier contact, actual stock or financial/tax posting.
