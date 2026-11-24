# Phase 1GB — M17 append-only runtime privilege envelope

The 1GA restricted-principal test exercised SELECT/INSERT on the field service plan and creation audit tables and proved SQL UPDATE/DELETE denial. However the general runtime grant assessor previously accepted table-specific DML on ordinary tables, including these two. 1GB explicitly rejects UPDATE and DELETE on either table (case-normalized names); only SELECT and INSERT are allowed for them. No change to actual deployed grants or production database.

Unit regression checks allowed and forbidden grant combinations. Disposable MySQL test creates an isolated random runtime account, observes SELECT/INSERT as allowed, grants UPDATE and DELETE one at a time on each table, requires read-only preflight rejection, revokes each temporary grant and confirms recovery. The temporary account is removed. This is an application-controlled observation of grant shape, not independent DBA approval, cryptographic evidence or protection against privileged DBA rewrite.

All M01–M30 external acceptance remains OPEN. M17 SERVER_INTERNAL_HELD; main unchanged, PR #1 Draft/unmerged, Issue #2 OPEN, production HARD HOLD. Exact-head dual CI required.
