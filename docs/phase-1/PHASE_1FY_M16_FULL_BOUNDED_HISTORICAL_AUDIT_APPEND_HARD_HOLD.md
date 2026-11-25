# Phase 1FY — M16 full bounded historical audit integrity before status append

24 November 2026 IST. Development branch only; production HARD HOLD.

## Engineering

Phase 1FX checked only the latest 101 audit events before a status mutation. A previously corrupted genesis, older transition or actor outside that window could still go undetected. Phase 1FY replaces that partial guard with a **complete structural check of the existing bounded ledger**. The active OWNER and owned ticket/customer provenance row remain locked first. After expected-version/transition validation, the transaction checks the append capacity and performs one current shared-lock read of the ticket audit, ordered by descending version, limited to 1000 rows. The query deliberately does not filter by actor.

`verifyInternalTicketAuditForAppend` requires exact event count equal to the current ticket version, all event actors equal to the scoped OWNER, valid latest anchor, continuous versions/status transitions and valid CREATE genesis. Overlapping 101-row windows from the same locked result reuse the 1FR verifier; each sentinel also starts the following window. No original evidence is rewritten. Invalid history returns generic 503 before either UPDATE or INSERT. Valid writes retain the atomic ticket/version update and new event append.

The resulting ledger cannot exceed 1000 events (the same numerical capacity as the existing internal fingerprint). At version 999, one validated append to 1000 is allowed. At version 1000 or above, further status updates fail closed with HTTP 409, explicit independent-review requirement and INTERNAL_HELD/dispatch disabled. This is an intentional operational limit: do not bypass by deleting, truncating, rolling over or silently rewriting evidence. No new grants, migration or production activity.

## Tests and acceptance

- Unit fixtures at 1/99/100/101/102/103/201/999 verify complete historical windows. Wrong actors at multiple depths, genesis changes, gaps, missing/extra rows and invalid/capped versions rejected. Source contract verifies owner/ticket lock, capacity, locked read, whole-ledger guard and write/commit order.
- Disposable MySQL test corrupts genesis and version-two actor outside the newest 101 rows of the 104-event fixture. Detail's bounded read can still succeed; write rejects 503 with unchanged version/status/count. Restore only the intentionally corrupted CI fixture, then valid append and fingerprint succeed.
- Separate CI fixture builds a structurally valid 999-event ledger, allows one append to 1000, rejects the next with 409 and confirms exactly 1000 stored events and an unsigned fingerprint.
- Verify push and Draft PR workflows on exact latest HEAD. The fixture is synthetic, not external evidence.

## Limits

Complete structural validation within the 1000-event bound is not cryptographic authentication, privileged rewrite detection, legal consent, WORM custody, actual technician work or an external signed audit. Notes/timestamps may be changed without violating structural continuity. An independently authorized review and evidence-preserving long-history strategy are still required. Detail/history reads remain bounded and do not individually promise full historical validation. No real customer/service approval is granted.

M16 SERVER_INTERNAL_HELD; all M01–M30 independent external acceptance remains OPEN. Genuine consent, provider authority, company/signatory verification, signed revocation/WORM/DR, DBA/Security/Legal/Business signoff and independently approved staging remain pending. `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Keep main unchanged, PR #1 Draft/unmerged and Issue #2 open. No production migration/deploy, real customer/supplier sends, official quote/PO/GRN, stock/finance/tax booking, provider activation or remote Windows operation.
