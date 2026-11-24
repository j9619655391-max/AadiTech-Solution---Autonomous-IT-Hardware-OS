# Phase 1FX — M16 locked status mutation audit guard (HARD HOLD)

Date: 24 November 2026 IST. Development branch `chore/phase0-foundation-20261106`; Draft PR #1 open/unmerged; Issue #2 open.

## Gap and controls

Phase 1FR verifies structural audit integrity when reading ticket detail/history. Phase 1FS computes a bounded unsigned local fingerprint. Neither previously prevented a legitimate status transition from extending an already inconsistent recent audit ledger.

The existing PATCH status transaction locks the active OWNER and the owned ticket/customer provenance row. After validating the proposed internal transition and optimistic expected version, it now issues a **locking current read** of the latest 101 audit events using `WHERE a.ticket_id=? ORDER BY a.version_after DESC LIMIT 101 FOR SHARE`, on the same connection and transaction. This includes the actual boundary sentinel, rather than filtering out mismatched actors. The existing 1FR verifier checks anchor version/status, adjacent transitions, continuity, genesis when in scope, and sentinel validity. Every returned event must have the ticket owner's actor ID. The ticket row lock serializes legitimate concurrent writers; audit shared locks protect the selected records until commit or rollback. Shared locks use read privileges on supported MySQL 8 releases and do not require granting audit UPDATE/DELETE authority. No migration or new grants.

An inconsistent ledger produces a generic 503 via the existing failure handler, rolling back before either ticket UPDATE or audit INSERT. Existing stale-version, invalid-input, role and owner rejection remain; valid transitions still atomically increment the ticket version and append a STATUS_CHANGE event. All resulting states remain INTERNAL_HELD, consent UNVERIFIED and dispatch DISABLED.

## Verification

- Unit source-contract test checks the order: active owner lock, owner-scoped ticket lock, bounded audit locking read, version/status verifier, actor check, status UPDATE, audit INSERT, commit. Failure path rolls back.
- Disposable MySQL HTTP tests exercise corrupted genesis status, mismatched historical actor, moved latest audit version, broken transition linkage, foreign OWNER denial, recovery after restoring synthetic fixtures, successful valid updates and subsequent read/fingerprint. Assert ticket version/status and audit count remain unchanged on rejection.
- The prior 103-version CI-only ticket exercises a corrupted 101st sentinel; valid status write fails without changing version or count; restoration permits transition to version 104.
- Verify both exact-head push and Draft-PR CI, including baseline, MySQL and governance. Retain failed historical runs.

## Explicit limitations

The guard checks only the newest 101 events, not an unlimited historical scan or a cryptographic signature. Earlier corruption outside this window, coordinated rewrites by a privileged administrator, untrusted notes and historical identity/key custody are not independently certified. Local database integrity and synthetic CI cannot establish legal consent, actual repair, technician authority or immutable external WORM custody. Do not automatically repair/delete real audit rows; investigate inconsistencies with independently authorized DBA/Security/Legal reviewers. Independent staging permissions and behavior remain unverified.

M16 remains `SERVER_INTERNAL_HELD`; genuine customer consent, SLA/AMC, signed WORM/DR, independent business/legal/security/DBA approvals, independently approved TLS staging and real provider trust (eMudhra/CCA/RCAI/MCA, live signed CRL/OCSP) remain OPEN, along with remaining M01–M30 external acceptance. No production migration/deploy, main merge, real customer/supplier dispatch, official quotes/PO/GRN, stock/finance/tax posting or provider/device activation.

`productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`.

Related: [1FR audit snapshots](PHASE_1FR_M16_SNAPSHOT_AUDIT_CONTINUITY_HARD_HOLD.md), [1FS unsigned fingerprints](PHASE_1FS_M16_BOUNDED_UNSIGNED_AUDIT_FINGERPRINT_HARD_HOLD.md), [master completion plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
