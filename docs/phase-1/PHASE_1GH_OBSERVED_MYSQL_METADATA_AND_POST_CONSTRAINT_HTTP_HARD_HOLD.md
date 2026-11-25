# Phase 1GH — Observed MySQL metadata and post-constraint HTTP compatibility (HARD HOLD)

24 November 2026 IST. Phase 1GG exact PR run 45451176514 on 3957bd8494de7b9c5e44980148f190dd91730724 FAILED (7/8). The bounded diagnostic now shows MySQL 8.0.46 returns a generated expression with outer parentheses, backtick-delimited identifiers and a UTF-8 introducer with literal backslashes preceding both quote delimiters around CREATE. Type char(36), STORED GENERATED, nullable YES, utf8mb4_unicode_ci all match. This is observed evidence, not inferred metadata.

The corrective parser accepts the exact observed representation plus narrowly specified equivalent formatting, paired comparison parentheses, explicit/implicit NULL ELSE, exact literal bytes and identifier tokens. It rejects altered operation values, malformed escaping, quoted identifiers with embedded spaces, altered branches and additional predicates. Added exact observed-expression unit regression and negative variants. Original 0051 migration SQL bytes unchanged. Bounded trigger readback diagnostics remain disposable CI-only.

CI now reruns the real restricted-account HTTP fixture AFTER applying 0051, checksum rerun and SQL race tests. Before 0051 the existing legacy corruption/quarantine cases remain mandatory; after 0051 the fixture checks installed constraints, refuses a fresh install over existing artifacts, expects SQL duplicate CREATE and identical quote-pointer reassignment to fail, and preserves CRM create/patch/soft-delete, quote create/replay/revision, M16/M17 held flows, OWNER lock/role disable and raw-auth/destructive privilege denial. The flag must match the actual migration ledger, not merely an assumption. No test skips either security boundary. Exact-head hosted execution pending.

The initial unauthorized first CREATE / first same-owner binding boundary remains unresolved. No trusted independent issuer is provisioned, no staging or production migration, no real customer/supplier/provider action. All M01–M30 external acceptance and independent DBA restore/custody remain OPEN. Production HARD HOLD.


## Verified hosted receipt

Exact Draft PR run 45452881328 on 110738c27111585b5f4097519748280bfe5c7cd0 completed SUCCESS 8/8, including MySQL steps 146–150 (0051 apply/rerun, restricted SQL races, post-constraint restricted HTTP, readiness preflight). This is disposable CI verification only, not staging or production acceptance.
