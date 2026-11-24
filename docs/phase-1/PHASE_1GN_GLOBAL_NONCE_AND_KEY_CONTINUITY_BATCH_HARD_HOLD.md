# Phase 1GN — Global nonce and issuer key continuity batch (HARD HOLD)

1GM exact Draft PR run 45462587791 on b91f08bbaaa6e00b5dba2121a385aeb1050e864d SUCCESS 8/8. Hosted baseline logs show all three GM verifier tests passed; MySQL logs show quote/customer/lead/product signed issuance subtests and provenanceIntegrity PASS. Separate push CI not observed.

1GN adds disposable CI-only shared nonce registry and four AFTER INSERT triggers for the GJ/GK/GL intent tables. Each insertion reserves the same global primary-key namespace, even when a synthetic issuer bypasses the GM verifier and issues raw SQL. Reservation and intent insertion are atomic: same/cross-table reuse fails, concurrent contenders have at most one committed winner, rolled-back issuance releases the reservation. Registry direct SELECT/INSERT/UPDATE/DELETE denied to issuer and runtime in the fixture; malformed noncanonical nonce rejected. No automatic expiry deletion or reuse policy. Tests install all four candidate tables plus registry and triggers together (no consuming routines installed in this particular test); other existing tests retain individual consumption workflows. Source custody inventory updated; 0051 bytes unchanged.

The GM verifier library adds a pinned snapshot continuity validator: unique IDs and SPKI fingerprints, actual Ed25519 SPKI verification, immutable previous identity/interval/scope, irreversible revocation, no removed prior key, no backdated newly introduced key. Tests exercise legitimate rollover/revocation and malicious replacement/reactivation/scope/interval changes. This is structural continuity of independently supplied snapshots, not authenticated registry enrollment; no persistent key lifecycle store or signed snapshot trust established.

Limitations: isolated CI source only, exact-head CI pending. Shared registry is not installed in the existing application or staging, and the GM issuer adapter is not forced to use it outside the integrated fixture. The raw INSERT issuer can still mint arbitrary fresh nonces/payloads, and signatures are not enforced by SQL. Independent key custody, non-bypassable issuer, authenticated rollover/revocation publication, consumption-time revocation, combined issuance/consume tests with registry installed, session revocation/deadlock and restore tests, quote content verification, actual DBA and external business/legal acceptance remain OPEN. No production release.


## Verified hosted receipt

Exact Draft PR 45463561713 on f0de7c513ee3e65401a82154dd0bfb05dcda8670 completed SUCCESS 8/8. Hosted rollover unit test and shared nonce MySQL race/rollback tests passed, provenanceIntegrity PASS. Isolated disposable CI only.
