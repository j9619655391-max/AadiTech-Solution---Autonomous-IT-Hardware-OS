# Phase 1GG — Corrective provenance metadata and interrupted-installation refusal (HARD HOLD)

Phase 1GF exact Draft PR run 45449749870 on a1371e72c485ded33d230ccd7d72a34f84d85fb9 completed FAILURE: seven other jobs passed, MySQL 8.0.46 failed after DDL at generated-column metadata verification. Chromium and earlier MySQL tests passed before the failure. The previous run is not a successful 0051 receipt.

1GG keeps migration 0051 SQL bytes unchanged. The generated-column verifier now uses a narrow expression grammar with accepted UTF-8 charset introducers, optional comparison parentheses and implicit/explicit NULL ELSE, preserving literal bytes. It additionally checks column type, size, nullability and collation. The actual hosted metadata representation was not printed by the failed run, so this is a candidate fix, not a confirmed root-cause diagnosis. Bounded generated-column metadata diagnostics are enabled only by the disposable CI migration CLI.

Before any fresh DDL, the runner now observes named indexes, generated column and quote-request trigger artifacts and refuses a partial/conflicting installation. It does not delete evidence, drop objects, restart a partially applied migration or waive the historical duplicate/foreign-pointer checks. Unit fixtures cover accepted formatting, changed operation/actor/else predicates, altered shape, missing/duplicate metadata and all three conflict queries/metadata failure. Exact-head hosted MySQL migration, rerun, restricted-principal tests and staging preflight still required.

Independent first-event provenance issuance and initial quote binding authority remain unresolved; an active OWNER lock with caller-supplied identity is not independently authenticated DB authority. Do not represent this increment as implementing that trust boundary. Independent historic-data reconciliation, DBA definer custody, tested restore, actual external legal/business acceptance and all release controls remain OPEN. No live migration, no production release.


## Observed follow-up

Exact PR run 45451176514 FAILED (7/8). Bounded diagnostic captured actual MySQL 8.0.46 outer parentheses and escaped literal delimiters with matching column shape. See [Phase 1GH correction and post-install HTTP verification](PHASE_1GH_OBSERVED_MYSQL_METADATA_AND_POST_CONSTRAINT_HTTP_HARD_HOLD.md). No successful migration receipt yet.
