# Phase 1GT — Encrypted authority schema restore batch (HARD HOLD)

25 November 2026 IST. 1GS exact Draft PR 45488593104 on 873ece82c601c95e6956c7a81375abde850324b9 SUCCESS 8/8, baseline GR/GS manifest regressions and GN–GS MySQL subtest 7 passed, provenanceIntegrity PASS. No separate push receipt observed. Prior GR typecheck defects resolved by GS.

1GT adds bounded AES-256-GCM logical row artifact, random 96-bit IV and ephemeral 256-bit key, manifest and schema digest authenticated as AAD. Writes mode-0600 ciphertext to a temporary local file, reads and authenticates before import, rejects tamper/truncation/wrong key or context, cleans artifact and zeroes local key buffer. No secrets or plaintext backup artifact committed. CI-only source must actually select aaditech_ci. New randomly named disposable schema restores seven authority tables from fixture SHOW CREATE TABLE metadata, foreign keys/check constraints included, then installs 22 triggers and five routines from checked-in sources after loading rows. Compares signed data and schema digests, exercises restored receipt/nonce/key deletion denial, FK and cross-table nonce replay denial. Checks source unchanged. Schema V2 binds FK actions and CHECK clauses; local FK schema name normalized only for same-schema references. Unit and hosted regression source added.

Limits: seven authority tables only; business/auth tables and full application schema not restored, so restored routine definitions are compared but runtime business consumption in restored schema not exercised. DDL sourced from fixture, not persisted in encrypted row artifact; not a portable standalone backup. No independent signer, durable external key storage, independently verified schema baseline, offsite/WORM, actual staging recovery, full business/audit/quote content, app adoption or external acceptance. Schema capture requires quiescent metadata. Ephemeral synthetic keys only. Actual execution pending exact-head CI; no production changes. 0051 unchanged. Production HARD HOLD.


## Verified hosted failure receipt and correction

Exact Draft PR 45491355617 on 34ac2ab78f6aadeef1428d696f92098596df5653 FAILED 6/8. Baseline TS1005 unescaped LOCAL string in schema metadata query; MySQL integration failed transform before combined test. 1GU corrects literal source; encrypted restore remains unverified. 1GS earlier successful 8/8 unchanged.
