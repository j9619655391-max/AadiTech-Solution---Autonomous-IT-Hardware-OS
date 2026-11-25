# Phase 1BK — Historical quotation lineage and anti-rollback consistency: HARD HOLD

**Date:** 2026-11-17 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Decision:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Precisely scoped audit finding

Phase 1BJ verified the **latest** internal quote revision/review/held preparation and all line fields, but a historical held quote or review from an earlier revision could remain compromised while the current revision appeared coherent. For example, adding an unreviewed revision after a previous held approval made the owner-side inspection ignore the older held snapshot. Current-only queries did not detect revision-number gaps, orphaned old review decisions, a missing held outbox or older, untrusted snapshot hash changes.

## Implementation

- `server/commercialIntegrity/quoteHistory.ts`: pure deterministic **internal MySQL historical consistency** inspector. Walks original revision zero and all stored sequential revisions, checks missing numbers, duplicates, review/revision and hold-to-review references, reviewer segregation and valid reason/override policy, per-revision source money and tax re-evaluation, exact line-key constraints, all previously held snapshot scopes and disabled outbox. It cannot turn an internal approval into an issued quotation.
- For each held version it reconstructs the **writer's deterministic JSON field order** using the stored original/revision values and compares the SHA-256 output with both locally persisted hold/outbox digest fields. This avoids mistakenly hashing MySQL's normalized JSON key order. A digest mismatch is an internal anomaly; a matching locally stored digest is **not** an independently authenticated signature, immutable storage receipt or proof against a privileged DB attacker rewriting all related objects.
- `server/commercialIntegrity/ownerRouter.ts` uses the existing owner session and privileged MFA, owner-scoped parent row lock and transaction. It reads *bounded* revision/review/hold histories (maximum 1000 inspected revisions; extra rows result in `HISTORY_INSPECTION_BOUND_EXCEEDED`), refuses orphan/duplicate reviews, missing or duplicate outbox rows, previous stale held-scope changes and invalid revision arithmetic; its response publishes only aggregate counts and anomaly codes, not customer contacts or supplier payment data. All outcomes continue to assert production HOLD and no independent rollback anchor.
- Current snapshot still uses the Phase 1BI/1BJ inspector; combined `localScopeConsistent` requires **both** current and entire bounded historical readback to pass. `historyConsistent`, `historyInspectionComplete`, revision/review/held counts, `historyAnomalyCodes`, `independentHistoricalAnchorVerified=false` and `independentRollbackProofVerified=false` are separate explicit fields.
- `tests/bk-quote-history.test.ts` tests benign old hold + later revision, unauthorized historical changes, revision gaps/forks, missing outbox, orphan/duplicate reviews/holds, exact line tax math, digest substitution and inspection bounds. `tests/crm-mysql.integration.ts` uses the actual disposable MySQL schema with authenticated HTTP owner inspection, fresh unreviewed version, historical JSON HSN forgery, stored revision tax alteration and revision-number gap, and verifies restoration.
- **No new migration**, production workflow, outbound worker, email, invoice, stock posting, supplier ordering or credentials; all previous role/CSRF/MFA and migration checksum checks remain.

## Explicit anti-rollback limitation

Contiguous revision numbers and locally reproduced SHA-256 checks detect **inconsistency** but **cannot establish completeness** if an administrator removes or rewrites a consistent tail of revisions and all associated rows. An external independently published, authenticated monotonic commitment, trusted key custody, real WORM provider delete/overwrite denial, authenticated CRL/OCSP and a separately witnessed DR restore would be required for meaningful independent rollback proof. A synthetic witness fixture does **not** close that gap. No legal MCA/GST customer identity, supplier origin/price/HSN proof, real customer quotation delivery or independent provider authority is established here.

## Acceptance boundary

This phase's internal engineering can be marked validated only after **the exact pushed HEAD** has both GitHub Actions baseline and isolated disposable-MySQL integration jobs completed successfully. Red CI stays red until the code or test issue is corrected and rerun. Production governance remains PR #1 Draft/unmerged, Issue #2 open, `main` unchanged, no production deployment or irreversible business action. Legal, OWNER, SECURITY and OPERATIONS independent acceptance remains pending. Never provide provider credentials or private signing keys in chat, issues or source control.
