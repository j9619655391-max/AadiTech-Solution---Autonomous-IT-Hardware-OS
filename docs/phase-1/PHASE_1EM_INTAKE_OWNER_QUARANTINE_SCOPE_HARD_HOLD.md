# Phase 1EM — OWNER-scoped intake custody and quarantine metadata: HARD HOLD

**22 Nov 2026 IST.** Canonical development branch `chore/phase0-foundation-20261106`, Draft PR #1, Issue #2 open, production release blocked.

## Confirmed problem

Previous intake `GET /api/intake/quarantine-summary` returned globally grouped physical quarantine witness records with warehouse codes, SKU, evidence counts, and cross-owner discrepancy information. Four global subqueries counted orphan evidence, quantity/line anomalies, expected serials and recorded serials. Log-in as OWNER was not enough to authorize another OWNER's stock evidence. Historic purchase requests referencing another supplier/site creator could also survive older procurement server fixes.

## Implemented route and SQL rules

1. Summary custody rows require **both** original observation actor `o.recorded_by=?` and physical site creator `i.created_by=?` bound to session OWNER. No client ownerId.
2. All four discrepancy aggregate subqueries join their own observation parent and filter `o.recorded_by=?`; stored serial query joins observation, not all global serial rows. Thus status and totals cannot leak foreign owners' discrepancies.
3. Intake `/eligible` joins purchase request, supplier and warehouse site and requires their creator matches the session. Observation list/detail require both original observation recorder and site creator.
4. Intake POST checks held PO, original request owner, supplier owner and site creator in one MySQL `FOR UPDATE` source query before claim creation, preserving serial uniqueness, held PO immutability and hash/idempotency boundaries. Foreign source is denied with transactional rollback and no idempotency reservation.
5. Unverified custody stays **unavailableToSell=null**, financial value null, external receipt not verified, no actual GRN or invoice. No schema changes, no historical data deleted/reassigned, no real outbound business transactions.

## Real MySQL regression and authority boundary

`tests/intake-mysql.integration.ts` now tests two distinct OWNER sessions and an unrelated REVIEWER. Fixture constructs a foreign private warehouse and independent internal quarantined observation with a deliberately inconsistent custody quantity. Authenticated first OWNER sees only own event and zero discrepancy, foreign OWNER sees only foreign event and own discrepancy, and neither can read the other's observation detail. Anonymous or REVIEWER access denied 401/403. A historical purchase request mutated to refer to a foreign site cannot appear in eligible list, cannot create an observation or claim an idempotency key. Existing MySQL witnessed serial/lot and duplicate-serial transaction tests must remain green.

Only exact-SHA push and PR GitHub-hosted CI, official Check/Job identity reconciliation, 0043 migration checksum and independent Chromium loopback can provide **internal test acceptance**. Those cannot prove real physical inventory, legal ownership, third-party corporate trust, financial/tax posting, provider licenses or staging signoff.

## Remaining external gates

First-class verified tenant membership, full route-by-route BOLA across reviewer/warehouse/dispatch/GRN/journals, historical CRM provenance reconciliation, real supplier delivery and receipts, customer pricing/dispatch with consent, MCA/CCA/RCAI/eMudhra signed trust and live CRL/OCSP, independent remote WORM/CAS/DR, protected main two-nonauthor reviews, signed CI and independent staging approvals all remain pending. Do not close Issue #2 based on this incremental internal route fix.

**Release invariant:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No merge, deploy, provider onboarding, supplier/customer outreach, PO/GRN, stock/finance/tax posting.
