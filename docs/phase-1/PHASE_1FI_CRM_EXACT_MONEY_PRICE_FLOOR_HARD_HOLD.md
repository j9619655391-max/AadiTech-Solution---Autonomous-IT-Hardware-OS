# Phase 1FI — exact-decimal CRM price floor; M03/M04 internal only (HARD HOLD)

Date: 24 November 2026 IST. Development branch `chore/phase0-foundation-20261106`, Draft PR #1. This is a **real server-side business data-integrity correction** rather than an external procurement/quote approval. No live supplier, customer, stock, payment or invoice actions are authorized.

## Concrete defect

`crm_products.minPrice` and `sellingPrice` use MySQL `DECIMAL(18,2)`. Both initial HTTP product validation (`server/crm/validation.ts`) and the server-side, row-locked partial product UPDATE (`server/crm/repository.ts`) previously compared prices using `Number(min) > Number(sell)`. That silently rounds nearby valid decimal values outside JavaScript's exact binary64 integer limit.

Example: `minPrice=9007199254740992.01`, `sellingPrice=9007199254740992.00`. Both can round to the same JavaScript Number, so the minimum-price guard could allow a price one paisa below the floor. This is an M03 catalog-integrity and M04 quote-snapshot input issue. Existing quote draft creation independently uses integer paise and rejects selling prices beneath floor, but that **does not repair invalid persisted CRM master data**.

## Narrow implementation

- `server/crm/validation.ts` exports `crmMoneyPaise` and `isMinPriceAboveSellingPrice`. The parser accepts only **nonnegative canonical decimal strings**, max 16 whole digits and up to two fractional digits, and converts exactly to `bigint` paise; never uses float/Number in price-floor comparisons. The existing strict HTTP validation normalizes accepted money to two decimal places, and continues denying unknown/inventory-balance fields.
- `validate('products', ...)` applies exact comparisons when both prices are supplied, including initial product creation.
- `server/crm/repository.ts` applies the **same exact paise rule** when product PATCH updates only one side of the price floor, comparing the proposed price with the existing stored MySQL DECIMAL value under its already-required active-OWNER and CRM row locks. Violations return version-style **409 conflict** and roll back, without mutating CRM or appending an UPDATE audit event. A valid equal-floor price remains permitted. No added migrations, unchecked SKU scopes, external dispatch or balance changes.
- `tests/crm-validation.test.ts` exercises `9007199254740992.01` versus `9007199254740992.00`, equal price, fractional normalization, upper `DECIMAL(18,2)` range and invalid decimal formats/types.
- `tests/crm-mysql.integration.ts` exercises **actual disposable MySQL and HTTP API**: reject under-floor CREATE, permit valid near-limit create, reject independent PATCH mutations to both `minPrice` and `sellingPrice`, preserve original fields/version/audit on conflicts, then allow exact equal-floor PATCH and reject a stale version. This is already executed by `bun run test:mysql` in the existing GitHub Actions MySQL job; unit tests run in baseline. No production data is touched.

## Unresolved acceptance

- This change only protects the catalog boundary and transactions through this repository. DB administrators, unreviewed direct SQL or imported historical rows can still introduce bad records; the code does not rewrite historical prices or attest independent DB controls.
- The quote engine uses separate `server/quotes/money.ts` integer paise checks with a **narrower** admitted price range for per-line arithmetic. A catalog product at the full MySQL `DECIMAL(18,2)` upper range can remain an internal catalog record but **cannot automatically become a quote** until the independent quoted totals/range requirements pass. No bypass or silent conversion to a quote is allowed.
- Global SKU uniqueness, historical author-creation provenance, verified corporate tenancy/ownership, supplier SKU/HSN/GST records, independent margin approvals and actual customer issuance still require M03/M04 acceptance and migration reconciliation.
- Production runtime service versus privileged auth/DBA account separation, independent TLS staging and real user/browser acceptance remain OPEN, as do M05–M30 external real business journeys, legal mandates, eMudhra/CCA/RCAI trust, revocation, provenance, WORM/CAS, encrypted DR and independent reviews.

## CI/evidence gate

Record exact latest HEAD push + Draft PR workflow results, especially baseline TypeScript/unit suite and `Run real MySQL integration tests`. Preserve historical intermediate failed runs. A passing CI receipt proves only the disposable fixture; **no independent staging, customer consent, corporate authority, external account or release signoff**.

**HARD HOLD:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. Main remains unchanged, PR #1 stays Draft/unmerged, Issue #2 remains OPEN. Do not perform live deployment/migrations, customer/supplier dispatch, official quotation/PO/GRN, stock posting, financial/tax posting or provider onboarding.
