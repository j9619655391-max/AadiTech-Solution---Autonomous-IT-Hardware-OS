# Phase 1BJ — Fail-closed held commercial snapshot integrity hardening

**Date:** 2026-11-17 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development branch:** `chore/phase0-foundation-20261106`  
**Release:** HARD HOLD — `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Audit finding

Phase 1BI owner readback covered money, reviewer and core held-line bindings, but the quote snapshot comparison did **not** check every creator-owned product/HSN/GST/tax field. A stored held snapshot could be changed in omitted columns (for example an HSN or line GST estimate) without triggering the per-line binding anomaly. Held quote and purchase-order envelopes also did not reject unexpected metadata fields, potentially allowing a visually misleading `recipientEmail`, `dispatchEnabled` or authority claim in an otherwise held payload. The procurement snapshot exposed supplier code/name text without reconciling those fields to the current internal supplier row. These are integrity detection gaps, **not evidence of external-origin forgery or an actual dispatch**.

## Engineering controls

1. `server/commercialIntegrity/checks.ts` now requires the precise internal envelope field set for held quotes (including `leadId`, `currency=INR`) and POs (including supplier code/name), rejecting additional undeclared fields instead of silently accepting shadow actions or actors.
2. On held quote readback, **all ten creator-owned line attributes** are compared to the original or revision source, preserving revision-specific key mappings and requiring matching product, SKU, name, HSN, quantity, cost, price, GST rate, subtotal and tax estimate. Unexpected line keys fail closed; line order and count remain checked. This does not re-price or certify the applicant's source SKU.
3. PO held-line readback similarly rejects shadow fields. The owner query adds internally stored supplier `code` and `legal_name` so the held snapshot cannot silently substitute a supplier display identity.
4. Quote owner readback now detects more than one matching internal review (LIMIT 2) and emits `DUPLICATE_QUOTE_REVIEW`, rather than trusting an arbitrary single row. Existing duplicate preparation and procurement reviewer/hold checks remain.
5. Regression coverage: `tests/bi-commercial-integrity.test.ts` for field-by-field quote tamper, revision HSN, extra shadow dispatch/recipient claims and PO supplier label attacks; `tests/crm-mysql.integration.ts` for live disposable-MySQL held JSON modification, owner readback denial and restoration.
6. No migrations or new supplier/customer message dispatch worker were introduced. Existing MFA, password step-up, CSRF, owner BOLA checks, disabled outbox, and draft-PR release gate remain unchanged.

## Limitations and prerequisites

- All stored values, reviews, signer IDs and supplier labels remain **application-controlled internal MySQL data**. Detection of mismatched values is not proof of genuine supplier quote, negotiated price, GST/HSN correctness, legal authorization or a signed customer quotation.
- The persisted SHA-256 digest is not an independently signed or immutable WORM receipt. The validator intentionally does not interpret a matching locally supplied digest as external attestational authority. An administrator with power to replace *all* related database objects can evade cross-record comparisons; independent source authentication, anti-equivocation publication, provider Object Lock and signed custody remain blocked.
- No approved eMudhra/RCAI/CCA issuer chain, authenticated live CRL/OCSP, MCA corporate/signatory verification, vendor contract, cloud negative delete test, verified encrypted isolated restore or independent release signoff has been provided in this phase.
- This implementation requires the development HEAD's complete baseline and disposable MySQL CI to be **green before claiming verified engineering completion**. CI pass remains an internal engineering result only; any test failure must be reported and corrected, not relabeled.
- No production deployment, external supplier PO, customer quote dispatch, GRN, stock posting, invoice, bank transfer or finance posting is authorized.

**GitHub governance:** PR #1 must remain Draft/unmerged, Issue #2 open, `main` unchanged. Independent security, operations, legal and owner acceptance stays pending. Never put approved provider credentials or certificates' secret keys into GitHub comments, code or chat.
