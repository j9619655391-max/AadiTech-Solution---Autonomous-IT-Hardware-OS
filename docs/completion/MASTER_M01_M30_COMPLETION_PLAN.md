# Master completion plan — AadiTech IT Hardware OS (M01–M30)

**Source-of-truth code:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, branch `chore/phase0-foundation-20261106`, Draft PR #1 and Issue #2. **Assessment 17 November 2026:** partial internal engineering, production **HARD HOLD**. This document is a backlog and acceptance protocol, **not** a claim that all user-requested business modules have been built or verified.

The machine-readable state is [REMAINING_M01_M30_ACCEPTANCE_LEDGER.json](./REMAINING_M01_M30_ACCEPTANCE_LEDGER.json), checked by `scripts/project-completion-preflight.mjs --ci-hold` and `tests/master-completion-ledger.test.mjs`. These checks validate honesty/completeness of the register; they cannot attest that external services or real business transactions work. Do not use `database/schema.sql` for deployment or migration; it contains destructive legacy statements.

## Immediate fixes already applied in this development pass

- Executive dashboard no longer invents revenue/profit/stock/receivables, GST compliance, autonomous bookings, verified Telegram sends or AI answers on service failure. Approved quotations are not invoices; browser catalog valuations are not stock title.
- Finance screen now treats credit exposure as **simulation**, blocks automatic credit approval/release, and removes fictional bank account, GST ITC, financial income and receivables. Owner-entered company identifiers remain **UNVERIFIED** until authoritative validation.
- Customer-facing portal no longer impersonates invented customers or offers real e-sign without authenticated scoped accounts. Partner deal lock and commission disbursement are held.
- Logistics view no longer generates fictitious carrier AWB/e-Way bill, work order/RMA IDs or authorizes delivery/warehouse/technician status changes.
- **Crucially**, parent `src/App.tsx` business mutation callbacks now reject illegal customer-acceptance, PAID/DISPATCHED, fulfillment, warranty renewal sends, integration CONNECTED, workflow execution, disbursement and RMA/WO transitions even if a future child UI bypasses a disabled button. Denial is not a substitute for a future server-authoritative workflow.
- New CI regression suite `tests/legacy-operational-truth.test.ts` makes these false-success regressions explicit; new master M01–M30 ledger and preflight ensure every unapproved workstream remains held.

## Follow-up Phase 1BH internal hardening — 2026-11-17

[Detailed Phase 1BH security acceptance notes](../phase-1/PHASE_1BH_BUSINESS_SOURCE_TRUTH_AND_EXTERNAL_HOLD.md) document the *next* deny-only fixes. The parent `App.tsx` can no longer produce an internally `APPROVED` fake commercial quote, `ISSUED` PO, serialized inward evidence, supplier RFQ broadcast or AI/KYC onboarding audit from browser-local callbacks. BOM keyword compatibility never equals OEM `PASSED` and the browser commercial quote button is disabled. Customer-facing SLA/OEM/DOA RAG answers, simulated API HTTP 200, provider status toggles, tenant context switches, successful DLQ retries, stock liquidation, agent sends and legacy procurement buttons no longer assert verified or executed effects. Regression suite: `tests/remaining-business-truth.test.ts` plus `tests/ai-business-truth.test.ts`.

**This phase does not supply actual server-backed replacements, legal authority, provider keys or real executed business transactions.** All 30 acceptance workstreams remain `HOLD`.

## Workstream inventory and missing evidence

### Internal foundations (M01–M12)

Some MySQL-backed auth, CRM, quote, supplier and stock proof controls exist. They are held evidence foundations, not a saleable or posted stock ledger.

| Track | Module | Current engineering class | Still-required acceptance | 
|---|---|---|---|
| M01 | Identity and session security | `SERVER_INTERNAL_HELD` | Read-only external penetration test, verified staging TLS, deployment signoff |
| M02 | MFA, privileged owner and reviewer lifecycle | `SERVER_INTERNAL_HELD` | Real hardware/mobile authenticator enrollment and independent recovery exercise |
| M03 | CRM contacts, customer master and leads | `SERVER_INTERNAL_HELD` | Complete tenant/object scope, data reconciliation and authorized customer migration |
| M04 | Quote draft, revisions, price reviews | `SERVER_INTERNAL_HELD` | Verified supplier SKU/HSN/GST costs, independent approvals and customer issuance |
| M05 | Commercial pricing and GST e-invoicing | `LEGACY_PREVIEW_ONLY` | Official invoice, IRN, GST returns/ITC and accounting authority |
| M06 | Inventory site/opening count foundations | `SERVER_INTERNAL_HELD` | Verified stock title, reconciliation, serial tracking, true sellable balances |
| M07 | Inbound quarantine and serial/lot custody | `SERVER_INTERNAL_HELD` | Supplier evidence, authority, inspection, official GRN and stock acceptance |
| M08 | Supplier registry and purchase requisitions | `SERVER_INTERNAL_HELD` | External vendor legal verification, price quotes, signoff, supplier onboarding |
| M09 | Purchase-order dispatch and message outbox | `SERVER_INTERNAL_HELD` | Consented authorized supplier endpoints, delivery receipts, dedupe and dispatch release |
| M10 | Supplier acknowledgment and GRN evidence | `SERVER_INTERNAL_HELD` | Official supplier response, warehouse receipt, independent signature validation |
| M11 | Available-to-sell stock planning | `SERVER_INTERNAL_HELD` | Physical-to-ledger reconciliation and authorized stock release transactions |
| M12 | Inventory valuation and financial journal posting | `SERVER_INTERNAL_HELD` | Authorized accounting posting, COGS proof, reversal and audit acceptance |

### Sales, service and financial workflows (M13–M20)

Legacy/browser-only views cannot issue customer orders, invoices, commission disbursements or physical/financial movements. New server APIs and reconciled data are still required.

| Track | Module | Current engineering class | Still-required acceptance | 
|---|---|---|---|
| M13 | Sales orders, shipment and carrier tracking | `LEGACY_PREVIEW_ONLY` | Server-issued sales order, carrier account, AWB and verified delivery events |
| M14 | Customer payments, receivables and bank reconciliation | `LEGACY_PREVIEW_ONLY` | Verified bank mandate, payment gateway and immutable settlement journal |
| M15 | Warranty and serial title verification | `LEGACY_PREVIEW_ONLY` | OEM entitlement/serial registry and authorized warranty claim validation |
| M16 | AMC renewals and service tickets | `LEGACY_PREVIEW_ONLY` | Service contracts, ticket RBAC, customer consent and approved renewal sends |
| M17 | Field service work orders and RMA | `LEGACY_PREVIEW_ONLY` | Technician identity, customer e-sign, proof of repair and replacement approval |
| M18 | Verified customer self-service portal | `LEGACY_PREVIEW_ONLY` | Customer SSO, BOLA/IDOR, scoped issued records and verifiable e-sign |
| M19 | Reseller registration and price protection | `LEGACY_PREVIEW_ONLY` | Legal partner registration and enforceable reviewed price lock, not browser only |
| M20 | Commission accrual and actual bank payout | `LEGACY_PREVIEW_ONLY` | Actual revenue ledger, tax withholding and multi-person payment authorization |

### AI, integration and migration (M21–M26)

Outbound consent/delivery, agent authorization, model/evaluation evidence, reliable workers, RAG ingestion and legacy data reconciliation are not complete.

| Track | Module | Current engineering class | Still-required acceptance | 
|---|---|---|---|
| M21 | Consent-based campaigns, WhatsApp and email | `LEGACY_PREVIEW_ONLY` | Verified contacts/consent, opt-out, approved provider send receipts and retries |
| M22 | Agent and AI business command execution | `INTERNAL_DENY_ONLY` | Authoritative tool/data scoping, evals, safety RBAC and approved external actions |
| M23 | Forecasting, analytics and next-best-actions | `LEGACY_PREVIEW_ONLY` | Measured history, model validation, no fabricated figures and approved action gate |
| M24 | Workflow, event bus and background jobs | `LEGACY_PREVIEW_ONLY` | Durable outbox/queue, idempotent worker, retries, monitoring and audit proof |
| M25 | Retrieval augmented knowledge and document governance | `LEGACY_PREVIEW_ONLY` | Verified source rights, ingestion checks, role-scoped search and retrieval controls |
| M26 | Legacy browser-data migration and secure imports | `INTERNAL_HELD` | Data mapping and reconciled non-destructive server import with owner authorization |

### Real provider and release acceptance (M27–M30)

Public vendor docs and self-supplied signed fixtures are NOT a provider agreement, independently authenticated issuer, legal signatory, real WORM or genuinely witnessed DR.

| Track | Module | Current engineering class | Still-required acceptance | 
|---|---|---|---|
| M27 | Provider company identity and supplier legal onboarding | `INTERNAL_HELD` | Signed provider agreement, MCA company/director/signatory and approved sandbox credentials |
| M28 | PKI witnesses, revocation CRL/OCSP and key rotation | `INTERNAL_UNTRUSTED_PROOFS` | Named external issuer, independently authenticated RCAI/CCA/eMudhra trust and live signed CRL/OCSP |
| M29 | Object Lock, encrypted backup/DR and infrastructure | `INTERNAL_HELD` | Real provider Object Lock denial and independently witnessed isolated encrypted restore/RTO/RPO |
| M30 | Release authorization, third-party security review and operations | `INTERNAL_HELD` | Independent source/build and staging attestation, owner/security/operations signoff and legal release |

## Acceptance contract for *every* module

For each M01–M30: (1) named business and technical owner with authenticated source record, (2) specified use cases/empty/error/loading states, (3) versioned non-destructive MySQL migrations and reconciled legacy-data mapping, (4) server-side RBAC and per-object tenant/owner authorization, input/CSRF/file/secret protection and audit, (5) approved exact business rules with idempotency and concurrency/rollback tests, (6) actual customer/supplier/gateway integrations gated by consent, policy, provider quota and delivery acknowledgments, (7) unit plus real disposable MySQL plus browser/E2E and approved isolated staging evidence, (8) independently observed recovery with measured RTO/RPO, documented rollback, monitoring/alerts and incident duties, (9) genuine legal/provider approval where applicable, and (10) dated independent SECURITY / OPERATIONS / OWNER signoffs. A synthetic fixture or CI assertion does not satisfy any external clause.

Owners, reviewer identities, legal agreements, secrets, current CRL/OCSP chains, cloud WORM provider account, real stage DNS/IP, and DR observers **have not been independently authenticated by this repository work**. Do not mark a field complete without a verifiable source pointer, timestamp, signer authority, audit trace and approval. Collect private credentials via approved secret manager—**never in chat, issues, Git or artifacts**.

## Engineering work order (safe defaults)

1. **P0 business truth and security guardrails:** keep the above browser-only false-success routes deny-only. Audit remaining legacy components for claims of PAID/APPROVED/SENT/VERIFIED and add regression tests. Fix auth/CSRF/BOLA/IDOR and route authorization prior to any external effects. This is a safety dependency for all later phases, not production GO.
2. **P1 authoritative transactions:** CRM source migration → pricing/SKU/vendor evidence → quote review/step-up MFA/customer issue → supplier PO/acknowledgment/GRN → verified warehouse title and stock ledger → invoices/payment/COGS/journal posting. Each transaction requires independent signatures and reconciliation, never a direct browser callback.
3. **P2 customer operations:** authorized orders, carrier API/AWB/e-way IRN, warranty/AMC, RMA and work-order signature evidence, customer account scoping, reseller price protection and commission financial approval.
4. **P3 agent/integrations:** consent and opt-out, provider sandboxes, delivery receipts, durable outbox and dead-letter retries, role-scoped AI/RAG and forecasting evaluation with real source data; no autonomous sending by default.
5. **P4 independent trust/infra:** provider-signed agreement and lawful KYC, out-of-band SPKI and live CRL/OCSP, real Object Lock delete/overwrite denial, KMS and encrypted independent isolated restore. A release decision needs actual named operators, dated evidence and independent signoff.
6. **P5 production release (future, not available):** only after all M01–M30 evidence is evaluated, critical/high/unknown advisories resolved, CI + approved real staging E2E/DR passed and explicit owner/security/operations/legal signoff. Keep the current draft PR unmerged; maintain all outbound/stock/finance dispatch gates HOLD until separately authorized.

## Exact current release decision

`productionReleaseAuthorized = false` · `productionReleaseBlocked = true` · `releaseDecision = HOLD`.

Internal CI proves only that the current tested implementation and safeguards execute; it is not a third-party security audit or independent WORM/DR certificate. **Do not describe completion of all modules or full production readiness as achieved.**
