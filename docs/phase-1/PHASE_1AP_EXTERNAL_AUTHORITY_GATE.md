# Phase 1AP — Provider-authorized sandbox access and genuine external evidence: RELEASE HOLD

**Date:** 2026-11-13. **Branch:** chore/phase0-foundation-20261106. **Production:** HOLD. The engineering change provides only SHA-only offline administrative inventory, not trusted enrollment.

## Source-of-truth and explicit non-authorization

CCA publicly lists eMudhra as a licensed CA: https://cca.gov.in/CAServicesPublic.html . CCA's eMudhra disclosure page https://cca.gov.in/e_mudhra.html currently identifies **CPS v4.2.1**, whereas the Phase 1AO runbook cites historical v4.2.0. Independent reviewers must validate the currently applicable provider-signed CPS and correct certificate policy OIDs. RCAI is the source for CA-public-key authentication: https://cca.gov.in/rcai.html .

emCA product documentation (https://emca.emudhra.com/integrating-emca/rest-api-support/certificate-management) describes an application registration, allowlisted source IP, ClientID, HTTPS and JWT credential flow. This public product documentation does **not** establish that this application's proposed supplier/warehouse use is covered by emCA, the licensed Indian DSC CA, or a service-specific eMudhra sandbox grant. Never infer contract, API tenancy, onboarding approval or signatory authority from public websites.

As of this phase there is **no genuine signed provider agreement, approved application credential, independently authenticated RCAI/eMudhra CA chain, provider-authenticated CRL/OCSP responder, genuine MCA corporate registry attestation or legal delegation** supplied to the application. No external vendor, MCA service, supplier or warehouse was contacted.

## Actual engineering scope

1. A strict SHA-only claims-inventory library (scripts/lib/providerAuthorityPreflight.mjs) requires 10 distinct artifact fingerprint categories and 6 distinct independent-review fingerprint categories. It checks schema/version, fixed evaluation-only provider and sandbox scope, canonical SHA-256 shapes, absent/unexpected values and deterministic inventory digest. It rejects raw documents, private keys, secrets, arbitrary status flags and unauthorized service scopes. A hash is **not** a signature, verified document, legally authenticated signatory or licensed issuer.
2. A read-only CLI (scripts/provider-authority-preflight.mjs) emits a HARD HOLD snapshot by default. Private offline SHA-only packet review is allowed only with PHASE_1AP_OFFLINE_INSPECTION_APPROVED=YES, no production/CI execution and an absolute, small regular-file packet stored **outside the Git checkout**. It never prints the supplied packet, hashes, path or personal data. It performs no network or database action.
3. Negative tests (tests/provider-authority-preflight.test.mjs) prove that fully populated synthetic evidence still never promotes sandbox authorization, CA trust, MCA validity, revocation trust, real GRN, stock, or production release. Unexpected keys including API tokens and activation switches fail closed. CI calls the read-only HARD HOLD check.
4. Existing Phase 1AO readiness reports additional explicit Phase 1AP hard-false flags. No operational provider API route, real credential access, purchase order issuance, stock reservation, inventory posting, approval override or financial operation was added. No new SQL migration: **27 checksum-registered migrations** and the existing **32-file release-candidate hash manifest** remain unchanged.

## Verification and accountable external prerequisites

| External item | Independent acceptance and evidence | Present state |
|---|---|---|
| Signed provider agreement & exact sandbox product entitlement | LEGAL validates executed signatures, legal entity, authorized countersignatories, application, allowable endpoints, source IPs, scope, data rights and term. SECURITY separately confirms through known-good official provider channels. | PENDING |
| API/service credentials | SECURITY binds approved secrets manager to isolated workload identity with least-privilege, service scope, TLS, credential expiry/rotation, emergency revocation and no logs; **no credential in chat, Git, application JSON, browser or CI fixtures**. | NOT PROVISIONED |
| RCAI/eMudhra PKIX authority | Out-of-band source-authenticated RCAI anchor, whole CA/sub-CA and subscriber chain, correct CP/CPS/OID, key usage, EKU, identity, issuer, name and current validity with RFC 5280 strict-policy checks. | PENDING |
| Signed revocation evidence | Authentic CRL publisher and OCSP responder/delegation, live issuer+serial binding, responder trust, freshness, rollover, revoked/unknown/stale/outage fail-closed tests. Synthetic offline CRL/OCSP cannot pass this gate. | PENDING |
| MCA registration and legal signer authority | Verified primary-source CIN/LLPIN/company record, up-to-date legal representative and delegation/power of attorney, scope, signatures and expiration. Keep sensitive identity evidence in controlled store. | PENDING |
| Supplier acknowledgment, physical GRN and stock | Real supplier/warehouse identities and signed PO ACK/physical receipt, serial/lot custody, no-negative stock ledger, independent operations/finance approval. | DISABLED |
| Production release | Independently approved staging isolation/TLS/MySQL, signed logs, secrets-manager controls, backup+measured restore, legal/security/ops/owner sign-off. | HOLD |

The signed agreement, authentic MCA extracts, KYC and personal records, actual certificates (where sensitive), tokens, JWTs, signing keys and API credentials must not be submitted in chat or checked into Git. Only allowed SHA-only private inventory can be locally reviewed. **Secrets are provided strictly via an approved secrets manager**, never manually pasted into a form or GitHub secret value copied from chat.

## Offline interface

Running "node scripts/provider-authority-preflight.mjs --ci-hold" always emits releaseDecision="HOLD" without reading secrets or requiring provider access. Private inspection only on an authorized nonproduction operator host:

    PHASE_1AP_OFFLINE_INSPECTION_APPROVED=YES node scripts/provider-authority-preflight.mjs --offline-packet /absolute/private/sha-only-packet.json

The packet needs schemaVersion=1, providerCode=EMUDHRA_CCA_EVALUATION_ONLY, requestedScope=SUPPLIER_WAREHOUSE_EVIDENCE_SANDBOX, and exact artifactDigests/reviewDigests keys exported by the library. Store packet outside the checkout; do not include actual documents, credentials, URLs containing access tokens or personal information. The checker is an **inventory validator**, not an external-authority verifier, irrespective of whether every claimed SHA is supplied.

## Explicit exit criteria (not yet fulfilled)

1. LEGAL obtains the executed provider agreement and verifies signatory authority and exact intended supplier/warehouse sandbox service.
2. SECURITY independently authenticates provider onboarding, root and issuer PKIX, current policies, signing certificate chain and authentic responder/publication sources.
3. SECURITY/infra provisions least-privilege sandbox credentials using an approved secrets manager and protected, isolated allowlisted TLS staging (no secret material in application tables or CI).
4. LEGAL/ops independently authenticates MCA company master data and legally binding delegation for actual supplier and warehouse signers.
5. Only with signed scope permission, conduct live provider-authorized positive and negative verification (revoked/expired/wrong issuer/wrong company/replay/rollover/outage) with signed evidence and responsible reviewer tickets. Never silently promote synthetic fixtures.
6. Full staging security/restore acceptance and separately recorded owner, legal, security and operations release decision are required before proposing any real external workflow or operational ledger/stock change.

**Mandatory:** Issue #2 remains OPEN; PR #1 remains DRAFT/unmerged; main unchanged. No Hostinger deployment, production migrations, supplier contact, real provider API calls, official GRN, inventory credit, financial posting, payments or production authorization is implied by this phase.
