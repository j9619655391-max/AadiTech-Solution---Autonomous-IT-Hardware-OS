# Phase 1AN — Named India CCA trust-provider shortlist, policy OID trial and corporate/signatory onboarding gates

**Date:** 2026-11-12 · **Branch:** `chore/phase0-foundation-20261106` · **Release:** PRODUCTION HOLD

## Scope and real-world evidence (not fabricated)

Phase 1AN nominates **eMudhra Limited / eMudhra CA** as a **named, India CCA-listed evaluation candidate**, NOT as an approved company vendor or operationally trusted issuer. The public [Controller of Certifying Authorities licensed-CA services](https://cca.gov.in/CAServicesPublic.html) explicitly lists eMudhra CA. CCA's [India PKI guidance](https://cca.gov.in/india_pki.html) explains licensed CA profiles, hierarchy and OID certificate-policy assurance. A CCA listing does not prove that eMudhra contracted to serve the user's supplier/warehouse workflows, has approved this application, issued an end-entity credential for the target company, or provided an approved API/credential, OCSP or CRL endpoint. No official provider enrollment has been performed.

Company references use the **Ministry of Corporate Affairs (MCA)** [public Company/LLP Master Data service](https://www.mca.gov.in/) as a **reference only**. The app does not contact MCA and has no access to legally attested corporate status, CIN validation, company records, actual delegated signatories or directors. A SHA-256 fingerprint of an owner-entered document is **not** a registry attestation. No raw KYC or private personnel documents are uploaded.

**No genuine external authority, approved provider sandbox credential, corporate identity KYC, signatory mandate, trusted policy OID or CRL/OCSP proof is available in this project.** Synthetic tests cannot establish them. The eMudhra CPS URL [CCA-hosted historical CPS](https://cca.gov.in/sites/files/pdf/Licensed-CA/eMudhra_4.1.0.pdf) is a reference to **confirm and update out of band**, not a verified current CPS or assurance of specific issuance profile.

### Desired future production prerequisites vs. delivered nonproduction controls

| Requirement | Phase 1AN delivery | Production evidence still missing |
|---|---|---|
| Named licensed CA shortlist | eMudhra CCA-listed candidate in fixed allowlist + internal due diligence ticket | Signed agreement, vendor authorization, confirmed product fit, official designated liaison |
| External root | Exact Phase 1AL separately configured root public key enforced for synthetic evidence | Independently obtained and authenticated licensed-CA root/pinned CA certificate hierarchy |
| Sandbox API credentials | `WAITING_EXTERNAL` access request *ticket only*, SQL ENUM `NOT_CONFIGURED` | Contract-backed sandbox API authorization, secret-manager handle, scoped tokens, legal data-sharing consent |
| Provider-specific CP/CPS | Document hash, source URL and requested policy OID; OpenSSL `-x509_strict -policy_check -explicit_policy` trial on Phase 1AM public certs | **Actual provider-approved policy OID**, signed/current CPS, complete supported PKIX chain, key usage/name/policy constraint validation |
| Revocation | Existing Phase 1AL locally root-signed cumulative list checked again in Phase 1AM readiness | **Authentic provider CRL/OCSP**, authoritative publisher, CA rollover, chain-specific serial revocation and freshness |
| Company + signatory | Original Phase 1AM claimed registration, MCA reference and separately hashed document claims, independent internal HELD inspection | Real MCA data or equivalent verified corporate registry evidence and provider-validated authorized legal signatory/power of attorney |
| Official GRN and stock posting | No integration or route; previous SQL HARD-ZERO protections remain | Independently authenticated real PO/ACK, physical supplier/warehouse GRN, serial title, valuation and separately authorized stock ledger |

## Additive migration 0026 — seven InnoDB tables

1. `inv_provider_named_nominations` — fixed provider code `EMUDHRA_INDIA_CCA` and fixed legal label `eMudhra Limited`, CCA official listing URL, owner, immutable internal ticket. `provider_contract=NOT_APPROVED`, `sandbox_credentials=NOT_PROVIDED`, `external_root_authenticated=NO`, `production_release=HOLD`. No trusted state is possible in ENUM.
2. `inv_provider_named_reviews` — one independent REVIEWER evaluation of CCA listing with explicit `contractMissingAcknowledged`. Positive `REVIEWED_CANDIDATE_HELD` remains internal candidate evaluation; negative `REJECTED_INTERNAL` irreversibly blocks subsequent reads.
3. `inv_provider_policy_proposals` — owner-selected **synthetic/test** certificate policy OID and SHA-256 of CPS document, source URL and exact linked independently reviewed Phase 1AM X.509 certificate. `PROFILE_HELD`, `full_certification_path=NOT_VALIDATED`, `trusted_crl_ocsp=NOT_VALIDATED`, `provider_policy_approved=NO`. One immutable per nomination/certificate.
4. `inv_provider_policy_reviews` — independent one-shot REVIEWER decision `REVIEWED_POLICY_HELD` or reject with explicit review of requested OID and missing trusted CRL/OCSP.
5. `inv_provider_registry_dossiers` — original claimed Phase 1AM registration and exact sandbox case, SHA-256 of allegedly obtained MCA master data and legal delegation documents, ticket and fixed MCA reference URL. `registry_authentication=UNVERIFIED`, `legal_signatory_authentication=UNVERIFIED` regardless of status.
6. `inv_provider_registry_reviews` — independent one-shot REVIEWER inspection of internal source evidence, positive `REVIEWED_CLAIM_HELD` or rejection, never legal KYC.
7. `inv_provider_sandbox_access_gates` — **request metadata only**; no API tokens or raw credentials. `secret_reference_status=NOT_CONFIGURED`, `provider_authorization=NOT_VERIFIED`, `live_test_access=DISABLED`, `production_release=HOLD`.

Tables FK-bound to existing Phase 1AK/1AL/1AM evidence with distinct unique constraints and source actors. No existing SQL migrations modified. No user, reviewer or developer route can claim `TRUSTED`, `PROVIDED`, `VERIFIED` or `POSTED` in these phases. Earlier zero-only stock gates, UNPOSTED inventory journal, quarantined GRN and held supplier dispatch remain unchanged.

## Security and certificate-policy experiment

`POST /api/provider-selection/policies` performs an **isolated nonproduction cryptographic trial**, not production certificate validation. It first independently revalidates original Phase 1AL pinned Ed25519 root and Phase 1AM one-hop CA/leaf certificates and reviewer decisions. The exact certificate PEM bytes (public, ≤8 KiB each) are written into temporary OS-private files, then Node invokes OpenSSL via `execFileSync`, with **argument-array invocation only** (no shell), time limit 4 seconds and 8 KiB max stdout:

```text
openssl verify -CAfile <temporary pinned root> -policy_check -explicit_policy
  -policy <canonical OID> -purpose any -x509_strict <temporary leaf>
```

An OID is accepted only if canonical ASCII numeric components and length bounds pass. The test requires a one-hop pinned CA/leaf chain with explicit synthetic X.509 certificatePolicies. It rejects a wrong OID or invalid signature. Temp public PEM files are immediately removed; no private key, shell interpolated input, insecure redirect or remote request is involved. The experiment only runs when `NODE_ENV=test`, `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, **or** in nonproduction explicitly approved TLS staging (`POLICY_DRY_RUN_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_SSL=true`, `DB_NAME=aaditech_staging_*`). **Production is always blocked**, even for a correctly signed leaf.

This OpenSSL experiment is **not** full India PKI / eMudhra certificate certification-path verification. In particular it does not incorporate the real RCAI/CA/sub-CA hierarchy, authorized policy OID, provider-vetted EKU and key usage for this PO/GRN purpose, authenticated live CRL or OCSP serial status, certified signatory organization, contract or actual provider-issued end-user identity. A synthetic policy OID such as `1.2.3.4.5` is **test-only** and must never be described as an eMudhra-approved policy OID.

## End-to-end readiness must fail closed

`GET /api/provider-selection/readiness?policyId=...&dossierId=...` requires:
- original independently reviewed named CCA **candidate**, not rejected;
- original Phase 1AL environment-backed pinned root, Phase 1AM independent certificate/corporate case reviews;
- OpenSSL local explicit policy-trial matching the proposed source OID and immutable CPS metadata;
- one-shot independent HELD policy review with missing live revocation acknowledged;
- independently reviewed original corporate-registry/signatory SHA evidence dossier for the exact same original Phase 1AM case;
- **current** Phase 1AL root-signed signed revocation snapshot through Phase 1AM `sandboxReadiness`, with no revoked issuer/leaf and no frozen root; no stale or edited signature;
- an explicit sandbox access request gate that **must still read** `NOT_CONFIGURED / NOT_VERIFIED / DISABLED / HOLD`.

If any internal prerequisite is wrong, the endpoint denies with 409. If all match, response returns `openSslPolicyTrialMatched=true`, `namedProvider='eMudhra Limited'`, but **`providerContractApproved=false`, `approvedSandboxCredentialsPresent=false`, `registryIndependentlyVerified=false`, `signatoryLegalAuthorityVerified=false`, `fullRfc5280ProductionPath=false`, `authoritativeCrlOcspValidated=false`, `productionReady=false`, `officialGrnVerified=false`, `stockPostingEnabled=false`, `availableToSell=null`** and lists missing genuine evidence. A later valid signed revocation revoking that source must immediately force readiness 409.

No provider webhook or production network client is created. The existing Phase 1AL optional TLS-pinned preview remains disabled unless specifically enabled in disposable isolated staging; it **does not** become an authenticated eMudhra integration.

## Role/CSRF/MFA controls and owner/reviewer interfaces

- OWNER: `GET /api/provider-selection/candidate`, `GET/POST /nominations`, `POST /access-requests` (ticket only), `GET/POST /policies`, `GET/POST /dossiers`, `GET /readiness`, `GET /authority`.
- REVIEWER: `GET /api/provider-selection/review/nominations`, `POST /review/nominations/:id/decide`, `GET /review/policies`, `POST /review/policies/:id/decide`, `GET /review/dossiers`, `POST /review/dossiers/:id/decide`.
- Every endpoint is no-store, requires authenticated OWNER or REVIEWER. Mutations require CSRF, recent-password step-up and configured privileged MFA. Only different reviewer may approve a self-entered claim, and all positive reviews are strictly HELD. APIs strictly reject extra JSON keys, including `apiKey`, `secret`, `trusted`, `contractApproved` or `verified` fields. No UI asks for tokens, private keys, raw government IDs or confidential files.
- Owner UI shows CCA listing URL, internal nomination, request ticket, synthetic policy proposal, MCA hash dossier and false production readiness. Reviewer UI records separate signed-off internal-only listing, CP and dossier inspections.

## Guarded migrations and CI

`bun run db:migrate:provider-selection` can execute only on disposable CI MySQL (`CRM_TEST_DB=1`, `NODE_ENV=test`, `DB_NAME=aaditech_ci`) or explicitly approved isolated nonproduction TLS staging (`PROVIDER_SELECTION_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_SSL=true`, `DB_NAME=aaditech_staging_*`). It checks SHA-256 of all 25 predecessor SQL migrations under the shared advisory lock and applies additive 0026 with exact checksum/idempotent rerun. No production migrations are authorized.

Unit tests validate named CCA allowlist, strict OID, KYC hash-only payload, rejection of raw credential/token fields, independent reviewer attestations, local OpenSSL explicit-policy success/wrong-policy failure with ephemeral **synthetic** Ed25519 X.509 root+leaf and nonproduction guard. Real isolated MySQL test exercises prior 1AC–1AM fixture end-to-end and new nomination+review, no-credentials access ticket, policy trial+independent review, MCA/signatory hash dossier+independent review, no-external-trust readiness, SQL enum trust-promotion refusal and a newer root-signed revocation forcing 409. The synthetic test root and leaf private keys are created in isolated ephemeral test directories and deleted; no private key or real provider credential is committed.

CI runs 0026 migration twice, 1AC–1AN real disposable MySQL suites, unit/TypeScript/build, Chromium MFA/role smoke, staged read-only preflight and dependency/hash inventory checks. Preflight checks **26 migration SHA-256s**, immutable nomination, missing sandbox creds, policy/dossier HELD and unverified states, all prior provider/GRN/stock HARD HOLD gates. Release candidate now hashes **31 files**. No success should be claimed for queued/failed workflows; verify exact branch SHA, push and PR status.

## External artifacts required before a genuine provider sandbox integration

1. Accountable procurement/legal/IT nomination approval; a **written provider contract** specifying which certificate and eSign/PKI services can authenticate supplier/warehouse PO ACKs and GRNs, with commercial, jurisdiction, privacy, delegated signatory and retention terms.
2. Independent corporate identity/authorized legal signer evidence via actual MCA and appropriate authority channels, not documents merely uploaded by an owner. Verify CIN/LLPIN, directors and legally permitted delegation.
3. Provider-confirmed **sandbox endpoints and test account credentials**, kept only in an approved external secret manager, not Git/chat/screenshots/DB metadata. Obtain documented API scope, test-use consent and live certificate issuance examples over authenticated TLS.
4. Independent RCAI/licensed-CA root and intermediate trust-chain pinning, provider-authorized current certificate policies/OIDs, appropriate keyUsage/EKU, path length, naming/policy constraints and time/status checks.
5. Authenticated CA-specific signed CRLs and OCSP responder identity, update/freshness and rollover policy, root compromise distribution and test of revocation effect on original supplier/warehouse authority.
6. Genuine externally issued supplier PO/ACK, physical packing/serial/lot receipt and official independent warehouse GRN evidence, followed by independently reviewed operational stock/serial/accounting control design and formal signed release approval.

**FINAL DISPOSITION: HOLD.** Draft PR #1 remains DRAFT and unmerged; Issue #2 OPEN, `main` untouched. No Hostinger deployment, production migrations, supplier/vendor contacts, operational GRN/stock/reservation, invoices or financial posting. A licensed CA candidate or synthetic policy signature is **not** genuine external proof.
