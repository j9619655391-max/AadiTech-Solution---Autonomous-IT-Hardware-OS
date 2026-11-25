# Phase 1AL — Independently preprovisioned trust-provider pin, signed corporate credential and revocation transport bridge

**Date:** 2026-11-12 · **Branch:** `chore/phase0-foundation-20261106` · **Production Release: HOLD**

## Outcome and non-negotiable truth

Phase 1AL introduces a **real cryptographic adapter** for a separately configured Ed25519 root PUBLIC key, a separately pinned HTTPS TLS leaf certificate SPKI fingerprint, signer-matched organizational credential and revocation feed, and optional pinned-TLS read-only preview in explicitly authorized isolated staging. This phase **does not** complete real external corporate identity verification, trusted issuer enrollment or legally authorized supplier/warehouse signature acceptance. No independently vouched corporate registry identity, real trust provider certificate, supplier KYC, authorized signatory contract, production API credential or authenticated third-party signed payload has been supplied. The synthetic CI Ed25519 roots and signatures are never proof of an external party.

All application records in this phase remain **UNVERIFIED**, `REVIEWED_HELD`/`REVIEWED_CRYPTO_HELD` at most, and operational stock `DISABLED`. Even if every signature matches a preprovisioned key, `productionReady=false`, `corporateIdentityVerified=false`, `externalProviderAuthenticated=false`, `officialGrnVerified=false`, `availableToSell=null`. No PO dispatch, official GRN, physical movement, stock credit, reservation, serial title, valuation, accounting, payment, live supplier contact, deployment or production migration is performed.

## Schema — additive migration 0024_provider_identity_bridge.sql

Eight InnoDB tables:

| Table | Operational intent | Never-promoted state |
|---|---|---|
| `inv_provider_pin_candidates` | Records exact server-environment preprovisioned Ed25519 X.509/SPKI root PUBLIC key, SHA-256, separately pinned TLS SPKI, HTTPS public-DNS origin, provider code and owner evidence reference | `external_root_state=UNVERIFIED`; PENDING_INTERNAL / REVIEWED_HELD / REJECTED_INTERNAL only; root+provider unique |
| `inv_provider_pin_reviews` | One independent reviewer-inspected internal root-pin ticket, rationale and outcome | HELD, not externally trusted CA; owner cannot self-review |
| `inv_provider_org_credentials` | Root-signed canonical corporate purpose claim bound to a Phase 1AK independently reviewed issuer, exact party, claimed corporate registration, bounded validity and immutable SHA/signature | `corporate_identity_state=UNVERIFIED`, `external_issuer_state=UNVERIFIED`, `stock_posting=DISABLED`; never actual legal credential |
| `inv_provider_org_reviews` | One independent reviewer re-verifies root signature and held issuer evidence | REVIEWED_CRYPTO_HELD or rejection only |
| `inv_provider_revocation_feeds` | Exactly signed root revocation message per provider sequence, SHA-256, creation/import/expiry and signed-message JSON | SIGNED_CANDIDATE, `external_publisher_state=UNVERIFIED` |
| `inv_provider_revocation_entries` | Unique sorted fingerprint set for each immutable signed feed | No change to previous revoked set permitted on later feed |
| `inv_provider_pin_freezes` | Immediate one-way local root compromise block with evidence ticket/actor | No reactivation or trust override API |
| `inv_provider_audit` | Actor-identified immutable-in-application event-hash journal | Hashes are not independently tamper-proof from privileged DB administrators |

Schema is additive to migration 0023. Older migration file checksums and SQL hard-zero account balances remain intact. Existing Phase 1AG `available_quantity`, `reserved_quantity`, `picked_quantity`, `posted_quantity` are still CHECK-constrained to 0, Phase 1AH journals UNPOSTED; 1AI/1AJ/1AK source hold and revocation denials remain active.

## Configured root is NOT automatically trusted

Only out-of-band operations configuration can provision these **public** values (never submit via OWNER UI): `PROVIDER_CODE`, `PROVIDER_HTTPS_ORIGIN`, `PROVIDER_ROOT_SPKI_B64`, `PROVIDER_ROOT_SHA256` and **separately** `PROVIDER_TLS_SPKI_SHA256`. The root must be exactly Ed25519 X.509/SPKI DER 44-byte canonical base64 and SHA-256 must match the independent fingerprint. Origin must be canonical HTTPS with a real DNS hostname, no userinfo/path, IP addresses, localhost or custom ports. TLS pin is SHA-256 of the certificate public key **SPKI DER**, not the Ed25519 issuance root (TLS and issuance signing keys are deliberately separate). These are public keys/hashes, not auth tokens.

The configuration is never made available for arbitrary user editing. `POST /api/provider-bridge/pins` accepts only an internal evidence reference and takes every public pin value directly from server environment, then creates a PENDING_INTERNAL record. Independent REVIEWER can inspect and set REVIEWED_HELD (not trusted). All downstream reads must match the current server environment root fingerprint, key bytes, origin, provider code and TLS pin exactly; changing the configuration invalidates previous candidates, rather than silently reassigning trust. No principal can submit a new root via an API body or promote a root to `TRUSTED`.

**Required human controls not satisfied by the application:** procurement/IT/legal must separately verify the actual provider and beneficial organization identity, independently obtain its root fingerprint through authenticated channels, record authorized issuer and employee signatory relationships, establish approved root rollover/CRL distribution, and approve TLS pin owner and certificate renewal. Without them, environment-root pinning merely prevents accepting a *different key* and does **not prove who owns the pinned key**.

## Root-signed corporate credential contract

The canonical `aaditech-pinned-provider-organization-credential-v1` JSON signs exactly: provider pin UUID, provider code, pinned HTTPS origin, root Ed25519 fingerprint, independently internally REVIEWED Phase 1AK issuer UUID and Ed25519 fingerprint, supplier/warehouse party kind and exact internal party UUID, claimed corporate registration, purpose SUPPLIER_ACK or WAREHOUSE_GRN, validFrom/validUntil canonical UTC with ≤30-day lifetime, and hard flags `independentCorporateVerification=false`, `externallyAuthenticatedRoot=false`, `officialGrnVerified=false`, `stockPosting='DISABLED'`.

OWNER requests the exact `JSON.stringify` UTF-8 via `POST /credential-template`; this is the only byte string valid for an offline detached Ed25519 signature. `POST /credentials` verifies that signature directly with the independently provisioned server-root public key, original parties, scope, exact digest, bounded validity and immutable idempotency uniqueness. Different payload for same (pin, issuer, purpose) conflicts 409. REVIEWER independently revalidates the entire signature/party/root provenance and records one REVIEWED_CRYPTO_HELD or rejection. Review is **cryptographic only**, and there is no production-trusted issuer, official GRN or stock ledger posting route.

This is a custom signed-JSON evidence contract, **not** a general-purpose X.509 certificate chain, OCSP or automatic government KYC integration; provider-issued credentials that do not implement this exact format cannot be represented as verified in this system. Actual provider-specific adapters and legal provider onboarding must precede any external trust activation.

## Revocation stream, rollback prevention, compromised root

`aaditech-pinned-provider-revocations-v1` is an Ed25519 root-signed JSON object bound to provider pin UUID, provider code, HTTPS origin and pinned root fingerprint, integer per-pin sequence, publishedAt UTC, validUntil UTC (≤24 hours), sorted unique list of ≤128 lowercase SHA-256 revoked Ed25519 fingerprints, and hard flags `transportExternallyAuthenticated=false`, `externalPublisherVerified=false`, `stockPosting='DISABLED'`. No private keys and no signed documents are sent into the application; only detached signature and source metadata are stored.

1. First sequence MUST be 1, all following sequence numbers previous+1. In MySQL a pinned root row is locked before inspecting/inserting the latest immutable feed; exact byte-for-byte replays are idempotent, conflicts and sequence gaps fail closed.
2. New revoked fingerprint set must be a **superset** of every immediately preceding set. No earlier revoked key can be unrevoked by removal from a later manifest.
3. Latest feed is reverified at read-time for SHA/detached Ed25519 signature, stored canonical JSON values, original root+origin/scope, normalized fingerprint entries, positive 24-hour validity, not expired, not future-dated beyond five-minute skew. No feed, expired feed, changed root, altered fingerprint set, signature conflict, or revoked issuer => readiness 409.
4. The original Phase 1AI `readCandidate` path also conservatively **DENIES** any recorded candidate key fingerprint found in provider signed revocation entries, including older/expired entries. A candidate feed cannot create sellable inventory or grant external trust. Operator/root compromise uses `POST /pins/:id/freeze`, which irreversibly blocks all future local pinned-provider credential/feed checks, including previously recorded evidence.
5. If the pin is frozen or no longer matches the separate environment configuration, all source checks fail. No emergency override route is shipped. Historical internal records remain for audit but cannot constitute current legal proof.

### Pinned read-only HTTPS preview: NO automatic deployment

`POST /feeds/pull-pinned-preview` is a **read-only preview** with no DB write, no auto-supplier dispatch, no automatic feeding into inventory and no background worker. The endpoint can issue a single GET to the **fixed path** `/.well-known/aaditech/revocations/latest` under the pinned canonical HTTPS origin, and only when **all** explicit nonproduction conditions are set:

- `PROVIDER_PINNED_FETCH_ENABLED=YES`
- `PROVIDER_PIN_FETCH_SCOPE=ISOLATED_STAGING`
- `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_SSL=true`
- `DB_NAME=aaditech_staging_*`, `NODE_ENV` not production
- complete, matching ROOT and separately pinned TLS SPKI environment configuration.

Node's TLS stack must authenticate a valid hostname and trusted certificate chain; the callback additionally computes SHA-256 of peer certificate SPKI from X.509 DER and compares against the separately pinned TLS fingerprint using constant-time comparison. HTTP is GET only, redirects disabled, no cookies/private auth headers, 4-second timeout, maximum 64 KiB JSON response, `Content-Type: application/json`, no compressed payload. The preview only returns canonical signed revocation candidate after verifying root detached signature and nonexpired dates, and **does not import it**. Even when this read-only preview validates the TLS peer mathematically, **corporate issuer/registry legal authority remains independently unverified**.

The default deployment must **not** set the enabling flags. Never ask the user to paste production provider credentials into chat.

## API and UX

Authenticated, no-store role scopes; every mutation and canonical template/preview operation requires current-password step-up, CSRF and configured privileged MFA.

| Actor | Routes | Limitation |
|---|---|---|
| OWNER | GET /api/provider-bridge/pins, POST /pins | Only server environment root can be registered, as PENDING_INTERNAL |
| REVIEWER | GET /review/pins, POST /review/pins/:id/decide | Independent root pin internal HELD/reject |
| OWNER | POST /credential-template, POST /credentials, GET /credentials | Offline signature must match preprovisioned root, issuer reviewed internally; corporate ID still unverified |
| REVIEWER | GET /review/credentials, GET /review/credentials/:id, POST /review/credentials/:id/decide | Reconstruct and reverify signature/party/root under DB lock; CRYPTO_HELD only |
| OWNER | POST /feed-template, POST /feeds, GET /feeds | Immutable signed publisher candidate feed, freshness and antirollback |
| OWNER | POST /feeds/pull-pinned-preview | Explicit isolated TLS staging opt-in read-only preview, not auto-imported |
| OWNER | POST /pins/:id/freeze | Immediate irreversible internal root compromise quarantine |
| OWNER | GET /readiness/:id, GET /authority | Cryptographically consistent **internal** evidence only, productionReady false and detailed blockers |

The OWNER UI includes preprovisioned public root candidate registration, root/TLS fingerprints, exact JSON signing templates, detached signatures, issuer credential and feed listings, staging preview and root incident freeze. REVIEWER UI includes root/TLS comparison, independent inspection of root-bound org credential and immutable HELD decisions. No private key entry or purported production trust control.

## Migration guard and test evidence

`bun run db:migrate:provider-bridge` accepts only disposable CI MySQL (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicitly approved isolated TLS staging (`PROVIDER_BRIDGE_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, no production NODE_ENV). It verifies SHA-256 checksums for 0001–0023 under the shared migration advisory lock, applies 0024 and verifies an idempotent rerun, refusing unknown IDs. **Production migration and Hostinger deployment are prohibited.**

Static tests validate Ed25519 SPKI fingerprints and origin, forbidden IP/localhost/ports/HTTP, exact credential/feed payload and purpose, modified signatures, canonical sorted revocations, 30-day credential and 24-hour feed TTL, transport disabled by default, staging-only opt-in and migration refusal. Real isolated disposable MySQL test uses synthetic provider keypair and Phase 1AK supplier issuer: role/CSRF/stepup, independent pin HELD review, invalid signature rejection, source/organization SHA tamper 409, independent credential CRYPTO_HELD, 1AL signed feed sequence/replay/gap/expiry/tamper/revoke denial, DB enum trust-promotion rejection, permanently frozen root, absent official GRN/post-stock API, original 1AG hard-zero positions. New transport is not called over the public Internet during CI.

CI applies migration 0024 twice, runs all existing real MySQL suites plus new Phase 1AL tests, TypeScript/unit/build/dependency gates, browser Chromium MFA/role smoke, release-candidate hash inventory and read-only disposable staging preflight. Preflight checks server-independent DB candidate fingerprints, independent reviewer decisions, UNVERIFIED corporate+issuer status, signed candidate feeds, contiguous sequence, normalized fingerprint counts and all prior 1AG–1AK safeguards. Preflight does not claim real-world external trust. **24 registered migrations; 29 release-candidate files**.

## Remaining real external verification work — prior to production activation

Required external authority and credentials have **not** been supplied. A future independently approved implementation must obtain provider-specific authorization and independently authenticated root/SPKI and TLS pins through a verified channel, establish authorized legal corporate registration/signatories and financial/warehouse delegation, vendor-specific certified issuer chain with issuer rotation, trust-anchor compromise procedure and authenticated revocation distribution, audit authenticated HTTPS retrieval/signed feed source with live issuer consent, and prove actual PO issuance, independently accepted vendor ACK, real physical GRN, QC/serial/lot ownership, valuation and inventory ledger posting under independent human controls. Review vendor jurisdiction/legal identity proof and privacy/data minimization with accountable operations/legal personnel. Only a separately approved future release can enable genuine operation; **never reinterpret synthetic signed evidence or app-registered external issuer candidates as genuine identity verification**.

**Release disposition: HOLD.** Keep GitHub Issue #2 OPEN, Draft PR #1 DRAFT/unmerged, `main` untouched. No production deployment, production migrations, supplier communications, official GRN, inventory movement/reservations, financial posting or payments.
