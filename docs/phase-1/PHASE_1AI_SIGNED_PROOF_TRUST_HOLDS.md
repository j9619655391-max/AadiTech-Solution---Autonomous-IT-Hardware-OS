# Phase 1AI — Offline Ed25519 proof prerequisites, candidate-key review and external trust HOLD

**Date:** 2026-11-12 · **Branch:** `chore/phase0-foundation-20261106` · **Production:** HOLD.

## Executive judgment

Phase 1AI is **not** external supplier verification or a trusted warehouse GRN system. It adds real Ed25519 detached-signature *mathematical verification* for offline documents, tightly tied to existing internal HELD purchase/GRN evidence and independent human review. Every public key is supplied by the same internal owner who recorded the underlying order/quarantine observation. An independently reviewed self-registered key **cannot establish that a legitimate supplier or warehouse controls the key**. A correctly matched signature therefore proves only that someone possessed the corresponding private key, not who that person was, what goods moved, or that legal title transferred.

Existing constraints stay active: Phase 1AC/1AE supplier PO is UNSENT; 1AF supplier ACK is an unverified manual assertion and GRN is only internal HELD reconciliation; Phase 1AG operational stock positions remain SQL CHECK-constrained to ZERO; Phase 1AH paired journal legs are UNPOSTED evidence and serial candidates are NOT ownership records. No real financial or inventory event, supplier network message, vendor communication, authentic delivery/receipt, sellable stock, reservation or GRN posting occurs.

## Schema — migration 0021_signed_proof_prerequisites.sql

Seven new additive InnoDB tables:

| Table | Purpose and non-bypassable state |
|---|---|
| `inv_proof_key_candidates` | Owner-entered Ed25519 X.509/SPKI DER candidate key, SHA-256 fingerprint, supplier or warehouse-site scope, source ticket and `PENDING_INTERNAL`/`REVIEWED_UNTRUSTED`/`REJECTED_INTERNAL`; never `TRUSTED`. UNIQUE public-key fingerprint; CHECK enforces exactly supplier ID or site ID |
| `inv_proof_key_reviews` | One immutable separate REVIEWER key-format/source-document inspection, written rationale and ticket; cannot be the registering owner |
| `inv_signed_proof_claims` | Immutable document-kind/source-bound signed **assertion**, captured canonical JSON and SHA-256, detached Ed25519 signature, `signature_matched` boolean and status `PENDING_INTERNAL`/`REVIEWED_CRYPTO_ONLY`/`REJECTED_INTERNAL`. Supplier kinds reference 1AE dispatch preparation; warehouse kind references 1AF HELD internal GRN; conditional MySQL CHECK enforces source type |
| `inv_signed_proof_blockers` | One record per claim with SQL enum-only `party_identity='UNVERIFIED'`, `actual_po_issued='NO'`, `supplier_ack_authenticated='NO'`, `official_grn_authenticated='NO'`, `stock_posting='DISABLED'` |
| `inv_signed_proof_reviews` | One immutable independent reviewer decision on captured signature/source and written evidence reason; only `REVIEWED_CRYPTO_ONLY` or `REJECTED_INTERNAL` |
| `inv_signed_proof_holds` | Exact one hash-bound internal review HOLD for positive crypto-only decision; SQL enum-only `status='HELD'`, external trust `UNVERIFIED` and stock posting `DISABLED`; manifest always records official GRN false and availability null |
| `inv_signed_proof_audit` | Actor-bound audit SHA digests for candidate-key/claim creation and review |

The system stores **only** public-key SPKI DER base64 and detached signatures. **Never store, ask for or transmit private keys or signed original documents.** References and SHA-256 are pointers to independently retained offline files, not document custody, timestamp authority or independently verified identity.

## Cryptography contract — offline unsigned template and detached signature

1. A registered Owner may submit an Ed25519 PUBLIC key only for its own internally reviewed supplier or its own inventory site. The DER must be exactly 44 bytes with the Ed25519 SPKI algorithm identifier and canonical base64 encoding; fingerprint is SHA-256(DER bytes). The server never generates or handles private keys. An independently authenticated REVIEWER inspects the internal evidence and can mark `REVIEWED_UNTRUSTED` or reject. **Even internally reviewed keys remain UNTRUSTED.**
2. For PO_ISSUANCE_ASSERTION and SUPPLIER_ACK_ASSERTION, source is a Phase 1AE approved internal dispatch preparation and its original `HELD`/`DISABLED` outbox SHA-256. For WAREHOUSE_GRN_ASSERTION, source is the Phase 1AF HELD internal GRN-reconciliation record SHA-256, including its original Phase 1AD independently witnessed quarantine custody. Party scope must match supplier ID or warehouse site exactly, along with original owner. These are internal evidence references, not real issued POs/GRNs.
3. `GET /api/proof-foundation/message-template` creates the exact JSON byte string (UTF-8, `JSON.stringify`) to sign with the offline Ed25519 private key. Version `aaditech-self-registered-offline-proof-v1` includes kind/source ID/source SHA/party ID/reference/document SHA/canonical `YYYY-MM-DDTHH:mm:ss.000Z` timestamp, and **externalIdentityVerified:false**, **officialGrnAuthorized:false**, **stockPostingState:'DISABLED'**. No browser or server key-signing function is provided; an operator may use a separately controlled offline signing environment.
4. OWNER `POST /api/proof-foundation/claims` accepts only `{keyId,kind,sourceId,reference,documentSha256,issuedAt,signatureB64}`. All fields are exact-key validated; SHA must be lowercase 64 hex; signature canonical base64 decodes to exactly 64 bytes. The server recomputes source digest and exact canonical message, then calls Node.js Ed25519 `crypto.verify(null, canonicalUtf8, candidatePublicKey, detachedSignature)`. Any altered source/hash/key/payload/byte/signature is rejected. Valid signatures are still **UNTRUSTED internally recorded claims**.
5. Unique (kind,source ID) DB constraints ensure one immutable assertion per source/kind. Identical byte-for-byte requests return the original ID; altered data conflicts. The server binds each claim to one key, owner and source, and stores permanent source blockers atomically. No claim can enable supplier PO issuance or warehouse receipt.
6. Independently authenticated REVIEWER re-verifies key-format fingerprint, original key review, upstream HELD evidence source and all signature bytes at decision time, then records `REVIEWED_CRYPTO_ONLY` or `REJECTED_INTERNAL`. A positive internal review creates only one `HELD`/`UNVERIFIED`/`DISABLED` snapshot. It does NOT establish that the signing key belongs to the supplier, that an order was dispatched or acknowledged, that goods were physically delivered, or that an official GRN exists.

## Routes, roles and UX

| Actor | Endpoint | Boundary |
|---|---|---|
| OWNER | GET `/api/proof-foundation/keys`, POST `/keys` | Own public-key candidate registration only; exact party scope and evidence ticket; no identity trust |
| REVIEWER | GET `/api/proof-foundation/review/keys`, POST `/review/keys/:id/decide` | One independent key-format/doc check, outcome REVIEWED_UNTRUSTED or rejected, inspection flag required for internal-positive |
| OWNER | GET `/api/proof-foundation/sources`, GET `/message-template` | Read original held source ID/hash and exact canonical UTF-8 bytes to sign offline; identity/trust flags false |
| OWNER | POST `/api/proof-foundation/claims`, GET `/claims`, GET `/authority` | Detached cryptographic assertion, own claim list and unconditional false authority readiness |
| REVIEWER | GET `/api/proof-foundation/review/claims`, GET `/review/claims/:id`, POST `/review/claims/:id/decide` | Independently revalidate crypto/source under MySQL lock and decide REVIEWED_CRYPTO_ONLY/REJECTED_INTERNAL; cannot authenticate external party |

All routes are authenticated and no-store; OWNER/REVIEWER segregation applies; mutations require CSRF, current-password step-up and configured privileged MFA. MySQL transactions and unique constraints provide one-time decisions; a credentialed DB administrator capable of modifying the key and fingerprint together is **not** cryptographically prevented by self-registration. The UI makes private-key prohibition explicit and never asks for keys other than public SPKI DER.

Owner panel has owned source/key selectors, public-key candidate form, canonical template generator, detached-signature submission and external trust readiness warning. Reviewer panel shows key fingerprint and offline claim details, original source digest, actual signature math result, inspection flag, reason and an irreversible decision limited to **internal** statuses.

## CI, strict migration guard and preflight

`bun run db:migrate:signed-proof` allows disposable CI only (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicit separately authorized TLS staging (`SIGNED_PROOF_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, nonproduction NODE_ENV). Requires exact registered 0001–0020 SHA-256 migration checksums, migration advisory lock and 0021 checksum/idempotent rerun, and refuses unknown migrations. No production DB connection or deployment.

`tests/signed-proof-validation.test.ts` covers Ed25519 DER/SPKI canonical encoding, strict field/timestamp/base64 constraints, detached-signature success and tampering failure, nested JSON checksum, key/claim review declarations, and production migration denial. `tests/signed-proof-mysql.integration.ts` runs genuine Ed25519 signatures over isolated synthetic 1AC–1AG source fixtures in disposable MySQL: owner/reviewer role/CSRF/password step-up; key candidate and independent UNTRUSTED review; source digest binding; failed signatures; immutable exact retries; tampered outbox/message; independent CRYPTO_ONLY review and HELD snapshot; independently signed warehouse assertion that remains NOT a GRN; SQL enum rejection of trust promotion and stock posting; strict zero stock; absent real post routes.

GitHub CI runs all existing migrations, applies 0021 twice for checksum/idempotent rerun, all prior real MySQL integration tests, new signed-proof integration, real Chrome MFA role smoke, read-only isolated staging preflight and baseline typecheck/unit/build/release hash checks. Staging preflight checks key fingerprint SHA-256/format evidence, reviewed-key independence, claim hard-denial rows, match flags, claim/decision/HELD consistency, and all existing hard-zero/UNPOSTED guards. Passing these checks certifies software controls only, **not** trust in an external public key.

### Pre-existing Phase 1AG/1AH corrective regressions

Prior Phase 1AH head first failed MySQL because migration `0019` reused the schema-wide FK name `fk_release_actor` from `0007`. The 0019 migration definition was corrected to `fk_stock_intent_preparer`, with intentional checksum change; that old invalid migration never completed in isolated CI. Before any independent staging upgrade investigate recorded checksums rather than rewriting old migration history. Subsequent CI passed the complete disposable MySQL suite but the static FK regression test had literal backslash escaping in its regular expression; this Phase 1AI push corrects the regex so it checks all real `CONSTRAINT ... FOREIGN KEY` identifiers. Concurrent identical request conflicts may return 409 (fail-closed), followed by explicit sequential identical-id replay; source tamper always remains rejected. **No production migration performed.**

## Release decision and real prerequisites

**HOLD.** No production supplier identity KYC, destination ownership proof, production-trusted key enrollment with external verification and rotation/revocation, signed transport acknowledgments, externally issued PO, authenticated supplier ACK, official physical warehouse GRN, landed-cost finance, inventory posting, customer reservation, site/serial ownership, backup/restore or human production approval has been established.

Future activation requires supplier/warehouse identities validated *outside* internal self-registration, chain-to-trusted-root credentials/certificate or approved key registry with revocation, authorized operator dual-control, independent shipment/packing/physical receipt, signed real GRN, legal invoice, and a **separate audited operational ledger design and explicit production authorization**. Keep 1AG hard-zero CHECK, 1AH disabled journals and 1AI `UNVERIFIED` SQL enums in force. Keep Draft PR #1 DRAFT/unmerged, `main` unchanged, Issue #2 OPEN.