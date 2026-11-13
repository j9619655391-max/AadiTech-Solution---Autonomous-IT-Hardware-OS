# Phase 1AJ — Offline key possession, suspended rotation & irrevocable revocation

**2026-11-12 · Development only · Release disposition: HOLD.**

## Scope and truth boundary

Phase 1AJ addresses the **key-lifecycle prerequisites** for signed offline evidence without pretending that the keys belong to real supplier or warehouse representatives. The Phase 1AI candidate public keys are owner-self-registered, independently reviewed for internal document format only and explicitly `UNTRUSTED`. A Phase 1AJ verified Ed25519 challenge-response demonstrates **control of the corresponding private key at challenge time only**. It cannot verify the supplier company's identity, signatory authority, real purchase-order issuance, actual shipment, supplier acknowledgment, official goods-receipt note (GRN), title to serialized goods or ledger posting.

All 1AC–1AH predecessor records remain internal, HELD, disabled, or unverified; Phase 1AG site/SKU gates remain MySQL CHECK-constrained to exactly ZERO, and Phase 1AH evidence double-entry journals are UNPOSTED. Phase 1AI `party_identity='UNVERIFIED'`, external PO/ack/GRN `'NO'` and stock posting `'DISABLED'` SQL enums remain untouched. No network dispatch or supplier contact, no production migration, no real inventory or financial posting and no private keys or confidential original documents uploaded.

## SQL migration 0022_key_possession_lifecycle.sql (seven additive InnoDB tables)

| Table | Purpose and invariant |
|---|---|
| `inv_key_possession_challenges` | Random 32-byte nonce displayed **once**, challenge ID, key/owner, SHA-256 of exact canonical JSON, 10-minute expiry, consumed timestamp and single-use status `ISSUED` → `MATCHED_INTERNAL`. The nonce itself is not stored on challenge issuance |
| `inv_key_possession_receipts` | One immutable receipt per consumed challenge with matched signature, nonce and signature SHA-256. Stores detached signature/nonce only, **not private key**. `MATCHED_INTERNAL` only, not a trust credential |
| `inv_key_possession_reviews` | One independent reviewer decision per receipt: `REVIEWED_UNTRUSTED` or rejection; original reviewer, written reason, evidence reference, explicit possession inspection. Owner cannot self-review |
| `inv_key_retirements` | One irreversible retirement record per key, event `EMERGENCY_REVOKED` or `ROTATION_RETIRED`, action actor, incident rationale and ticket. No `ENABLED`, `TRUSTED` or reactivation status exists |
| `inv_key_rotation_proposals` | Immutable old → new candidate linkage; unique old and new key IDs, distinct-key CHECK, owner, evidence and `PENDING_INTERNAL`/`REVIEWED_UNTRUSTED`/`REJECTED_INTERNAL` only |
| `inv_key_rotation_decisions` | One independent reviewer decision and inspection record. Positive decision atomically inserts a permanent retirement for the old candidate |
| `inv_key_lifecycle_audit` | Append-only actor/target/event digests for issuance, proof, independent reviews, emergency revocation and rotation events |

Every table has FK constraints to existing Phase 1AI candidate keys and authenticated user actors. Migration 0022 is additive and retains original 0021 historical checksums; names are schema-unique. SQL `CHECK` and enum constraints continue to prevent fake trust or live posted inventory. The audit event SHA-256 alone is not an external tamper-proof anchor; direct privileged DB access needs separate governance.

## Canonical challenge and proof-of-possession model

1. An OWNER selects a previously independently `REVIEWED_UNTRUSTED` Phase 1AI Ed25519 SPKI public key. The issuance handler rechecks 1AI key format, reviewer separation, key ownership and fingerprint while holding the key row. It refuses previously retired candidates and candidates involved in any pending rotation.
2. A cryptographically random **32-byte nonce** and random challenge UUID are generated. The exact canonical UTF-8 signing message has `format:'aaditech-offline-key-possession-v1'`, challenge UUID, candidate key UUID, SHA-256 SPKI fingerprint, party kind and exact internally registered supplier/site UUID, canonical nonce base64, `identityAuthenticated:false`, `officialGrnAuthenticated:false`, `stockPosting:'DISABLED'`.
3. Only message SHA-256, expiry and original key/actor are stored at issue time. The canonical UTF-8 and nonce are returned ONCE with the 10-minute expiry timestamp; no API can later fetch the nonce. Sign the exact bytes in a separately controlled offline Ed25519 environment. Do not upload/enter private keys or sensitive documents.
4. `POST /responses` takes exactly `{challengeId,nonceB64,signatureB64}`. Inputs require canonical base64 (32-byte nonce, 64-byte signature) and UUID. The server first locks the original candidate key, then locks the challenge, compares owner, unconsumed `ISSUED` status and `expires_at > UTC_TIMESTAMP(3)`; it reconstructs the canonical bytes, compares SHA-256 and verifies Ed25519 using the candidate SPKI key. A tampered nonce, source, key or signature, expired or reused challenge is **409**, with zero receipt/side effects.
5. On success, challenge consumption, one signature receipt and audit event commit **atomically**. The stored nonce allows an independent REVIEWER to reconstruct and reverify the signature and original challenge SHA, compare candidate fingerprints and original owner, verify that consumption occurred before expiry, and record one internal decision (no new challenge for this review).
6. The reviewer may select `REVIEWED_UNTRUSTED` only with independent inspected-evidence attestation, a written reason and ticket; otherwise reject. All keys remain externally UNTRUSTED regardless of the decision. Proof possession does not imply custody or identity of an external supplier.

## Rotation, revocation and cross-module fail-closed behavior

- **Emergency revocation**: authenticated OWNER with fresh password step-up, CSRF and configured privileged MFA submits `POST /keys/:id/revoke` with written reason and evidence ticket. It locks the candidate row and inserts the one-time `inv_key_retirements` record transactionally. No reviewer delay: subsequent 1AI signed-proof preparation/validation or 1AJ challenge issuance rejects that retired key. Repeated retirements conflict; there is **no un-revoke route**. Previously stored signed assertions remain historical internal evidence, but cannot be treated as a currently valid external source. Forensic evaluation of signature-at-time-of-signing requires a separate supervised historical view not included here.
- **Dual-possession rotation**: OWNER selects *two different* internally reviewed, not retired, not pending-rotation candidate keys for the **same supplier/site and same owner**. Both require individually completed and positively independently reviewed one-time Ed25519 possession receipts. No direct external authority upgrade is possible. Creation of `PENDING_INTERNAL` proposal **suspends both old and new keys** in the 1AI key-read validator, preventing fresh 1AI signed claims/templates while an independent reviewer checks the change.
- **Independent rotation decision**: REVIEWER cannot be the owner. A positive `REVIEWED_UNTRUSTED` decision revalidates both original possession receipts, their signature bytes and independent reviews under transaction locks. It atomically records the decision, changes proposal state, and inserts `ROTATION_RETIRED` for old key; new key remains self-registered `REVIEWED_UNTRUSTED` and still cannot authenticate external identity. A rejection ends pending suspension without automatically retiring the old key. If the old key was emergency-revoked while pending, a reviewer can still reject the proposal to release unrelated new-key suspension; approval fails closed.
- The 1AI `readCandidate()` path enforces revocation with current locking reads (preventing stale REPEATABLE READ snapshots) on every query and also checks for pending rotation before allowing either candidate key into new signed-claim, canonical-template and independent-claim validation workflows. Its candidate-key/retirement/rotation decision is serialized by InnoDB row locks. Revocation does not make an external trust root suddenly exist. Previously recorded claims are never silently promoted to trusted or GRN-valid.
- **Compatibility boundary:** Phase 1AI older internal CRYPTO_ONLY assertions may still use independently key-format-reviewed candidates without Phase 1AJ possession enrollment. Such assertions are always explicitly **UNTRUSTED and non-posting**. Before a future externally trusted/operational provider is implemented, make independently reviewed challenge possession plus external identity validation mandatory on that **separate** authorization path and design revocation-aware historical evidence retention. This phase does not unlock external trust.

## Route contracts and interfaces

| Role | API | Effect |
|---|---|---|
| OWNER | GET `/api/key-lifecycle/keys`, `/receipts`, `/rotations` | Own candidate key status, internal possession/review counts and retired/rotation state; all trust flags false |
| OWNER | POST `/api/key-lifecycle/challenges` `{keyId}` | Issue 10-minute single-use nonce and exact canonical offline signing message, no secret-key processing |
| OWNER | POST `/api/key-lifecycle/responses` `{challengeId,nonceB64,signatureB64}` | Verify SHA-bound canonical message and detached Ed25519 signature, consume once in atomic transaction |
| REVIEWER | GET `/api/key-lifecycle/review/receipts`, `.../receipts/:id`, POST `.../receipts/:id/decide` | Independent signature/nonce inspection and immutable `REVIEWED_UNTRUSTED`/rejection |
| OWNER | POST `/api/key-lifecycle/keys/:id/revoke` `{reason,evidenceRef}` | Immediate irreversible `EMERGENCY_REVOKED` row, subsequent candidate use blocked |
| OWNER | POST `/api/key-lifecycle/rotations` `{oldKeyId,newKeyId,reason,evidenceRef}` | Same-party independently reviewed possession of BOTH keys required, suspend both until decision |
| REVIEWER | GET `/api/key-lifecycle/review/rotations`, POST `.../rotations/:id/decide` | One immutable independent decision; positive retires old key atomically |

All role-scoped GET endpoints carry `Cache-Control: no-store`. Mutations require authenticated OWNER or REVIEWER, CSRF token, recent password step-up and configured privileged MFA. No external/trusted key enrollment endpoint, private-key upload route, authentic shipment/GRN posting or stock release is introduced.

Frontend: dedicated OWNER lifecycle panel for key status, challenge issuance, exact canonical text, detached signature, reviewed receipt listing, separate two-key rotation and emergency incident retirement; independent REVIEWER panel for nonce/key fingerprints, evidence inspection, one-time review and rotation retirement approval. Both display explicit no-external-trust and no-GRN boundaries.

## CI coverage, staging and safeguards

`bun run db:migrate:key-lifecycle` is restricted to disposable CI (`CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`) or explicit nonproduction isolated TLS staging (`KEY_LIFECYCLE_MIGRATION_APPROVED=YES`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, `DB_SSL=true`, nonproduction NODE_ENV). Script checks prerequisite migration SHA-256s 0001–0021, forbids unknown migrations, takes the shared MySQL migration lock, applies additive 0022 and verifies exact-checksum idempotent rerun. Production DB or unapproved target is refused.

`tests/key-lifecycle-validation.test.ts` checks exact input shapes, required reason/inspection, canonical signed-message binding, changed nonce/fingerprint negative crypto, forbidden trusted outcome and migration guards. Real `tests/key-lifecycle-mysql.integration.ts` uses isolated disposable synthetic supplier/site, owner/reviewer sessions and genuine offline Ed25519 signatures; tests role/CSRF/step-up, successful one-time challenge/receipt, forged signature or nonce, expired/challenge-SHA tampering, duplicate replay, independent receipt review, two-key possession before rotation, pending suspension of 1AI template, atomic old-key retirement, continued new-key external-UNTRUSTED status, immediate emergency revocation, absent external trust/stock routes and SQL enum constraints. No external party is contacted.

GitHub CI applies migration 0022 twice, executes all earlier MySQL suites, the new lifecycle suite, TypeScript/unit/build/dependency gates, real browser MFA/role smoke, read-only staging preflight and checksum-tracked held release candidate. Staging-preflight checks challenge consumption, receipt/reviewer independence, permanent retirement provenance, rotational key owner/party invariants and HELD/no-trust rules in addition to 1AG hard-zero stock. Migration inventory includes **22 registered SQL migrations**, and release-candidate build records all 22. Do not call CI green until the **exact final HEAD** push and PR workflows report success.

## Production readiness blockers (future Phase 1AK+)

An independent external trust root is still absent: supplier KYC/vendor corporate signatory verification, warehouse identity/device assurance, external independently issued key credentials and proof of domain/transport control, key rotation approval from verified source, CRL/OCSP or equivalent revocation distribution, compromise incident recovery, signed PO delivery acknowledgment, supplier/warehouse signed receipts and physically witnessed official partial/full GRNs. Future production must also add authenticated inventory credits and immutable operational stock/serial journal with atomic no-negative debits, independent valuation and invoice controls, isolated TLS staging restore evidence and owner/legal/ops release approval. No existing 1AG/1AH/1AI hard-zero or UNVERIFIED/DISABLED control should be bypassed.

**Release remains HOLD.** Draft PR #1 must remain DRAFT/unmerged, `main` unchanged, Issue #2 OPEN; no production migration/deployment, real supplier contact, true GRN, stock posting or reservation performed.

### Phase 1AJ final hardening

Candidate retirement and pending-rotation checks use **InnoDB current locking reads**, not ordinary repeatable-read snapshots, to refuse newly revoked/suspended keys even after an earlier transaction snapshot. Owner rotation locks candidate IDs in deterministic order to avoid reverse-order deadlock. Emergency revoke has independent selected key, written reason and ticket (never inherited from challenge or rotation form) and displays the exact candidate ID before confirmation. Read-only preflight omits unreachable predicates.
