# Phase 1DV — Offline dual-observer publication candidate and external anchor intake HARD HOLD

**Scope:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`, development branch `chore/phase0-foundation-20261106`. PR #1 is OPEN/DRAFT/UNMERGED; Issue #2 remains OPEN; `main` is unchanged. No real external onboarding or release.

## What this phase establishes — and what it cannot

Phase 1DU verifies a 2–6 epoch four-signature rollover to dual-signed v2 checkpoint sequence but takes every input, first anchor, key and clock from the applicant. Earlier 1CF/1CG code already explores offline candidate publication/reviewer evidence; neither fetches, independently identifies nor authenticates real off-platform sources. Phase 1DV does **not** silently convert those local candidate receipts to real publication.

`scripts/phase1dv-offline-observer-publication-candidate.mjs` exports `assessOfflineObserverPublicationCandidate` and `observerSigningBytesDv`. It is a **pure read-only verifier** that:
- Accepts **exactly** `{history,observations,comparisonPins,expected,archivePayloadBase64,now}`; limits the aggregate JSON to 768 KiB, archive bytes to 16 KiB, observer statement bytes to 8 KiB and packets to 12 KiB; requires an explicit normalized UTC clock.
- Re-verifies every prior Phase 1DU signed epoch, rather than accepting a submitted boolean receipt. Its terminal fully signed v2 checkpoint must equal expected organization, source HEAD, main base, sequence, previous checkpoint and full checkpoint digest.
- Hashes **the actual supplied archive bytes** and compares them to a caller-provided digest carried in two Ed25519 signed, role-separated witness statements. The signed statements also bind legal-mandate and revocation-evidence digest **claims**, challenge nonce, source/organization/checkpoint, archive version, observer key ID and SPKI, endpoint, operator, observed TLS-peer SPKI, HTTP status and no-redirect assertion, issued time/expiry and immutable HOLD.
- Requires exactly one `CHECKPOINT_PUBLISHER` and one `INDEPENDENT_ARCHIVE_OBSERVER`; enforces unique roles, identities, organizations/operators (represented as distinct operator IDs), key IDs, SPKI, endpoint hosts, TLS pins and non-reuse of any Legal/Registry witness key from the supplied signed history. All these origins and pins remain **untrusted caller assertions**.
- Detects signed but wrong-digest archive, altered scope, forged GO, repeated packet, key/role swap, TLS/endpoint/operator collision, expired signature, history rollback, missing proof, fake admission metadata, and private-evidence leakage. The response is frozen, bounded and redacted.

**A mathematically corroborated candidate is not independent publication.** `candidateObserverPublicationCorroboratedMathematicallyOnly=true` never sets any authority flag. The signed statement's `httpStatus=200`, `redirectCount=0`, endpoint and TLS SPKI are not actual HTTP/TLS observations. Likewise any legal mandate/revocation digest is a **hash supplied by the applicant**, not actual MCA/eMudhra/CCA/RCAI legal or certificate trust verification. Raw archive bytes are supplied locally, not fetched or pinned off-platform.

## Test coverage

The existing `tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs` now includes **13** Phase 1DV synthetic Ed25519 adversarial groups in addition to earlier Phase 1DT/1DU tests. They cover a mathematically linked two-role signed candidate, duplicate role, newly re-signed source/previous-checkpoint substitution, fake mandate/revocation hashes, archive-byte spoofing, GO/redirect/status fraud, signature substitution, signed TLS/endpoint/operator/key-ID drift, role independence and old witness key reuse, modified signed predecessor, time/expiry failure, schema/size/encoding failure, and response secrecy/immutability. Per-test fixture history is cloned; synthetic keys must never be presented as real organization authority.

Both Phase 1BV build-input and Phase 1BW independent reviewer source custody inventories contain the new 1DV verifier source. Run the bounded Node suite with:

```bash
node --test tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs
```

**Phase 1DV initial docs-inclusive engineering HEAD** `1eb799b179c5884ad603aec301a1c4b54e9cdfa2`: [push Actions 44885773106](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44885773106) **COMPLETED/SUCCESS** with 7 executed jobs success and one expected PR-only source-merge-lineage skip; [PR Actions 44885776966](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44885776966) **COMPLETED/SUCCESS** with 8/8 jobs success. Both exact head source SHA. This includes Node baseline, source/reviewer custody, governance, disposable MySQL and isolated Chromium smoke. Neither external TLS retrieval nor legally enrolled observer/mandate key can be inferred from CI. Following this documentation-only receipt, exact latest HEAD push/PR CI must be verified again; do not substitute prior SHA. Hosted tests never grant legal/staging release authority.

## Explicit real-world evidence admission prerequisites (NOT SATISFIED)

The next authorized, **separate** intake must require independently appointed legal/security/business/registry operators, and all of the following *from authenticated external sources rather than from applicant JSON or synthetic keys*:

1. **Organization/legal mandate:** Current MCA company, signatory, board/authority mandate and effective/revoked status authenticated out-of-band by an appointed Legal officer; identity-verified signatory/observer roles and business need approved.
2. **Provider trust:** Explicit signed provider sandbox agreement, approved credentials stored only in an approved secrets manager, official RCAI/CCA/eMudhra certificate policy/trust-chain, and live signed CRL/OCSP status with freshness/issuer/key usage; verify through permitted provider endpoints and named Security owner.
3. **Independent published checkpoint:** Separate operator-owned publisher and archive endpoints, externally enrolled public-key SPKI/key IDs, trusted out-of-band TLS certificate chain/host verification, anti-redirect/bounded retrieval, exact externally retrieved signed bytes, independently enforced WORM/Object Lock and CAS/high-watermark challenge/response with deletion-denial and anti-equivocation cross-observer evidence.
4. **Time/revocation/DR:** Independently authenticated time source and key-rotation/retirement registry, public key compromise handling, signed and retained immutable external receipt, independent off-site restore/reconstruction with measured RTO/RPO, authorized incident mandate.
5. **GitHub/staging/release:** Protected main with no-admin-bypass CODEOWNERS and two genuine nonauthor Security and Business approvals on exact current SHA, authenticated signed CI/workload provenance (OIDC/SLSA), owner/legal/security/operations staging acceptance and no production release while any approval is absent.

No actual external credentials, customer/supplier data or private evidence are requested or stored by this phase. No provider activation, key enrollment, reviewer request, main merge, production deployment or real commercial transaction is authorized. Store sensitive evidence only in approved external custody; GitHub should hold redacted digests, links and reviewer acceptance receipts.

**Nonnegotiable result:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`.
