# Phase 1CE — Cross-witness RFC6962 consistency, anti-equivocation and archive retrieval prerequisites (HARD HOLD)

**Date:** 18 November 2026 (IST).  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`.  
**Engineering branch:** `chore/phase0-foundation-20261106`. `main` remains unchanged; PR #1 stays Draft/open/unmerged, Issue #2 stays open.

## Engineering objective and actual trust boundary

Phase 1CD checks that candidate Ed25519 CI/WORM/DR statements, signed by **caller-supplied** keys, form a bounded chain relative to **caller-supplied** checkpoint anchors. Without genuinely independent identity enrollment and a trusted monotonic source, signatures alone cannot detect a publisher who provides inconsistent log roots to different parties. Phase 1CE extends the engineering tests with dual-witness signed log-head agreement, real RFC6962 append-only proof mathematics and byte-exact archived CI envelope retrieval.

These are **OFFLINE, self-supplied candidate records only**. GitHub workflow CI deliberately supplies no real witness keys, no external challenge, no independent anchors, no network credentials and no WORM API response. A locally passing synthetic test is **not** proof that the third-party source was authenticated or a log was externally witnessed.

## Implemented control

The new `scripts/phase1ce-cross-witness-retrieval-preflight.mjs` exports `witnessSigningBytes` and `assessCrossWitnessRetrieval`. It reuses the existing `phase1BbVerifyConsistencyProof` RFC6962 verifier rather than trusting a new unreviewed consistency algorithm.

The verifier enforces:
- **Two independent claimed witnesses:** exactly two Ed25519 detached signatures with different witness references, public keys, organizations and administrative authorities. Candidate enrollment includes public SPKI digest, validity interval and non-revocation *as self-supplied fields*. Keys must match their signed claims; duplicate or reused administration/key enrollment is rejected.
- **Exact run/source:** the two signed tree heads must both name the same repository, Phase 1CC unsigned envelope checksum, CI source HEAD, PR checkout SHA, exact run ID/attempt, externally supplied nonce and log reference. Any unauthorized extra signed claim fields (including release GO) or stale/expired timestamp is rejected.
- **Anti-replay / rollback:** each signed witness statement claims exactly the previous anchored sequence+1 and supplied predecessor digest, previous Merkle tree size/root and a new tree size/root. Missing, repeated, skipped or rollback sequence and a fork from the supplied previous head fail closed.
- **Cross-witness equivocation:** the two signed current heads must agree on `treeSize|rootSha256` and previous heads on `oldTreeSize|oldRootSha256`. If a party supplies divergent heads for the same source/run/nonce the verifier detects that contradiction. It cannot detect a fork **not provided** to it, nor authenticate the published head or trusted anchor.
- **Append-only Merkle math:** a bounded, strict-hex RFC6962 consistency proof is validated for each witness from its old head to new head. Equal-size trees require identical root and empty proof; log shrinking, missing audit paths and substituted roots fail.
- **Archive retrieval-bytes correlation:** a bounded (256 KiB), canonical base64 offline retrieval packet is decoded and SHA-256 hashed. The digest, content length, object version ID, retrieval nonce and source/checkout must agree with each signed witness. The payload must parse as the exact Phase 1CC envelope and pass its own domain-separated checksum. This verifies the *submitted bytes*, not who retrieved them or whether they came from the claimed external object store.
- **No release privilege:** all real third-party identity, OIDC/CI workload, high-watermark, publisher, WORM Object Lock/retention/delete-denial and independently recovered DR flags remain false, regardless of test mathematical validity. `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

In the existing `build-input-provenance` GitHub Actions job, `node scripts/phase1ce-cross-witness-retrieval-preflight.mjs --ci-hold` follows Phase 1CC and 1CD. This zero-input CLI checks the Phase 1CC source-bound envelope, the Phase 1CD zero-input hold report, exact read-only GitHub job/source context, and verifies that **zero submitted witnesses cannot be promoted into independent approval**. It writes only `phase1ce-zero-input-cross-witness-hold.json`, which the existing GitHub artifact uploader archives **UNSIGNED** alongside prior BV/BZ/CC/CD reports. No new job, runner label, writable token, action ref, provider secret or outbound network request was added.

`tests/phase1ce-cross-witness-retrieval-preflight.test.mjs` adds **14** adversarial Node test groups with temporary synthetic Ed25519 test keys and a genuine constructed two-leaf SHA-256 Merkle consistency proof: dual-witness and source equality; zero inputs; equal-size tree; conflicting new/previous heads; fake/omitted RFC6962 proof, tree shrink and oversize; replay/rollback/sequence gaps; changed enrollment, public key and revoked authorities; spoofed signed identity/run/nonce/object version; invalid signature/base64 and duplicate witness; byte/length/hash/JSON replacement or oversized retrieval; path/version/nonce/time spoof; timestamp/extra claim attacks and false dependency green/release GO. Temporary test keys and fabricated external-storage identifiers **never qualify** as real third-party proof.

Phase 1BV and Phase 1BW custody inventories also include the Phase 1CE script and tests to ensure a selected-source digest changes when they change.

## Actual independent evidence required before any trust promotion

| External prerequisite | Acceptance requirement | Status |
| --- | --- | --- |
| Witness key authority | Real independently enrolled issuer public keys, organization legal/administrative control, independent key lifecycle and signed revocation proof | **NOT AUTHENTICATED** |
| Published Merkle heads | Out-of-band separately retrieved signed current and previous heads from distinct approved trust endpoints; cryptographically verified publisher and witness identities, non-equivocation monitoring | **NOT VERIFIED** |
| Trusted monotonicity | Independent persistent append-only witness checkpoints and external high-watermark, exact quorum of previous/current state and coordinated fork detection across runs | **NOT VERIFIED** |
| Genuine WORM response | Authenticated external object-store GetObjectVersion, retention Object Lock compliance mode, denied delete/overwrite log, independent API response/transaction attestation | **NOT VERIFIED** |
| DR retrieval | Separate-authority retrieval of the exact archived object bytes/version from isolated DR, signed restore and freshness witness | **NOT VERIFIED** |
| CI execution identity | Independently verified signed OIDC workload JWT, attested SLSA/in-toto material, selected package and source SHA, GitHub action and runner identity | **NOT VERIFIED** |
| Production gating | Actual enforced GitHub branch protections/CODEOWNERS, two distinct current-head Security/business non-author approvals, independently approved staging and Owner/Legal/Ops authorization | **NOT VERIFIED** |
| Vendor vulnerability | Genuine supported upstream Picomatch fix, checked-in regenerated frozen Bun lockfile and full mandatory zero Critical/High/unknown vulnerability audit | **BLOCKED** |
| Business legal/provider | CCA/RCAI/eMudhra licensed authority/approved sandbox/live signed CRL/OCSP, independently authenticated MCA/GST legal signatories | **PENDING** |

GitHub's current unresolved mandatory High advisory `picomatch@4.0.7` / `GHSA-fc5q-39xc-vjpf` (`CVE-2026-112366`) must **not** be overridden or ignored based on an isolated production dependency tree, local Merkle proof, fake patched release or source digest.

## Final state

Engineering can establish syntactic/cryptographic *candidate consistency*, not external truth. No production signing keys, cloud access, eMudhra credentials, customer data, approved reviewer attestations, real WORM object/version or privileged provider operations were created/used.

**Non-negotiable:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. PR #1 Draft/open/unmerged; Issue #2 open; `main` unchanged. No live quotes/PO/GRN, stock/finance/tax posting, customer outreach or production deployments.
