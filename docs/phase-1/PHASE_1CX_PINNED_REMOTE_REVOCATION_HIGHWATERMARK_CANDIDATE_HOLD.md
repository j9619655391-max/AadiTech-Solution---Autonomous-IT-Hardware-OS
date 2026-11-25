# Phase 1CX — Strict pinned-HTTPS revocation and dual-witness checkpoint intake (HARD HOLD)

**Review date:** 20 November 2026 IST  
**Repository:** `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`  
**Development-only branch:** `chore/phase0-foundation-20261106`  
**Governance:** PR #1 Draft/open/unmerged; Issue #2 OPEN; `main` untouched.  
**Release:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`.

## Why this stage exists

Phase 1CW checked six-role candidate signatures, proposed SPKI fingerprints, revocation lineage, claimed witness quorum and claimed recovery evidence. Every pin, key, source and previous checkpoint was supplied by the applicant/operator. This was mathematically useful but **not an actual independently authenticated source enrollment**, independently retrieved CA revocation feed or globally durable anti-equivocation checkpoint. Phase 1CX adds a narrowly scoped, read-only *technical intake path* with explicit TLS peer SPKI pinning, safe DNS policy and source-specific detached signature verification. It never installs a real trust anchor or converts a candidate packet into legal production authorization.

There are two separate experiences: **offline** evaluation of candidate source packets (suitable for synthetic tests) and **explicit human-authorized** HTTPS GET against already approved remote sources (no routine CI/live polling). Neither operates with eMudhra, CCA/RCAI, MCA, WORM, corporate legal identities, vendor secrets or real production privileges by default. We have **not run the remote mode**, because independently approved endpoint hosts, public keys, provider agreements and live credentials have not been supplied.

## Explicit operator commands

For a bounded offline fixture or externally obtained packet file (candidate observations, not proof of retrieval), the human operator can inspect:

```sh
node scripts/phase1cx-pinned-external-source-highwatermark.mjs \
  --offline-verify /approved/offrepo/phase1cx-observations.json
```

This JSON contains `manifest` and `observations`. `observations` has exactly three conceptual roles: `REVOCATION`, `WITNESS_A`, `WITNESS_B`. No network request is made in offline mode. A successful synthetic fixture is an **internally consistent candidate**.

Only after separate authorized corporate Security/Business and external trust-provider approval, a human may explicitly choose read-only candidate source fetches:

```sh
node scripts/phase1cx-pinned-external-source-highwatermark.mjs \
  --operator-readonly-pinned-https /approved/offrepo/phase1cx-source-manifest.json
```

The file is a manifest of *public* source metadata/pins, not private credentials. The operator is responsible for confirming each endpoint's owner, corporate mandate, CA policy, ED25519 enrollment provenance and SPKI pins through an independently authenticated out-of-band channel. Do not paste secrets, passwords or private signing keys into this manifest, Git, PR comments or chat. Both CLI modes reject `GITHUB_ACTIONS=true`; unattended Actions do **not** run remote retrieval. Failed integrity checks result in a nonzero process exit and HOLD receipt.

### Exact manifest constraints

The candidate `manifest` requires `schemaVersion=1`, exact repository, current 40-character development and base SHA, current Phase 1CV source policy SHA-256, Phase 1CV signed candidate SHA-256, a nonzero 64-character challenge nonce, an operator-supplied `previousAnchor` and exactly three `sources` (the role names above).

The `previousAnchor` specifies `epoch`, `checkpointDigest`, `revocationVersion`, `revocationDigest`, `observedAt`. It is **not assumed durable, independently signed or authentic**. An actual external provider-backed, immutable and read-after-write verified anchor must be obtained separately before trusting it.

Each role's source has exactly `host`, `path`, `tlsSpkiSha256`, `signerSpkiSha256`, `publicKeyPem` (public Ed25519 SPKI), and `keyId`. Three distinct hosts, TLS pins, signer pins and key IDs are mandatory. The only permitted public routes are:

- Revocation: `/v1/revocations/<id>.json`
- Witness A/B: `/v1/checkpoints/<id>.json`

Hostname validation rejects IP literals, URL authority/userinfo, embedded port, uppercase/unicode/empty labels, `.local`, `.internal`, `.localhost`, `.invalid`, `.example`, `.test` and other invalid host syntax. DNS must resolve only public IPv4 records; any private/link-local/loopback/reserved/IPv6 record or DNS error refuses the read. This intentionally **does not support IPv6-only sources** until their address safety review is implemented.

### HTTPS operator read behavior

A live candidate GET uses Node's native HTTPS client with full CA/hostname validation (`rejectUnauthorized=true`, no custom CA bypass), an actual-leaf X.509 public-key **SPKI SHA-256 match**, `agent:false`, a single DNS-selected validated public address, and no redirects. Only explicit source JSON paths can be requested. Fixed headers contain no tokens/cookies/authorization. Response must be HTTP 200 with JSON media type and no unsupported content encoding; it is limited to 64 KiB and 6.5 seconds. It never sends POST/PUT/PATCH/DELETE, remote CI credentials or a signed application action. A missing/mismatched peer pin is a technical source failure.

**Security limit:** the operator currently supplies the host and pins. Even a successfully pinned, CA-valid HTTPS connection proves only a TLS connection to the specified matching endpoint, **not** independently authenticated provider organization/CA/MCA signatory authority, authorized access, company key enrollment, approved certificate policy or legally valid data. A source may equivocate between reads; remote data could change after inspection. Cross-run durable CAS and independent witness gossip require separate offsite trusted infrastructure and evidence.

### Detached source packet validation

Each successful candidate response is JSON with `statement` and `signature`. The signature has an exact `keyId`, `algorithm=Ed25519`, canonical base64 `signature`, and must verify against a **role-specific, pinned SPKI public key**. Signed bytes use explicit domain separation:

```text
aaditech/phase1cx/readonly-source/v1/REVOCATION/v1\n
aaditech/phase1cx/readonly-source/v1/WITNESS_A/v1\n
aaditech/phase1cx/readonly-source/v1/WITNESS_B/v1\n
```

Each prefix is followed by recursively key-sorted canonical JSON. An unknown role, extra signed statement fields, wrong signature, wrong signer key ID, missing data or unsupported JSON type fails closed. The report never includes keys, signer fingerprints, full signed objects or endpoint hostnames.

The `REVOCATION` statement must bind the exact repo/head/Phase 1CV policy digest/candidate digest/nonce and a fresh signed checkpoint digest. New `epoch` and revocation `version` must equal the supplied prior values **plus exactly one**, while previous checkpoint and previous revocation digests must match. Bounded (max 32), unique, sorted `revokedKeyIds` must exclude *all three active remote source signers*. The statement must be fresh within a short canonical UTC issuance window, and later than the prior anchor observation. An archive/checkpoint from a prior commit cannot be substituted.

The `WITNESS_A` and `WITNESS_B` statements independently sign the exact current source/head/policy digest/candidate digest, checkpoint epoch and digest, prior checkpoint digest, current revocation statement SHA-256 digest, the same nonce, archive fingerprint and archive object version. Both must have fresh observation and expiry timestamps **after** revocation issuance. A mismatch is treated as a candidate **fork/missing quorum**, not accepted as a safe alternate state.

## Audit, recovery and external authority blockers

The output field `candidateThreeSourcePacketsCryptographicallyAndMonotonicallyConsistent` is **only a technical candidate check**. Even when true, these fields remain intentionally false:

`externallyMandatedTrustAnchorAndRoleEnrollmentVerified`, `remoteTlsPinsIndependentlyAuthenticated`, `independentlyApprovedRevocationAndCertificatePolicyVerified`, `independentlyDurableOffsiteCheckpointCasVerified`, `crossRunForkAbsenceAndAbaRollbackGloballyProven`, `externallyVerifiedWormObjectLockAndRecovery`, `independentMcaEmudhraCcaRcaiOrStagingAcceptance`, and `productionReleaseAuthorized`.

For any actual production readiness handoff, separate authorized external personnel must independently verify real Security and Business officer appointments and latest-head nonauthor approvals, **installed and enforceable no-bypass main CODEOWNERS/rulesets**, eMudhra/RCAI/CCA live trust hierarchy and signed CRL/OCSP/certificate-policy authenticity, independently authenticated MCA/GST corporate and signatory identity, source-owner/TLS pins, externally **durable** monotonic high-watermark, fork gossip and revocation distribution, real WORM COMPLIANCE lock/delete denial and offsite DR restore with RTO/RPO, signed OIDC/SLSA workload provenance and named Owner/Legal/Security/Ops staging signoff. None is available or silently manufactured by this code.

## Engineering tests and source custody

- Code: `scripts/phase1cx-pinned-external-source-highwatermark.mjs`.
- Tests: `tests/phase1cx-pinned-external-source-highwatermark.test.mjs` (**23 adversarial Node test groups**) using locally generated short-lived Ed25519 keys and mocked source response metadata. No real external private key, reviewer identity or provider credential is ever part of a fixture.
- Both files are included in Phase 1BV/BW exact source input inventories. `.github/workflows/ci.yml`, third-party action SHA pins, CI token permissions, `main`, PR approval/merge state and production service operation are unchanged.
- Verify a *new final-commit* hosted GitHub Actions **push and PR** run separately, frozen Bun advisory audit, JavaScript, TypeScript and staging-security suites, disposable MySQL migration/integration and Chromium MFA/role smoke. Reconcile GitHub Check Runs and Actions Jobs exactly. Record all failing runs, corrective commits and actual final evidence in PR #1 and Issue #2, never reuse Phase 1CW results to attest new code.

**Known actual blockers at phase start:** 0 submitted PR reviews, 0 installed main rulesets, `main` CODEOWNERS HTTP 404, no genuine external company/provider/revocation/key/signoff authority. No real approved operator remote HTTPS fetch was made.

**Final decision: PRODUCTION HARD HOLD.**
