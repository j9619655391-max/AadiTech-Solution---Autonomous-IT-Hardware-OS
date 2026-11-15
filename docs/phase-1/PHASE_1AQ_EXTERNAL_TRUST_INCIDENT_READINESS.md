# Phase 1AQ — WebPKI trust-incident containment and external authority acceptance: HARD HOLD

**Prepared:** 2026-11-15. **Branch:** `chore/phase0-foundation-20261106`. **Release:** HOLD. **Nature:** offline public-certificate negative screening and accountable readiness only, NOT an approved external integration or a production security audit.

## Change driving this phase (source-authenticated *public* references)

- India's CERT-In advisory of **2026-10-21** distinguishes eMudhra's **global WebPKI/TLS** incident from the separate CCA-regulated Indian DSC/eSign services. The advisory states Indian DSC/eSign was not affected; this is **not evidence of this application's RCAI anchor, contract, service entitlement, certificate policies or signatory identity**. Source: https://www.cert-in.org.in/s2cMainServlet?CACODE=CICA-2026-3649&pageid=PUBADV01 .
- Mozilla's original October 2026 incident documents **eight compromised G3B/G3C intermediate keys** (six TLS and two code-signing), and **eight distinct Sectigo cross-signed certificates** for those same G3 public keys. Subsequent incident findings/appendices extend operational distrust to **eight G2B/G2C RSA intermediates** that were revoked **2026-11-07** on key-handling/confidentiality concerns; do not incorrectly report that those RSA keys were mathematically recovered. Mozilla primary incident record and Appendix A/B/C: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 .
- The 24 explicitly identified public-certificate SHA-256 fingerprints are pinned in `scripts/lib/phase1AqTrustIncident.mjs`: 8 G3 original + 8 cross-signed + 8 G2 RSA. They are **public disallow candidates**, not credential material. If Mozilla or national trust stores revise the list, SECURITY must reconcile and extend this denylist through reviewed code and CI; no silent assumptions that it is permanently complete.
- Broader WebPKI program distrust, including affected roots/other possible future certificates, is NOT exhaustively represented by these 24 exact fingerprints. Certificates not matched remain **UNVERIFIED_HOLD**, never trusted by default. A matching known certificate receives **DENY**; neither classification grants any operational authority.

## Actual implementation

1. `classifyPhase1AqPublicFingerprint(sha256)` validates a complete SHA-256 certificate fingerprint with an optional canonical colon format and rejects all 24 currently enumerated incident certificates. Unknown fingerprints remain UNVERIFIED_HOLD. It does not accept subject names, environment flags or status strings as proof.
2. `auditPhase1AqPublicCertificateChain(pems)` optionally parses up to twelve bounded single-certificate public PEMs using Node's X509 parser. It rejects mixed PEM/private keys, duplicate public certificates, malformed/oversized data and nonarrays. It discloses only aggregate incident counts; it does not echo certificates, names, fingerprints or file paths. Public PEMs are **not** CA anchors, identity authority, PKIX path verification, authorization or cryptographic revocation evidence.
3. `scripts/phase1aq-trust-incident-preflight.mjs --ci-hold` always emits a **zero-input/zero-network HARD HOLD**, refuses other CLI modes, and provides **no** live provider access, secret reading, CA trust enrollment, MySQL updates, issuance, GRN, stock or finance write.
4. `tests/phase1aq-trust-incident.test.mjs` checks coverage of all three eight-certificate sets, case/colon normalization, invalid inputs, duplicate and injected PEM rejection, non-promotion of even an operating-system public root certificate, and CLI hard hold. Baseline CI runs the CLI and the repository-wide unit suite.
5. No schema migration and no release artifact count increase: the existing **27 registered migrations** and **32-file held release candidate inventory** continue unchanged. PR #1 remains DRAFT, Issue #2 stays OPEN and `main` must not be merged or deployed.

## Separation of trust domains

| Domain | Rule | Independent source of authority | State |
|---|---|---|---|
| Global WebPKI TLS / code signing | Explicit incident fingerprint **DENY**; unrecognized inputs still HOLD | Browser/root-program disallowed lists and authenticated PKIX/revocation status | OFFLINE NEGATIVE SCREEN ONLY |
| India CCA-regulated DSC/eSign | Do NOT use global TLS trust as a DSC/warehouse certificate-policy anchor, and do NOT infer Indian DSC keys were compromised by the global incident | Authenticated RCAI trust anchor, current CCA policy/CPS and issuing CA, correct OIDs/key purpose, entire PKIX path | NOT AUTHENTICATED |
| eMudhra product sandbox | Public API docs and CA listing do NOT grant tenancy/sandbox | Executed agreement, provider-confirmed specific service grant, allowed endpoints, secrets-manager workload identity and separate LEGAL+SECURITY reviews | NOT AUTHORIZED |
| MCA company and signer | SHA fingerprints and self-reported company records do NOT authenticate identity | Primary-source MCA checks and legally reviewed delegation/authority | NOT VERIFIED |
| Supplier/GRN/stock | Cryptographic screening does NOT prove real supplier, PO acceptance, delivery or custody | Independent operations and finance-approved physical/legal evidence | DISABLED |
| Production deployment | CI passing and synthetic tests do NOT establish independent security certification | Authorized staging IP/DNS, measured DR restore, MFA recovery, security findings remediation and signed approval | HOLD |

## Manual independent release and integration prerequisites (not executed)

1. LEGAL obtains a signed provider agreement explicitly naming legal entities, application/service, scope, sandbox IPs/endpoints, data use terms, signer authority and termination/revocation rights. Confirm out of band with verified provider representatives.
2. SECURITY records authenticated RCAI/CCA hierarchy and relevant current DSC certificate policies, algorithm strength, extended/key usages, name constraints and certificate lifecycle; **do not substitute global TLS roots or test-generated CA roots**. Confirm any applicable public security advisories.
3. SECURITY and infra approve sandbox workload identity and vault-managed ephemeral/rotatable credentials, TLS endpoint pinning under approved change control, egress allowlist, deny-by-default privileges and incident credential revocation. No tokens in Git, chat, CLI args, application database or browser.
4. SECURITY independently validates authentic issuer-bound CRL/OCSP signatures, responder delegation, expiry, freshness, correct serial, replay/outage and revoked/unknown behavior against truly provider-issued certificates. Synthetic CRL/OCSP tests are not externally authenticated evidence.
5. LEGAL/OPS obtains primary-source MCA registration, current signatory/delegation and physical supplier/warehouse paperwork, with scoped and private evidence handling; independently check identities, legal status, and effective dates.
6. SECURITY + OPS independently witness staging network/TLS/DB isolation, negative authorization tests, encrypted restore into a *new disposable* database and measured recovery; then collect owner/legal/security/ops sign-offs. None of these steps is automated by Phase 1AQ.

## Operational constraints

- The fingerprint list is an **additional DENY-only risk indicator**, not a substitute for the platform's current OS trust-store/blocklist updates, RFC 5280 verification, dedicated DSC provider chain or live revocation verification.
- Public certificates can be screened offline by a privileged operator using a separately approved tool; **do not upload provider secrets, private certificates, KYC or customer documents to this project**. The CI preflight cannot accept an arbitrary certificate input.
- An **unlisted** fingerprint, even if well-formed or present in a trusted OS bundle, is NOT a pass. The default decision for every branch of this tool is `HOLD`, `certificatePathAuthenticated:false`, `sandboxServiceAuthorized:false`, `authenticatedLiveRevocation:false` and `productionReleaseAuthorized:false`.
- No external calls, paid services, production write, GRN, procurement dispatch, financial posting, key enrollment or deployment were performed by this phase.

**Acceptance of this internal engineering change is separable from external trust or production release.** Public advisory references support the security risk classification, not provider authorization. Issue #2 and Draft PR #1 remain release HOLD.
