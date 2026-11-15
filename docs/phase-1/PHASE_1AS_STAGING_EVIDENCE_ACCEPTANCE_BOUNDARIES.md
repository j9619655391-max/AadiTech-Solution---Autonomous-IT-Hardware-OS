# Phase 1AS — Private staging evidence integrity and release acceptance boundaries

**Date:** 2026-11-15. **Development branch:** `chore/phase0-foundation-20261106`. **Production release:** HARD HOLD. This engineering milestone corrects offline validation of optional private staging evidence files; it does not approve staging, trust a legal signer, verify eMudhra/RCAI/MCA or deploy anything.

## Concrete security weaknesses addressed

The original `verifyStagingEvidenceFiles` implementation interpreted the source checkout using `process.cwd()`. When an operator invoked a staging acceptance review from another working directory, a path *inside the actual Git checkout* could be misclassified as a private external evidence directory. It also used `lstatSync` and a second path-based `readFileSync` operation, which could read a different file following a replacement. Permissions, owner identity and hardlinks were not screened. Relative file paths with symlinked intermediate directory components were not explicitly rejected when they resolved back inside the evidence root. These are preventive hardening findings; no breach or production exposure was established.

## Engineering controls implemented

1. Establish source checkout from `import.meta.url` in the installed `scripts/lib/stagingEvidenceIntegrity.ts` module, canonicalized with `realpathSync`. Reject any evidence root in or under this checkout regardless of process current directory; the root must be an absolute, canonical, non-symlinked **owner-private directory** outside the repository.
2. Require a complete 12-category evidence manifest with exact schema version, ticket, staging origin and exact allowed `kind/path/sha256` item fields; reject unknown fields, duplicate categories, path traversal and noncanonical hex fingerprints. These are **claims of file integrity only**, not verified signatures.
3. Reject final and intermediate symlinks (including aliases resolving to *inside* the evidence root), hardlinked files, nonregular files, files accessible to group/others and file owners different from the review process. This uses POSIX `0600`-like private evidence files and `0700`-like root directory.
4. Open file once with read-only, no-follow, nonblocking descriptor and compare its filesystem device/inode to the pre-open `lstat`. Cap each file to **8 MiB**, read a bounded `size+1` bytes from the opened descriptor and recheck size before hashing. Any unexpected change or unsupported secure file-open platform fails closed.
5. Keep all reports path/redaction safe: only evidence category labels and aggregate count, no raw file content, individual SHA, full private paths, personal data, certificate or signer disclosures.
6. Extend `tests/staging-evidence-integrity.test.ts` with synthetic fixtures for valid owner-private 12-file inventory, changed evidence, unknown fields, weak file and root permissions, hardlinks, symlinked root and intermediate paths, path traversal, missing categories and caller `cwd` outside checkout. Both ordinary unit suite and the standalone `test:staging-security` CI commands exercise this test.

## Boundary limitations

- This protects common local filesystem misconfiguration, symlink and file-swap mistakes. It does not make a hostile administrator, kernel, filesystem driver or privileged parallel writer trustworthy. Use an isolated approved workstation with restricted filesystem access; keep real evidence in the enterprise-authorized private record store.
- A matching SHA-256 confirms only **local file bytes** against a manifest controlled by the same operator. It does not establish that an external reviewer signed the document, that a certificate is valid, that restored data correspond to a genuine production backup, that MCA company registration is current, or that a provider issued an authorization.
- Do not store provider tokens, signing keys, customers' KYC, company signatory secrets, signed originals or raw legal files in chat, Git, app tables or CI fixtures. Actual provider credentials belong exclusively in an authorized secrets manager.
- **Phase 1AT continuation:** The separate `review-staging-acceptance.ts` JSON file-open boundary is now addressed by [Phase 1AT input hardening](PHASE_1AT_PRIVATE_STAGING_ACCEPTANCE_HOLD.md), with additional operator-only controls and unconditional release HOLD. Independent operator-host access and evidence-system controls remain necessary before any live/private evidence is used.
- Existing migration registry remains **27** additive migrations; the held release hash inventory remains **32** entries; `main`, deployed services, vendor APIs and production data are unchanged.

## Mandatory external exit gates — still incomplete

| Requirement | Independent acceptance authority | Current status |
|---|---|---|
| Signed and provider-confirmed eMudhra agreement with precise sandbox service scope | LEGAL and SECURITY out-of-band verification | NOT PROVIDED |
| Approved least-privilege vault-workload sandbox credentials | SECURITY and INFRA | NOT PROVISIONED |
| RCAI/CCA policy-constrained certificate paths, effective issuer authority, authenticated revocation | Independent PKI security reviewer | NOT AUTHENTICATED |
| Primary-source MCA corporate record and delegated signer authorization | LEGAL and independent OPS | NOT VERIFIED |
| Real signed supplier purchase acknowledgment, physical GRN and chain of custody | Supplier + independent OPS/FINANCE | DISABLED |
| Independently approved staging IP/TLS/MySQL, witnessed encrypted restore/MFA recovery, security closeout | SECURITY + INFRA + OPS + OWNER | NOT WITNESSED |
| Formal production change and release authorization | LEGAL + SECURITY + OPS + OWNER | RELEASE HOLD |

**Governance:** Issue #2 remains OPEN; PR #1 remains DRAFT/unmerged; `main` remains unchanged. Internal test success is not a provider, legal, security or production sign-off.
