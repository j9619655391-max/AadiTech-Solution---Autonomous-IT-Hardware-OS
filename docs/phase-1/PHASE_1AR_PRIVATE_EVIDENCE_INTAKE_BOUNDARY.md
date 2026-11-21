# Phase 1AR — Private external-evidence intake boundary hardening (NONPRODUCTION HARD HOLD)

**Date:** 2026-11-15. **Development branch:** `chore/phase0-foundation-20261106`. **Production release:** HOLD. This phase hardens the existing Phase 1AP optional offline SHA-only inventory file reader. It does **not** connect to eMudhra, provide credentials, authenticate RCAI/CCA or authorize a supplier/warehouse.

## Concrete security problem closed

The original Phase 1AP CLI used `relative(process.cwd(), packetPath)` to determine whether an offline packet was outside the repository. If the process was launched with a different working directory, a syntactically valid SHA-only packet *inside* the Git checkout could be accepted as an external packet. The reader also checked the file using `lstatSync` and then reopened the path with `readFileSync`, leaving a time-of-check/time-of-use file replacement window; owner-only permissions were not checked. This is **administrative evidence boundary** hardening, not a discovered live breach or external compromise.

## Implemented

1. Derive the immutable checkout-root boundary from `import.meta.url` and canonical `realpathSync`, not `cwd`. Reject any packet path inside checkout regardless of caller working directory, and reject any symlinked path component (canonical path must equal the supplied absolute path).
2. Explicitly refuse CI (`CI=true` or `GITHUB_ACTIONS=true`), `NODE_ENV=production`, missing exact `PHASE_1AP_OFFLINE_INSPECTION_APPROVED=YES`, unsupported mode, nonabsolute packet path or symlinked input. This optional inspection is permitted ONLY on an approved isolated nonproduction operator host, NEVER in CI or production.
3. Use an operating-system no-follow, nonblocking, read-only descriptor (`O_NOFOLLOW | O_NONBLOCK | O_RDONLY`); reject runtimes lacking required security flags; compare pre-open `lstat` device/inode to post-open `fstat` to detect common file-swap races.
4. Require a regular file, nonzero size at most **16 KiB**, same effective owner, and no group/other permission bits (mode 0600-like private file). Read at most 16 KiB + 1 through the validated descriptor and reject changed-size files. Release descriptor on success and failure.
5. Keep the existing Phase 1AP exact-scope JSON inventory validator and immutable `HOLD` decision. The output does not echo input path, packet document fingerprints, raw private data, user identity or credentials. Every genuine provider, legal, PKIX, CRL/OCSP, MCA, supplier, stock and production gate remains false/unverified.
6. New `tests/phase1ar-private-evidence-boundary.test.mjs` exercises a complete **synthetic** 16-hash digest inventory stored outside checkout, forbidden in-checkout packet with a deliberately different `cwd`, symlink, weak file permissions, oversize, unsupported modes and CI/production/no-approval denial. Synthetic fixture files are removed by test cleanup; no actual external evidence is read.

## Boundary notes and limitations

- POSIX/Linux secure-open semantics are required. An unsupported platform **fails closed**; this is intentional. Owner/group/other permissions are mandatory for offline evidence packets, unlike publicly distributable incident fingerprints.
- This reduces symlink, mistaken-worktree and simple file-replacement risk; it does not establish a general defense against a privileged host administrator, hostile local root process, malicious filesystem driver, or concurrent privileged modifications. Operator access control, file-system isolation, monitoring and private evidence retention remain separately required.
- A digest can prove only a local byte fingerprint, not authenticity of legal documents, out-of-band contact, authorized provider tenancy, certificate path trust, live revocation or MCA signer validity. Even a complete synthetic 16-hash packet always yields `releaseDecision: HOLD`.
- Source document records, actual KYC and executed provider agreement are retained under authorized organizational evidence management; **do not put them in Git, CI artifacts, ChatGPT, normal app tables or ad hoc storage**. Provider credentials must reside in an approved secrets manager, not in this tool or its packet.
- The canonical checkout path must be resolvable; the operator must not execute the optional intake through a symlinked checkout/file path. For automation/CI, use only `node scripts/provider-authority-preflight.mjs --ci-hold`.

## Independent external exit gates (still pending)

| Gate | Acceptance authority | Current state |
|---|---|---|
| Executed provider contract, exact sandbox product and signed legal service grant | Legal + out-of-band provider confirmation | NOT PROVIDED |
| Least-privilege rotated application credential via approved workload identity | Security + infrastructure | NOT PROVISIONED |
| Out-of-band authenticated RCAI / applicable CCA-issued hierarchy, full policy constraints and revocation | Independent PKI security reviewer | NOT AUTHENTICATED |
| Actual CRL/OCSP responder authorization, correct issuer/serial, freshness, signed status and outages | Independent PKI security reviewer | NOT AUTHENTICATED |
| Primary-source MCA corporate existence and lawful signatory authority | Legal + operations | NOT VERIFIED |
| Real supplier acknowledgement/physical GRN, site serial provenance and signed approvals | Operations + finance | DISABLED |
| Isolated staging/recovery test, source/build match and independent security/operations/owner signoff | Independent reviewers | RELEASE HOLD |

**No SQL schema migration or deployed service change.** Continue to maintain 27 additive checksum-tracked migrations, 32-file held release hash inventory, Issue #2 OPEN, PR #1 DRAFT, `main` unchanged. CI success proves internal regression tests only; real provider access and production approval remain pending.
