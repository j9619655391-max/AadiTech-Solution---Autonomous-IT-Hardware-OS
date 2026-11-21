# Phase 1BJ — Applicant commercial evidence quarantine contract

Date: 2026-11-17. Branch: `chore/phase0-foundation-20261106`. **Internal engineering only; production HARD HOLD.**

## Implemented in this small phase
- `server/commercialIntegrity/applicantEvidence.mjs` classifies **applicant-supplied** quote, PO and warehouse reference metadata without treating strings, hashes or identity claims as legal authority.
- Deterministic deny-only checks: permitted record types, subject/actor UUID syntax, SHA-256 digest syntax, safe bounded metadata, issue/expiry windows, explicit clock, and caller-supplied digest replay register. Missing or malformed prerequisites fail closed.
- `tests/bj-commercial-provenance.test.mjs` covers coherent-but-unverified claims, tampering, replay, metadata path injection, expiration, future timestamps and missing inputs. Existing `node --test tests/*.test.mjs` runner discovers the regression file.

## Explicit boundary
This classifier is **not yet wired to a new API route or authoritative provider verifier**, and a caller-supplied replay register is not an atomic durable replay database. Even a locally well-formed record remains `APPLICANT_ASSERTED_UNVERIFIED`. It does not verify a cryptographic signature, trusted issuer, CCA/RCAI/eMudhra chain, live signed OCSP/CRL, MCA/GST ownership, SKU title, independent WORM or DR. All issuance, dispatch and stock posting outputs remain false, and releaseDecision remains HOLD. No secrets, external traffic, schema migrations or real transaction side effects.

Next: integrate a real transactional evidence-quarantine row and subject-bound digest lookup in disposable MySQL, then run adversarial HTTP scope/MFA/CSRF tests **before** any external provider integration. External verifiers require independently authorized sandbox credentials, independent approvers and written approval. PR #1 must stay Draft/unmerged and Issue #2 open; `main` unchanged.
