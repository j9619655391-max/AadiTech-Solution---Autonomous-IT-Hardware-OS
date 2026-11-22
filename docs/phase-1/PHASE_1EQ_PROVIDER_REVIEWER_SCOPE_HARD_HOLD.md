# Phase 1EQ — provider reviewer authorization hardening (HARD HOLD)

Date: 2026-11-23. Development branch only. This is an engineering acceptance protocol, not a security certification or production authorization.

## Vulnerability and scope
A globally authenticated REVIEWER could list or decide evidence submitted by an unrelated OWNER in the provider bridge, sandbox, named selection and provider onboarding workflows. Preventing self-review alone did not establish an OWNER-to-REVIEWER nomination. Exposed candidate metadata included offline root pins, cryptographic credentials, certificate/corporate claims, provider policy and MCA/legal signatory digests; these do not represent genuine external authority.

## Implementation
- Migration **0047** append-only extends first-party reviewer grant and audit-event enums with `PROVIDER_BRIDGE`, `PROVIDER_SANDBOX`, `PROVIDER_SELECTION`, `PROVIDER_ONBOARDING`. No past grants, legal authority or live provider access are created.
- Existing OWNER-only `/api/reviewer-scopes` requires CSRF, privileged MFA, password step-up, correct REVIEWER account and explicit audited OWNER→REVIEWER workflow nomination; revocation ends access.
- All **10** provider reviewer queues filter candidates in SQL by current exact scope and ACTIVE OWNER/REVIEWER roles before returning data. Certificate/credential detail requires matching OWNER nomination. All **10** provider review decisions check active grants using `FOR UPDATE` in their durable write transaction. Missing/revoked/inactive grants fail closed with not-found behavior.
- Dual internal LEGAL and SECURITY app reviews still require distinct actors for packet review. They never constitute regulatory or statutory independence.

## Testing and CI gates
Require full exact-source hosted push + Draft PR GitHub Actions runs with frozen dependency advisory gate, source custody, unit/TS test, typecheck/build, real disposable MySQL migration with checksum/idempotent rerun, all provider prerequisite and integration suites, security checks and Chromium MFA smoke. Retain historical failures, distinguish push 7 plus expected skip from PR 8/8, and never infer external acceptance from passing CI.

Disposable MySQL fixtures explicitly insert synthetic OWNER→REVIEWER nominations, including distinct onboarding SECURITY reviewer. Regression tests verify revoked scope hides queue entries and direct review requests return HTTP 404, then explicit regrant restores only internal review access.

## External blockers
Written eMudhra provider approval and managed credentials, authenticated CCA/RCAI issuer chain plus live signed CRL/OCSP, MCA corporation/signatory mandate, independently authenticated nonauthor reviewer and witness keys, off-platform WORM/CAS/trusted timestamps and DR evidence, protected-main ruleset/CODEOWNERS and independent reviewers, signed third-party OIDC/SLSA provenance, authorized staging and all original Issue #2 M01–M30 acceptance gates remain pending.

**Immutable release hold:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. No merge, deployment, production migration, external messages, provider credential activation or real quote/PO/GRN/stock/finance/tax posting.
