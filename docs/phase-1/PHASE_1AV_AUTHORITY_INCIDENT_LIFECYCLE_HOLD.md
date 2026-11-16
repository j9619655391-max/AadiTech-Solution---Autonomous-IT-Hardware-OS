# Phase 1AV — External Authority Evidence Lifecycle, Trust-Anchor Change Governance and Revocation Incident Response

**Date:** 2026-11-16  
**Branch:** `chore/phase0-foundation-20261106`  
**Status:** INTERNAL ENGINEERING / SYNTHETIC TESTS ONLY — **PRODUCTION HARD HOLD**

## Purpose and boundaries

Phase 1AU introduced offline SHA-only review-window/expiry/policy drift detection. Phase 1AV adds an **administrative incident journal** and explicit quarantine on a proposed trust-anchor change, suspected key compromise, claimed revocation, unavailable revocation information, provider-access withdrawal, expired evidence, journal rollback, or journal-history fork.

The journal is **self-hashed, not signed**. Anyone who can replace the stored journal can also recompute every hash. It does not establish independent source authenticity, a trusted timestamp, the provider's RCAI/CCA chain, PKIX trust, a signed CRL/OCSP response, legal signer authority or operational authorization. This change provides **negative governance checks only**.

## Implemented code

- `scripts/lib/phase1AvAuthorityLifecycle.mjs` validates a bounded 64-event, contiguous sequence-1-based journal for the exact existing evaluation-only provider (`EMUDHRA_CCA_EVALUATION_ONLY`) and the proposed supplier/warehouse sandbox scope. Unknown keys, secret fields, production flags, malformed SHA-256, bad UTC timestamps, duplicate event transitions and invalid event types are rejected.
- Eight allowed **untrusted claim** event categories: `TRUST_ANCHOR_ROTATION_PROPOSED`, `TRUST_ANCHOR_COMPROMISE_SUSPECTED`, `REVOCATION_CONFIRMED_CLAIM`, `REVOCATION_SOURCE_UNAVAILABLE`, `PROVIDER_ACCESS_WITHDRAWN_CLAIM`, `EVIDENCE_REVIEW_EXPIRED`, `INCIDENT_ACKNOWLEDGED`, `INCIDENT_CLOSURE_CLAIMED`. The “CLAIM” events are *not authenticated*. They do not execute provider revocation or incident-closure work.
- Each entry contains exact schema version, sequence, canonical UTC event time, event/incident type, non-PII opaque incident and actor references, a claimed public evidence SHA-256, optional candidate public trust-anchor fingerprint, a bounded claimed reviewer-role inventory, previous-entry SHA and current-entry SHA. Hashes cover the ordered fields via deterministic JSON encoding.
- Anchor-rotation proposals and incident-closure claims require **two claimed distinct LEGAL and SECURITY reviewer refs, both different from the actor**. That is only basic separation-of-duties validation, **not** authentication of reviewer identity, legal signoff, real signed certificates or CA approvals. An anchor proposal itself activates quarantine; there is **no trusted enrollment API**, even when both claimed reviewers are present.
- A closure or acknowledgment claim must reference an earlier risk-triggering entry in the same incident history. Closure claims can *never* switch off quarantine or release the system. Reuse of an anchor candidate, replay of an event category for the same incident, a broken journal hash or a missing previous SHA fails closed.
- When comparing two valid journals, Phase 1AV rejects rollback and flags any history fork/rewritten prior event, even if the new branch is locally self-consistent. A missing independently authenticated checkpoint stays a blocker even when a journal prefix matches.
- Phase 1AU's **actual function** is invoked when optional prior/current SHA-only policy snapshots are provided: any public policy or incident-list drift, expired claimed review, revoked/unknown claimed status or timeline rollback activates quarantine. **No external evidence is inspected or automatically trusted**.
- `scripts/phase1av-incident-preflight.mjs --ci-hold` is the only CLI mode. It reads no files, credentials, private packets, CA certificates, journals or external endpoints. It outputs explicit `releaseDecision:HOLD` and hard-false provider, trust-anchor enrollment, CRL/OCSP, finance, stock, supplier-dispatch and production states. Other CLI modes reject with sanitized errors. No automatic clearing, secrets-manager integration or incident notifications are claimed.
- `tests/phase1av-authority-lifecycle.test.mjs` checks all high-risk triggers, anchor-review role collisions, tampering, duplicate/replayed transitions, rollback, full-prefix fork, forged positive flags, false incident closure, Phase 1AU policy expiry/changed CPS integration, production-blocked invariants and --ci-hold negative behavior. Existing `bun run test` discovers this Node .mjs suite, and GitHub Actions runs the zero-input preflight directly.

## Response plan for a *real* external incident (NOT AUTOMATED)

| Step | Required independent operator work | Release treatment |
|---|---|---|
| 1. Quarantine | SECURITY and INFRA isolate affected workflows, prevent outbound supplier/customer messages and stock/finance writes, preserve logs and timestamps | HARD HOLD |
| 2. Authenticate scope | Through verified CCA/RCAI/provider contacts establish affected issuer, serial, root/intermediate, product policy, effective incident window and legal service entitlement | HARD HOLD |
| 3. Credential containment | Authorized INFRA/SECURITY personnel revoke or rotate application workload keys, tokens and provider grants exclusively through the approved secrets manager and provider mechanisms | HARD HOLD |
| 4. Independent revocation | Validate issuer-bound, responder-authorized **signed** CRL/OCSP including freshness, responder delegation, revocation, unknown/outage and negative/replay cases | HARD HOLD |
| 5. Anchor changes | Obtain authenticated root/issuer public keys, real RFC 5280 policy-constrained PKIX validation, protected change record and separately signed LEGAL+SECURITY approvals | HARD HOLD |
| 6. Confirm organization/signer | Reauthenticate MCA primary-source company master data and legally effective signer delegation; independently validate warehouse/supplier custody | HARD HOLD |
| 7. Recover and witness | Re-run isolated TLS staging, MySQL checks, MFA, backup/restore and measured RTO/RPO; preserve externally controlled immutable evidence trail | HARD HOLD |
| 8. Production decision | OWNER, LEGAL, SECURITY and OPS review real provider/legal/security evidence and issue an explicit scoped production change authorization outside this module | **Still HOLD in Phase 1AV software** |

### Self-hashed journal is not immutable evidence

Journal digests demonstrate only *local self-consistency*. They cannot stop deletion or a complete rewrite by an operator who can modify the input and recompute its hashes. A credible audit chain needs independent signed checkpoints, protected storage, tamper-evident retention, authenticated reviewer identities and organization-level out-of-band controls. **None is provisioned by Phase 1AV.** A human may reconcile proposed changes in a separately authorized workflow; this software has no allow-to-production state.

Do not place executed agreements, confidential certificates, personal MCA/KYC records, signing/private keys, passwords, API credentials or provider secrets into the journal, Git, chat, CI or test artifacts. Operator and reviewer refs are synthetic non-PII identifiers; this module does not accept contact information or free-form evidence documents.

## Explicit test/CI acceptance

- Run `node scripts/phase1av-incident-preflight.mjs --ci-hold` or `bun run provider:incident-preflight --ci-hold`; expected exit 0 with **releaseDecision HOLD** and no private IO.
- Run `bun run test` for the new synthetic journal and all prior Phase 1AP/1AQ/1AU hold regression cases. CI also validates production configuration, dependency baseline, build and isolated disposable MySQL/Chromium integration.
- **No new migrations** (27 registered SQL files unchanged), provider services, live credentials, real revocation requests, actual incident clearing, GRN/inventory movement, supplier dispatch, finance posting or production deployment.
- Issue #2 remains OPEN, PR #1 remains Draft/unmerged, `main` unchanged, and the previously held build-artifact inventory scope is not changed by this logic.

## Outstanding real-world acceptance

The executed eMudhra sandbox agreement and exact service entitlement, vault-provisioned workload credentials, independently authenticated RCAI/CCA hierarchy and correct CPS/CP OIDs, authenticated live CRL/OCSP responders and revocation, MCA/authorized signatory evidence, full network/backup restore staging acceptance and signed cross-functional production authorization remain **NOT VERIFIED**. Successful GitHub CI is evidence only for **internal synthetic engineering checks**, not external provider, legal or security approval.

**Final decision: HARD HOLD.** Never promote self-generated keys, reviewer IDs, journal hashes or synthetic CRLs to genuine external CA authority.
