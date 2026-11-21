# Phase 1BZ — Immutable Actions SHA refs and independently unapproved CI supply-chain HOLD

**Date:** 18 November 2026 (IST).  
**Correct repo:** j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS.  
**Development branch:** chore/phase0-foundation-20261106; main not merged, PR #1 Draft and Issue #2 open.

## Implemented engineering control

Phase 1BY already binds CI's raw two-parent Git test-merge graph to the PR's exact source/base commit SHAs. Phase 1BZ separately addresses mutable action tags in the GitHub Actions workflow. The development workflow now pins its existing GitHub Actions dependencies to the concrete full-length commits observed in GitHub-hosted run #44282797391 (18 November 2026):

- actions/checkout: 11d5960a326750d5838078e36cf38b85af677262 (8 uses).
- oven-sh/setup-bun: 0c5077e51419868618aeaa5fe8019c62421857d6 (3 uses).
- actions/upload-artifact: ea165f8d65b6e75b540449e92b4886f43607fa02 (9 uses).

The SHA values were recorded as the actual resolved action commits in that CI runner's logs, not claimed as an independent publisher certificate, third-party signature, runner authenticity proof or upstream security assessment. Changes to these pins must be reviewed against genuine upstream code/security advisories rather than blindly following a tag or trusting an applicant-controlled file.

A deny-only local script, scripts/phase1bz-actions-pin-preflight.mjs, checks a bounded regular workflow file, an exact one-file workflow allowlist (ci.yml), all uses tokens against these three immutable commit IDs, required action presence, explicitly restricted action-reference YAML syntax, retained push/PR events, read-only top-level GitHub permissions, and the absence of selected privilege escalation/secret/dispatch triggers. It hashes the observed workflow with SHA-256 and writes an unsigned phase1bz-actions-pin-hold.json with mode 0600. This is a bounded source heuristic, not a complete YAML semantic parser, exhaustive injection assessment, verified installed code tree, attestation or signed release.

The existing build-input-provenance GitHub Actions job runs this gate after Phase 1BV, and archives both local HOLD inventories. The tests/phase1bz-actions-pin.test.mjs suite covers valid exact pins; mutated tags, hashes, owner, Docker and local references; malformed inline and multiline uses forms; missing or extra workflow files; write permission, PR-target and dispatch mutations; missing approved actions; source tampering and explicit non-approval. The Phase 1BV selected source inventory is expanded to include the Phase 1BZ verifier and its tests. The independent baseline, live governance, source parent lineage, MySQL and other jobs continue unchanged.

## Independent blockers and release decision

The previously inspected latest push run #44282797391 and PR run #44282810891 failed baseline because the full dependency graph includes one High picomatch@4.0.7 finding (GHSA-fc5q-39xc-vjpf). A production-only dependency closure that excludes Vite/picomatch or a green Phase 1BZ pin check **does not remediate or waive that gate**. Until a genuine supported upstream vendor patch, renewed lockfile and completed zero-High audit are verified, release stays blocked.

Also NOT VERIFIED: independent authenticated Security reviewers and enforced CODEOWNERS/rulesets; source-to-runner signed workload identity/attestation and third-party immutable WORM/DR evidence; actual CCA/RCAI/eMudhra authorization and revocation chain; independently authenticated MCA/GST legal signatories; approved staging plus owner/operations/security release signatures.

Final decision: productionReleaseAuthorized=false, productionReleaseBlocked=true, releaseDecision=HOLD. No main merge, live provider credentials, customer quote release, supplier PO/GRN, stock posting, tax/finance posting or production deployment.
