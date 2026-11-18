## Scope and unchanged release decision
- [ ] This PR remains **Draft / unmerged**. No live provider onboarding, quote release, PO dispatch, stock/GRN, tax/finance posting or production deployment.
- [ ] Confirm work applies to `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` and the intended development branch. Never alter `main` without separate authorization.

## Independent governance requirements (pending, not self-attested)
- [ ] GitHub `main` ruleset/branch protection independently inspected by a different authorized reviewer: no direct/force pushes/deletion, PR-only, stale-review dismissal, most-recent-push review, CODEOWNER approval, no admin bypass, no unresolved threads.
- [ ] Real independently authenticated Security and business-owner reviewers assigned in GitHub; at least two distinct, non-author approvals on the exact HEAD after latest push. A checkbox is **not evidence** of approval.
- [ ] Required CI jobs `baseline`, `mysql-integration`, `production-runtime-scope`, `build-input-provenance`, `review-vendor-intake-hold`, `independent-evidence-hold`, `live-github-governance-hold` independently verified for the exact approved source.
- [ ] Independently signed CI provenance, cryptographic identity/subject verification, retention in separate immutable/WORM store and witnessed DR check obtained; local SHA-256 inventory is **unsigned**.
- [ ] Approved credentials and signed RCAI/CCA/eMudhra legal/cryptographic evidence plus OWNER/SECURITY/LEGAL/OPERATIONS signoffs have been independently authenticated.

## Phase 1BX signed exact-head governance verification (still pending)
- [ ] Required sixth CI job `independent-evidence-hold` completed with truthful ZERO-INPUT/HARD HOLD; do not confuse this with independently signed approval.
- [ ] External administrator, Security reviewer, business owner, CI attestor and off-GitHub WORM auditor independently enrolled and authenticated with separate approved revocable keys; private signing keys never committed.
- [ ] Independently observed branch protection and two actual GitHub non-author approvals bind source HEAD, immutable base SHA, PR test-merge checkout SHA, and fresh external challenge nonce.
- [ ] Five distinct detached Ed25519 signed records bind source, challenge, CI input bundle digest and WORM receipt, verified by independently trusted keyring and external authority; **no in-memory CI fixture qualifies**.
- [ ] Signed CI identity, replay prevention, monotonic external WORM retention and witnessed DR independently checked, and every applicable job including `baseline` is green.

## Phase 1BY actual GitHub-read governance evidence (not independent release approval)
- [ ] Verify seventh `live-github-governance-hold` CI job is complete with source HEAD/base SHA and test-merge SHA correlated to GitHub's own event and PR REST API.
- [ ] Review real GitHub `rules/branches/main` effective rule count, `pulls/1/reviews` newest non-author exact-HEAD review state and legacy branch-protection API status; **403/unavailable is not an approval or proof all rules are absent**.
- [ ] Independently privileged administrator verifies `main` protected branch, no bypass actors and all seven required checks. Applicant-run read-only job alone is not independent authorization.
- [ ] Obtain genuine Security/business reviewer identities and submitted approvals and independently signed CI/OIDC plus external WORM/DR receipts; the job's JSON report is unsigned and cannot provide these.

## Dependency CVE-2026-112366 / GHSA-fc5q-39xc-vjpf
- [ ] Vendor-origin package release fixed for **all** affected extglob patterns, official npm publication, SHA-512 integrity, patched version advisory and real signed Security acceptance independently verified. Do not substitute an arbitrary fork/override or draft GitHub PR.
- [ ] Frozen `bun.lock` regenerated and exact-head zero-Critical/High global audit green, all real MySQL/Chromium/build tests green. Do not waive or change this gate.

**If any box remains unchecked or externally unverified: `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`.** This template sets requirements; it cannot establish branch protection or approval by itself.
