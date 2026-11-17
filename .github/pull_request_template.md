## Scope and unchanged release decision
- [ ] This PR remains **Draft / unmerged**. No live provider onboarding, quote release, PO dispatch, stock/GRN, tax/finance posting or production deployment.
- [ ] Confirm work applies to `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS` and the intended development branch. Never alter `main` without separate authorization.

## Independent governance requirements (pending, not self-attested)
- [ ] GitHub `main` ruleset/branch protection independently inspected by a different authorized reviewer: no direct/force pushes/deletion, PR-only, stale-review dismissal, most-recent-push review, CODEOWNER approval, no admin bypass, no unresolved threads.
- [ ] Real independently authenticated Security and business-owner reviewers assigned in GitHub; at least two distinct, non-author approvals on the exact HEAD after latest push. A checkbox is **not evidence** of approval.
- [ ] Required CI jobs `baseline`, `mysql-integration`, `production-runtime-scope`, `build-input-provenance`, `review-vendor-intake-hold` independently verified for the exact approved source.
- [ ] Independently signed CI provenance, cryptographic identity/subject verification, retention in separate immutable/WORM store and witnessed DR check obtained; local SHA-256 inventory is **unsigned**.
- [ ] Approved credentials and signed RCAI/CCA/eMudhra legal/cryptographic evidence plus OWNER/SECURITY/LEGAL/OPERATIONS signoffs have been independently authenticated.

## Dependency CVE-2026-112366 / GHSA-fc5q-39xc-vjpf
- [ ] Vendor-origin package release fixed for **all** affected extglob patterns, official npm publication, SHA-512 integrity, patched version advisory and real signed Security acceptance independently verified. Do not substitute an arbitrary fork/override or draft GitHub PR.
- [ ] Frozen `bun.lock` regenerated and exact-head zero-Critical/High global audit green, all real MySQL/Chromium/build tests green. Do not waive or change this gate.

**If any box remains unchecked or externally unverified: `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`.** This template sets requirements; it cannot establish branch protection or approval by itself.
