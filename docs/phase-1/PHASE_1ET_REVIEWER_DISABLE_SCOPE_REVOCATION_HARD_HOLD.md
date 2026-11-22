# Phase 1ET — reviewer disable / re-enable scope lifecycle, transaction identity, and revocation HARD HOLD

Date: 2026-11-23. Canonical development branch only; no production migration or release.

## Source-truth gap and denial boundary

Previously the security-admin `PATCH /api/security/reviewers/:id/status` handler invalidated reviewer login sessions but did **not** withdraw already ACTIVE `app_reviewer_scope_grants`. A subsequent account re-enable with a fresh session could therefore regain historical app-local review authority without a fresh nomination. Also, the nomination `REVOKE` path incorrectly required the target still to have the REVIEWER role, preventing explicit cleanup of a role-demoted account's formerly ACTIVE grant. The admin handler's request-level OWNER authentication was not rechecked under a transactional row lock.

## Implemented app-local correction

- The security-admin transaction now locks the acting OWNER `auth_users` row **before** the target reviewer and refuses status/revoke-session mutations unless the actor still has role OWNER and status ACTIVE. Existing CSRF, privileged MFA and step-up policies remain required.
- A DISABLED status transaction now also updates every ACTIVE `app_reviewer_scope_grants` row for that target to REVOKED **before** session deletion and commit. Re-enabling the reviewer never auto-regrants old scopes; a subsequent explicit OWNER scope nomination is required. No external provider or financial/stock action is enabled.
- Existing `REVIEWER_DISABLED` / `REVIEWER_ENABLED` `auth_security_events` remain the account-lifecycle audit, with a bounded `revokedWorkflowNominations` response count. This does **not** claim that an independent per-scope security revocation certificate or legal workflow audit was created by the admin action.
- The scope nomination route permits explicit REVOKE of a known target whose role/status subsequently changed, but only for an existing ACTIVE owner-target-scope grant. GRANT still strictly requires an ACTIVE REVIEWER and all previous safeguards.
- Node source-contract groups and disposable MySQL/HTTP procurement coverage include denied inactive/demoted OWNER, disable withdrawal, cleared sessions, fresh session without inherited scope, explicit regrant, demoted reviewer cleanup, no post-restore access and security event retention. Tests are first-party synthetic CI data, not evidence of outside authorization.
- Both existing 1BV and 1BW selected-source inventories include the new test and security-admin source. No production schema migration, secret, auto-nomination or broadened external trust is introduced.

## Remaining release blockers / operational limits

Independent corporate tenancy/administrative delegation remains unresolved; current admin reviewer lifecycle spans the application's existing account realm and is **not** a claim of legally authorized cross-organization governance. External or direct SQL role changes bypassing this API need a separately reviewed lifecycle/reconciliation mechanism. No formal concurrent-interleaving proof or production penetration test is claimed. Full server-authoritative M01–M30 operations, authentic MCA/eMudhra/CCA/RCAI issuer and live revocation evidence, real independent reviewer identities, signed CI/OIDC/SLSA, WORM/CAS/DR, branch protection and two nonauthor approvals, and authorized staging/security/business/operations signoff are all pending.

**Mandatory hold:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Draft PR #1 must stay unmerged and `main` unchanged; no external messages, quote/PO/stock/finance/tax posting, credentials or deployment. Exact-head hosted CI must be inspected separately, never presumed green.

## Hosted exact-source CI receipt (source SHA, not external release)

- Source commit: `3ca60448449d94fba46f103aa7ec0c431b1ea364`.
- [Push 45075103745](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45075103745) completed SUCCESS, 7 successful jobs + one expected push-only skipped lineage job, attempt 1.
- [Draft PR 45075107402](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/45075107402) completed SUCCESS at attempt 2, 8 successful jobs. First attempt 1 FAILED at the truthful PR-description bounded-evidence-index check (9,465 bytes exceeded 8,192) while other jobs passed; PR description condensed to 4,414 characters and failed job rerun without changing application source, checks or release gates.
- Official GitHub exact-source CheckRuns and Actions Jobs returned 8/8 matching job identities for each event; total latest 16/16 no mismatches. Hosted disposable procurement MySQL suite explicitly reported 1ET reviewer-disable lifecycle `ok 15` and 15/15 passed; source-contract baseline, typecheck, build, browser MFA and staging preflight succeeded.
- This receipt certifies **bounded internal CI observation only**. It does not prove legal tenancy, real reviewer authority, a signed vendor/provider certificate, main protection, independent approval or staging readiness. Documentation commit will have a new SHA requiring its own CI verification.
