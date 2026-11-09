# Phase 1R — Session lifecycle and recovery readiness regression

## Scope and evidence

This increment adds Chromium browser regression scenarios for **synthetic** OWNER and REVIEWER accounts backed by **disposable** `aaditech_ci` only. No production database, Hostinger deployment, customer outbox, or business workflow was modified.

### Browser regression matrix

| Scenario | Expected browser/API behavior |
| --- | --- |
| Wrong password | Error, no authenticated session |
| Invalid second factor | Visible error, no session |
| Owner/reviewer valid TOTP | Distinct authenticated role workspaces |
| Reviewer accessing owner APIs | HTTP 403 |
| Session expiry | HTTP 401; refreshed page returns to login |
| Expired MFA challenge | Recovery code denied; no session or code consumption |
| New challenge with the same unused recovery code | Permitted once |
| Disabled reviewer with existing session | HTTP 401 and login UI after reload |
| Disabled reviewer password login | Generic denial, no MFA challenge or session |
| Reactivation | Old session stays invalid; fresh login still requires MFA |
| Previously consumed recovery code | Rejected on subsequent challenge |
| Logout | Session invalidated and UI returns to login |

Tests update only synthetic test rows inside disposable CI MySQL and cleanly separate expiry/disable checks from production administration. The synthetic disable fixture models the production owner-admin lifecycle transaction (account status change plus deletion of existing sessions). The fixture reactivation directly changes a disposable test row; **these fixtures are not owner/admin APIs or production recovery procedures**. A direct database status flip without revoking sessions is not supported operationally.

These checks complement existing real-HTTP and MySQL integration suites. They do not validate production TLS, physical authenticators, password manager compatibility, cross-device session concurrency, screenshot accessibility, MFA lost-device recovery, or provider availability.

## Staging and disaster recovery acceptance: still pending

The `staging:preflight` gate validates migration checksums, held/disabled outbox invariants and selected authentication settings without modifying a database. Synthetic restore-evidence tests validate acceptance-rule behavior, **not an actual backup or restoration**.

An authorized operator and independent witness must provide:
1. Approved isolated and non-routable `aaditech_staging_*` target, with outbound providers disabled and data-protection controls documented.
2. Encrypted backup archive checksum, source snapshot timestamp, destination restore log, reconciliation and independent sign-off.
3. Actual measured RTO/RPO against **proposed** 60-minute / 5-minute objectives; these figures are not achieved or guaranteed until tested.
4. Separately secured `MFA_ENCRYPTION_KEY` recovery rehearsal; real HTTPS trusted-CA browser MFA and reviewer role scenarios.
5. Recorded incident runbook, account recovery governance, security reviewer approval, contingency plan and evidence retention/teardown.

Do not upload credentials, customers' records, raw MFA material, encrypted backups or production logs to this public Git repository. Keep PR Draft, outbox HELD/DISABLED and `main` unchanged until explicit release authorization.

## Engineering follow-ups

- Add controlled real-device/browser staging suite only after isolated staging infrastructure and security approval.
- Review session/event retention and stale challenge cleanup with measured workload.
- Run a separate dependency audit/security review; CI testing alone does not constitute production readiness.

## Follow-on Phase 1S

Phase 1S adds a CI-only dry-run-first expired-auth retention tool, non-gating dependency advisory artifact and stricter synthetic recovery evidence chronology. See [PHASE_1S_RETENTION_AND_DEPENDENCY_REVIEW.md](./PHASE_1S_RETENTION_AND_DEPENDENCY_REVIEW.md). No production cleanup has been enabled.
