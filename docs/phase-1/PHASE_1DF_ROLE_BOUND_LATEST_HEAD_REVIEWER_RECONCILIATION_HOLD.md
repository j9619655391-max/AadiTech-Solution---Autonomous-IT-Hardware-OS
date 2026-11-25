# Phase 1DF — Repeated role-bound GitHub review reconciliation (read-only, HARD HOLD)

Date: 20 November 2026 IST. Correct repository: `j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS`; engineering only on `chore/phase0-foundation-20261106`. `main` remains unchanged unless an independently approved administrator later makes an explicit out-of-band change.

## Actual gap addressed

A count of at least two GitHub `APPROVED` reviews on a HEAD cannot prove that the **specifically appointed corporate Security and Business officers** each approved it. Phase 1CO already has an operator-only source-bound per-login review check; Phase 1DC has an independent official GitHub current PR/main/readiness collector. Phase 1DE reviewed these separately. Phase 1DF reconciles them using **two** independently fetched 1CO reviews bracketed by **two** 1DC full read-only governance snapshots, not by treating a count or human-supplied username as a mandate.

## Read-only operator procedure

**Only after company Owner and Legal independently verify and appoint the two actual nonauthor officers**, a separately authorized human operator can use a narrowly scoped `GITHUB_READ_TOKEN` from an approved secrets manager, never chat, shell argument, Git or log:

```bash
node scripts/phase1df-role-bound-readonly-reconciliation.mjs \
  --inspect-role-approvals-readonly VERIFIED_SECURITY_LOGIN VERIFIED_BUSINESS_LOGIN
```

The new explicit manual command is rejected in GitHub Actions and without a non-empty read-only token, distinct syntactically valid nonauthor usernames, or explicit flag. It reuses the preexisting **fixed-endpoint GET-only** 1DC/1CO/1CM readers; no GitHub POST/PUT/PATCH/DELETE or policy installation, request for review, merge, credential enrollment, actual business transaction or deployment. It deliberately **omits names, tokens and raw source responses from its output**, reporting only bounded technical booleans, exact GitHub source/base SHA, anomaly codes, and permanent release HOLD.

Its pure `assessRoleBoundReadOnlyReconciliation` requires each 1DC record to identify exact repo/PR/base, stable source HEAD, complete review pagination, valid bounded totals and explicitly HELD release flags; both sources must report the same HEAD and main SHA. Each of the two 1CO readback records must confirm the *specific two nominees individually* approved the *current* source HEAD with current technical GitHub write permission, complete pagination, unchanged PR during its own read, no source errors, and no corporate role assertion. Submitted-review/approval totals must agree across both role reads **and** both independent governance snapshots. Incomplete, mismatched or changed counts, stale HEAD, contradictory GO, missing permission or partial role approval remain denied. The direct main protection `403` remains **UNKNOWN**. Main CODEOWNERS and actually applied no-bypass rules are separate checks and cannot be satisfied by a draft from the development branch.

No realistic API polling can guarantee that a review will never be dismissed or rules changed *after* the final read. A passed technical join remains a transient **untrusted technical observation only**, not an authenticated corporate appointment, protected-main authorization, production approval, external revocation trust, CAS/WORM, signed SLSA/OIDC or staging signoff. No real nominees or access credentials were supplied or invoked in this engineering change.

## Adversarial verification and source custody

- `scripts/phase1df-role-bound-readonly-reconciliation.mjs`: pure exact-head read-only reconciler + human-only CLI.
- `tests/phase1df-role-bound-readonly-reconciliation.test.mjs`: 21 Node test groups, including 1CO role quorum spoof, stale approvals, changed counts, duplicate read mismatch, invalid 1DC source, 403 unknown, missing main CODEOWNERS/rulesets, invalid counter, fabricated GO and permanent HOLD even when *synthetic* technical fields are all true.
- Both new source/test files included in Phase 1BV and 1BW bounded build/reviewer source custody; no workflow permissions or external access added. The existing `package.json` Node test glob runs the new tests in CI.

## Acceptance / external blockers

At phase start, GitHub's officially observed `main` is `b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b`, PR #1 Draft/open/unmerged, Issue #2 open; 0 actual submitted reviews, 0 listed rulesets, all 3 standard base-main CODEOWNERS locations 404 and direct branch protection 403/UNKNOWN. These observations cannot be used as role-specific approvals. Production release still requires genuine corporate role mandates, independent legal/company verification, authorized admin installation/readback of effective no-bypass main policy, two genuine current-HEAD approvals, approved provider signed CA/CRL/OCSP, external immutable CAS/WORM/DR and Security/Legal/Ops/Owner signed staging acceptance.

**No GO:** `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`; no merge or deployment. After commit, verify **exact new SHA** hosted push+PR CI and official per-suite Checks/Actions Jobs; do not claim future runs as passed in this document.


## Exact source-HEAD hosted CI and official evidence closure — 20 Nov 2026 IST

- **Engineering source commit** `50453e024bf86aa6bc379ec34ab822718082804e` on `chore/phase0-foundation-20261106`. [Push run 44723152621](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44723152621): **completed/success**, seven required job successes plus one expected source-merge-lineage job **skipped** on push. [PR run 44723162051](https://github.com/j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS/actions/runs/44723162051): **completed/success**, all **8/8 required jobs successful**.
- Official `/commits/50453e024bf86aa6bc379ec34ab822718082804e/check-runs?per_page=100` returned **16 checks across two separate suites**. PR suite `121053551325`: exact eight GitHub Actions App `15368` check IDs/name/source-run/conclusions matched separately fetched eight Actions Jobs in run `44723162051`. Push suite `121053526694`: same cross-API agreement for run `44723152621`, with seven success and one expected skipped. No cross-suite borrowing or pretending push is 8/8 success.
- Hosted baseline typecheck, Node tests, build, frozen-lock dependency advisory verification and disposable MySQL migration/integration plus Chromium MFA/role smoke passed. Phase1DF adds 21 adversarial test groups; local Node run passed all 21, and hosted baseline passed. No actual human-nominated 1DF operator command was invoked, because genuine independently appointed role-holders and approved operator token are absent.
- Actual post-source GitHub readback: zero submitted PR reviews; zero listed repository rulesets; `main` CODEOWNERS at the three standard paths each 404; direct main branch protection GET 403 = **UNKNOWN**, not disabled. `main=b5af0313de5f2439dcf2aa4b4e8bb241220b5a6b`; PR #1 Draft/unmerged and Issue #2 open. No legally delegated Security/Business authority, admin change, provider eMudhra/CCA/RCAI/MCA evidence or live CRL/OCSP, external WORM COMPLIANCE CAS/DR, signed SLSA/OIDC or staging signoffs.
- PR #1 title/body and Issue #2 factual verification comment updated; original remaining external acceptance blockers remain unresolved.

**PERMANENT HARD HOLD** remains: `productionReleaseAuthorized=false`, `productionReleaseBlocked=true`, `releaseDecision=HOLD`. This documentation-only follow-up commit is not the above engineering source SHA; run new exact HEAD CI before asserting its status.
