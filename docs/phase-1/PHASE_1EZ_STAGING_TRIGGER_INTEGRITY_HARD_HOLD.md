# Phase 1EZ — live read-only staging trigger integrity gate (HARD HOLD)

Date: 2026-11-23. Scope: disposable MySQL CI and separately authorized isolated TLS staging **only**. This is a defense-in-depth *technical preflight*; it is not an outside-DB attestation, external legal/security approval, a deployment permit, or production release.

## Gap and correction

1EW–1EY verified the checksum-locked migration 0048 and installed SQL trigger bodies when the 0048 migration runner was (re)executed. A later standard `staging:preflight` could previously report internal readiness based on checksum and other data checks without inspecting the **currently installed** `information_schema.TRIGGERS.ACTION_STATEMENT`. A privileged SQL actor may replace or add a trigger after the last migration rerun.

`scripts/staging-preflight.ts` now:
- Calls its existing deny-by-default CI/approved TLS staging target classifier **before** connection.
- Runs the existing read-only `runStagingPreflight`, which checksum-checks **all 48 migrations**, then separately queries the live database's **all** `auth_users` UPDATE trigger names, timing and bodies (no AFTER-only metadata filter).
- Reuses the 1EY literal-preserving pinned-body verifier. Exactly two expected AFTER UPDATE triggers must match. Any absent, duplicate, extra, BEFORE, changed-literal, changed-predicate, or otherwise unexpected body fails the new gate.
- Returns `triggerIntegrity: "PASS" | "HOLD"`. Any SQL error / metadata privilege denial / drift yields `ready:false`, a fixed non-sensitive problem string, and a nonzero CLI exit code; underlying SQL errors, trigger bodies and credentials are **not** printed by this new gate.
- Performs **only** a SELECT for the additional gate. It neither migrates, drops nor repairs triggers; never restores reviewer privileges or changes migration 0048.
- Includes the modified CLI in both 1BV build-input provenance and 1BW review-intake local source inventories; the existing staging-preflight tests include malicious SQL metadata, BEFORE trigger, missing trigger and metadata-denial cases.

## Verification steps

1. On exact development HEAD, run `bun run test` and `bun run lint`. GitHub CI's disposable real-MySQL pipeline must execute 0048 twice and run `STAGING_PREFLIGHT=1 bun run staging:preflight`.
2. Confirm the check returns `triggerIntegrity:"PASS"` only when installed metadata matches the pinned bodies, and fail-closed tests reject a changed state literal / unexpected BEFORE trigger.
3. Validate both push and Draft-PR GitHub Actions at the **same source SHA**, and record any failing earlier runs rather than erasing them.
4. Outside disposable CI, require a separately approved isolated TLS staging target and explicit operator sign-off. Do not invoke these scripts against production.
5. If `triggerIntegrity:"HOLD"`, preserve non-sensitive incident evidence, independently inspect SQL privileges and actual trigger definitions, and reconcile under authorized change control. Do not auto-repair or silently waive.

## Inherent limitations / release blockers

The check is a **point-in-time observation from the application-controlled DB session**. A privileged DBA can still change/disable enforcement afterward, or tamper with metadata, grants or query execution; this is **not** DBA privilege separation, durable external timestamped WORM/CAS, tamper-proof runtime authorization, or independent security witness evidence. There remains a time-of-check/time-of-use window. Actual adversarial concurrent transaction tests, external privileged-access attestation and human sign-off are still required.

Issue #2 and M01–M30 retain all genuine supplier/customer finance/inventory/AMC/ticket workflows, tenant/legal signatory mandates, independent provider/CCA/RCAI/eMudhra authority and current revocation chain, actual protected-main CODEOWNERS rules, two nonauthor signers, signed provenance, external encrypted DR/WORM, approved isolated staging and operational acceptance as **OPEN**.

**Release invariants:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. PR #1 remains Draft/unmerged; `main` unchanged. No production migration, live customer/supplier contact, actual invoice/PO/GRN, inventory or tax posting, or live provider activation.
