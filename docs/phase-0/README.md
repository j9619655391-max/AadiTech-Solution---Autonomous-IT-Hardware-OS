# Phase 0 GitHub integration

This branch adds documentation, a safe static baseline scanner and an automated typecheck/build workflow only. Existing application source and production schema remain unchanged.

Review the CI run on this branch. The static report is intentionally non-gating; it identifies known architecture risks, not proof of a vulnerability. Do not merge until typecheck/build results are reviewed. No secrets or real customer data should enter the repository.

To run locally: `bun install --frozen-lockfile`, `bun run lint`, `bun run build`, `node scripts/audit-baseline.mjs`. The audit writes `phase0-audit-report.json` which should not be committed.
