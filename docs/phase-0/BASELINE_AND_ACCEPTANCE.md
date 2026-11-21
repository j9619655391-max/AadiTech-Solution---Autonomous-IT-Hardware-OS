# Phase 0 — Baseline and acceptance gate

## Existing code evidence
- `src/services/storageService.ts`: browser-local business persistence.
- `server.ts`: limited diagnostic + AI endpoints; demo fallbacks and no authenticated business CRUD surface.
- `database/schema.sql`: destructive DROP TABLE initialization; never rerun on live data.
- `src/App.tsx`: client-side approval and optimistic Telegram messages.
- `src/components/WorkflowsAndRAGView.tsx`: simulated RAG and workflow UI.
- No repository CI or automated test suite in initial tree snapshot.

## Phase 0 deliverables
- [x] Dedicated branch isolated from main.
- [x] Add baseline CI (typecheck/build) and non-blocking static issue report.
- [x] Record architecture decision and safety rules.
- [ ] Verify CI workflow execution results and repair actual build failures.
- [ ] Establish automated unit, API integration and E2E test harnesses.
- [ ] Inventory data types and design migration mapping.
- [ ] Security threat model and authorization matrix.
- [ ] Document safe backup/rollback and owner sign-off.

## Release constraints
Phase 0 scaffolding is **not** production readiness. No real external integration, persistent central CRUD, secure authentication, or tested automation is introduced by this commit. Static patterns may produce false positives and are informational. No live data should be deleted or altered.

## Next engineering milestone
Build authenticated MySQL-backed API foundation with migrations and repeatable tests before enabling autonomous sending or orders.
