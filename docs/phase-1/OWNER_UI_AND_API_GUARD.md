# Phase 1B — Owner UI & Protected API Surface

## Added
- Login UI and session restoration through /api/auth/me.
- Owner logout and in-memory CSRF token handling.
- Route protection before existing AI and database diagnostic endpoints.
- Client requests attach CSRF token to POST and other state-changing requests.
- Anonymous API smoke test (no real MySQL required).

## Critical limitations
- The database still needs migration and owner bootstrap before the UI can log in. The app intentionally fails closed instead of exposing business UI without credentials.
- Business information in the shipped JavaScript bundle, including demo fixtures, is NOT protected just because the React UI requires login. Remove business-sensitive seed values before deployment.
- Existing business entities are still browser-localStorage, not authoritative MySQL data.
- AI responses can still include demo/hardcoded values; do not use them for live finance or stock decisions.
- /api/health is intentionally public and should avoid sensitive operational metadata in future hardening.
- This increment is not yet security-certified: test with actual MySQL, HTTPS reverse proxy, CSRF, session expiry, rate limits, and recovery workflows before production.
- The owner sign-in screen requires correct DB credentials and `APP_URL` equal to the deployed origin in production.
