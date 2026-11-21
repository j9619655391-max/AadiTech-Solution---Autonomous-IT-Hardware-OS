# Phase 1A — Owner authentication foundation

This is an incremental backend capability; it does **not** yet secure all existing app routes or replace client-side data storage.

## Setup order
1. Configure MySQL connection in a protected environment file (never commit it).
2. Run `bun run db:migrate:auth`. This applies only `database/migrations/0001_auth.sql`; **never run the legacy `database/schema.sql` on production data**.
3. Provide `AADITECH_OWNER_EMAIL`, `AADITECH_OWNER_NAME` and `AADITECH_OWNER_PASSWORD` through a secure ephemeral secret environment, then execute `bun run owner:bootstrap`. Remove the bootstrap secret from the environment afterward.
4. Configure the exact HTTPS origin in `APP_URL`; production cookies are HTTPS-only. Use `NODE_ENV=production` behind a trusted HTTPS terminator.
5. Log in using `POST /api/auth/login` with email/password; the browser receives an HttpOnly session cookie and a CSRF token. `GET /api/auth/me` returns current user and token; `POST /api/auth/logout` requires `x-csrf-token`.

## Known gaps / required next increments
- Existing AI, database diagnostics, order, quotation, and client-side workflow routes are **not yet protected** by this increment. Do not expose them to the internet as production.
- Login UI is not connected yet; /api/auth endpoints are backend-only for now.
- The attempt limiter is in-memory and single-instance; add persistent/shared rate limiting, logging, lockout monitoring and session revocation administration before multi-worker deployment.
- Owner bootstrap is safe for a freshly empty `auth_users` table; use DB locking/unique constraints and a protected administrative reset procedure for operational account recovery.
- Add API integration tests with a disposable MySQL database and production reverse-proxy smoke tests.
- This migration never drops data. Review schema carefully before applying to any existing MySQL instance.
