# Phase 1N — Read-only staging readiness and restore rehearsal plan

## Automated safeguards delivered

`bun run staging:preflight` performs **read-only** checks:
- Exact SHA-256 checksums of migrations 0001–0013 compared with `schema_migrations`; missing/altered/unknown migrations fail the report.
- Held quote preparations/outbox integrity: only `HELD`, `DISABLED`, matching digests, no orphan/missing events.
- MFA encryption key format; explicit privileged-MFA policy; owner and reviewer enrollment if privileged policy is enabled.
- Strict target allowlist. CI requires `STAGING_PREFLIGHT=1`, `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `NODE_ENV=test`. Isolated staging requires `STAGING_PREFLIGHT=1`, `STAGING_DISPOSABLE_CONFIRMED=YES`, `DB_NAME=aaditech_staging_*`, and `DB_SSL=true`.

The command prints only a sanitized JSON result. It does not output credentials, password hashes, encrypted TOTP secrets, recovery codes, session tokens, customer records, or quote line contents. It does not insert, delete, restore, dump, migrate, send messages, or modify production.

A `ready:true` result means **these limited automated database invariants passed**. The report explicitly retains `NOT_VERIFIED` flags for backup/restore rehearsal, real HTTPS browser MFA tests, and encryption-key recovery. It must never be interpreted as production deployment approval.

## Manual isolated staging backup/restore rehearsal — not performed

1. Authorized operator records change ticket, approved source database, its approximate size, table count, sensitive-data handling plan, retention/expiry and the designated **new isolated** staging target. Production must be read-only during export, and a consistent transaction snapshot is needed for InnoDB.
2. Export using the approved provider tool and encrypted storage; validate checksum and access controls. Avoid exposing secrets in shell history or command line arguments. Store encryption keys separately; review GDPR/Indian privacy and customer contract constraints before copying personal data.
3. Restore only to a **fresh** database named `aaditech_staging_...` with restricted credentials, non-routable network, outbound network and integrations disabled. Never restore onto the source database or an existing production schema. This step is intentionally **not automated by this repo**.
4. Independent verifier compares schema, row-count reconciliation for auth, CRM, quote drafts, revisions, holds and audit tables, as well as sampled record hashes under approved privacy controls. Rehearse recovery of `MFA_ENCRYPTION_KEY` in a secure nonproduction environment; never print the key.
5. On the restored staging copy, test additive migrations in order and rerun them, run the preflight with the staging opt-in variables and verified MySQL TLS. Check owner/reviewer MFA login, CSRF, roles, session revocation, audit and HELD/DISABLED outbox via a real HTTPS browser.
6. Record elapsed restore time and evidence against RTO/RPO targets, reviewer sign-off, backup deletion date and secure disposal after the rehearsal. Never equate a CI disposable-MySQL test with a real source backup restore.

## Blockers before production

Real backup export and restore, TLS CA chain with Hostinger, HTTPS browser E2E and MFA device tests, privileged account recovery governance, central audit alerts, external penetration review, secret rotation, database least-privilege, disaster recovery acceptance, and owner sign-off remain pending. The legacy `/api/db/schema-sql` endpoint now returns HTTP 410 and the readiness checklist explicitly forbids importing `database/schema.sql`.

No live hosting, production migration, real customer sending, invoice, order or stock reservation is enabled. PR must remain Draft.
