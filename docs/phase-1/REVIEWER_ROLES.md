# Phase 1I — Independent reviewer authentication and segregation of duties

- Migration `0008_reviewer_roles.sql` adds `REVIEWER` to `auth_users.role` and a reviewer-provisioning audit table. Existing OWNER account semantics are retained.
- A reviewer must have a **distinct identity**, provisioned via `bun run reviewer:provision` after setting `AADITECH_REVIEWER_EMAIL`, `AADITECH_REVIEWER_NAME`, `AADITECH_REVIEWER_PASSWORD`, `AADITECH_PROVISIONING_OWNER_EMAIL` in a protected ephemeral environment. No default password or self-service role escalation. Clear the password environment afterwards.
- Reviewer can authenticate using the same secure session cookie but is not permitted to access owner-only CRM, draft mutations, release-preparation creation, business diagnostics, or other owner APIs.
- Internal review decision routes require REVIEWER. Owner cannot review their own draft. Both the distinct-role check and `created_by !== reviewer_id` check are enforced on the server.
- Reviewer read-only queue and quote detail routes should expose only minimum internal draft metadata needed for review; never include customer contact details, password hashes, or browser demo state.
- Internal approvals are **not** external release permission. The release outbox remains `DISABLED`, and no dispatch worker exists.
- Production migration requires backup, restore rehearsal, DB account least privilege, reviewer identity verification and security acceptance. No customer messaging is enabled.

## Critical remaining controls
Reviewer account recovery/revocation UI, MFA, enterprise RBAC, persistent rate limiting and production HTTPS browser E2E remain pending. The provisioning CLI should only be operated by an authorized administrator with secure database credentials.
