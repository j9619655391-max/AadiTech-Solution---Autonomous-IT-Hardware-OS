# Delivery & Definition of Done

For every module M01–M30, completion requires all of:
1. Defined customer/owner business scenarios and UI states (loading, empty, error, success).
2. Versioned database tables/migrations and safe backup/recovery plan.
3. Authenticated APIs with validation, RBAC, audit and idempotency where relevant.
4. Connected frontend with no fabricated success or silently simulated live metrics.
5. Unit, integration and E2E tests including access denial, network failure and retry edge cases.
6. Metrics/alerts for critical jobs and integration failures.
7. Documentation of exact configuration and external provider restrictions.
8. CI green, reviewer acceptance, rollback instructions and explicit release readiness.

**Exception:** This Phase 0 increment is deliberately scaffold-only; it does not meet business module DoD and must not be marketed as production automation.
