# Phase 0 Threat Model — Initial Security Boundaries

Status: Initial draft; to be reviewed before production implementation.

## Protected assets
Customer PII, quotations and margins, vendor prices, bank/payment details, passwords and tokens, serialized inventory, approval records, message recipients, financial books and backups.

## Trust boundaries
1. Browser to Express API — untrusted inputs, authenticated session required for business endpoints.
2. Express to MySQL — parameterized SQL, least-privilege DB user, encrypted transport when remote.
3. Server to Gemini — sensitive prompt minimization, tool allowlist, output validation and prompt-injection boundaries.
4. Worker to Telegram/WhatsApp/email/courier/payment providers — scoped credentials, retries, idempotency, delivery reconciliation.
5. Uploaded RFQ/catalog documents — strict MIME/size validation, malware scanning, sandboxed extraction and no automatic execution of document instructions.
6. Admin configuration to workers — policies signed/versioned or transactionally read; emergency stop checked immediately before side effect.

## Priority attacker stories and mandatory countermeasures
| Threat | Failure | Required control | Test |
|---|---|---|---|
| Anonymous actor calls AI/database diagnostics | Leaks metadata or incurs API costs | Auth + rate limits + redacted diagnostics | Unauthenticated requests return 401/403 |
| Sales role approves own margin exception | Unauthorized commercial commitment | Server-side RBAC; enforce separation of duties | Non-owner approval denied |
| Forged Telegram callback | Invalid margin authorization | Verify webhook secret/chat/user and approval nonce/expiry | Forged or replayed callback denied |
| Duplicate job after restart | Duplicate WhatsApp send or purchase order | Transactional outbox, idempotency keys, reconciliation | Rerunning same job has one external effect |
| Concurrent orders reserve same serial | Oversold stock | Row locking/unique serial constraints | Two simultaneous reservations: one success |
| Malicious RFQ prompt injection | Agent leaks secrets/commits actions | Treat documents as data, tools restricted by policy | Injected tool request rejected |
| XSS or client-side manipulation | Session theft / false approval | CSP, sanitization, secure cookies, server enforcement | Tampered client state cannot change approval |
| Production SQL reimport | Data deletion | Immutable schema migrations, backups, no DROP-on-start | Migration rerun preserves data |
| Unconsented marketing | Messaging abuse and reputation damage | Consent, suppression, unsubscribe, quiet hours | Opt-out blocks send, including queued jobs |
| Backup or log access | Exfiltration | Encrypt backups; role access; redact tokens and PII | Restore verified; secrets absent from logs |
| Stale policy in worker | Outbound after kill switch | Check version/pause in transaction before send | Paused mode blocks pending sends |

## Security release gate
Model threats by STRIDE; maintain owner-specific authorization matrix. Define testable outcomes for every critical action. Do not enable real outbound automation before policy enforcement and audit persistence are demonstrated. Use OWASP ASVS requirements as a security verification reference; automated checks are not a substitute for human review.
