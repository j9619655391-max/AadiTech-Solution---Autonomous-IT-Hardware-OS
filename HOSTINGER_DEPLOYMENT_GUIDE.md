# AadiTech Solution — Hostinger staging security acceptance guide (Phase 1W)

**This is a gated operational review guide, NOT permission or instructions to deploy to a real site.** Phase 1W code is on a development branch in a **Draft PR**. No production migration, Hostinger configuration change, external dispatch or real account provisioning has taken place.

## Stop: legacy instructions are unsafe

Do **not** import or execute `database/schema.sql` on an existing database. The legacy demo schema contains seed/example objects and is NOT an upgrade path for the authenticated CRM/quote system. The legacy schema download API is disabled (HTTP 410). Use only checksum-tracked additive migrations 0001–0013 **after** a separately authorized encrypted backup/restore rehearsal. Do not install demo/master passwords or copied credentials.

The old deployment guide incorrectly suggested importing the legacy schema and configuring MySQL with TLS disabled. That advice is **superseded and withdrawn**. Do not copy old screenshots, YAML or configuration into a live service.

## Release gates (manual — all currently NOT VERIFIED)

1. **Change authority:** Project owner, engineering approver and independent security reviewer approve the specific environment, deployment scope and rollback ticket. Confirm business outage constraints; PR must remain Draft until approvals.
2. **Hosting capability:** Independently verify the actual hosting plan permits the required persistent Node.js runtime, trusted reverse-proxy headers, network restrictions and TLS. Do not assume a particular hPanel product tier, proxy address, document root or Node runtime is supported.
3. **Ingress isolation:** Obtain **verified** actual ingress addresses from the provider. Configure proxy to replace client-supplied `X-Forwarded-For` and `X-Forwarded-Proto`. Prevent clients from connecting directly to the application listener. Only then set the explicit trusted CIDRs; NEVER set Express `trust proxy=true` or trust whole hosting networks.
4. **HTTPS and environment:** Provision valid external HTTPS certificate and secure cookies. Set `APP_URL` to the HTTPS origin, `APP_REQUIRE_HTTPS=true`, narrow `APP_TRUSTED_PROXY_CIDRS`, verified `APP_BIND_HOST` (loopback by default), and `NODE_ENV=production`. Public binding requires an explicit documented firewall and `APP_ALLOW_PUBLIC_BIND=true`; avoid it whenever possible.
5. **MySQL and MFA:** Require certificate-verified `DB_SSL=true`, provider-approved trusted CA bundle where needed, secure DB credentials, a consistent 32-byte `MFA_ENCRYPTION_KEY` securely backed up, and `MFA_REQUIRE_PRIVILEGED=true`. Securely enroll active OWNER/REVIEWER accounts in staging first; demonstrate device loss handling without introducing insecure bypasses.
6. **Encrypted recovery drill:** Independently witness a real encrypted backup restore into a **brand-new isolated staging** database, reconcile record counts and hashes and measure actual RTO/RPO. The proposed 60-minute RTO / 5-minute RPO are only planning objectives. No real restore has yet been performed in this project workflow.
7. **Staging acceptance:** Run the isolated staging preflight with explicit staging target safety variables, demonstrate real HTTPS browser MFA login, role/CSRF restrictions, session revocation and audit controls using disposable identities, confirm secure response headers and test origin spoof rejection. Run lockfile-frozen CI and review dependency audit artifacts.
8. **Commercial safety:** Verify the quote outbox remains `HELD` / `DISABLED` with no dispatch workers, invoice/order automation, payment integration, supplier ordering or customer sends. Require distinct separate business approval for each future outbound capability.

## Read-only configuration contract checker

After provisioning test-only environment variables in a restricted staging shell, the preflight command is:

```bash
DEPLOYMENT_PREFLIGHT=1 bun run deployment:preflight
```

It checks the *declared configuration only* and prints a sanitized report. It does **not** connect to Hostinger, MySQL, TLS, DNS, proxies, backing stores or external apps. **Passing this test cannot certify ingress isolation or production readiness.** Production startup itself now refuses invalid security environment settings, and middleware rejects non-HTTPS or malformed forwarded-protocol requests without open redirects.

Inspect `docs/phase-1/PHASE_1W_HTTPS_PROXY_HARDENING.md` for the complete contract and test evidence.

## Phase 1X staging acceptance tooling

Phase 1X adds an opt-in, certificate-validating anonymous staging HTTPS probe and a separate local private-evidence review gate. See `docs/phase-1/PHASE_1X_STAGING_SECURITY_ACCEPTANCE.md` for the exact target allowlist, approval flags, manual review requirements and limitations. **Do not run against production** or infer that automated staging acceptance has occurred. No live staging host was contacted for the Phase 1X CI run.

## Phase 1Y DNS-pinned probe and private evidence integrity

Phase 1Y adds exact approved public IPv4 DNS inventory pinning to the opt-in HTTPS probe and requires a private 12-category SHA-256 evidence manifest for local staging acceptance review. The operator must independently confirm hostname, DNS answers, certificate and network isolation; all outputs remain production-blocking and **no real staging or production system has been contacted**. See `docs/phase-1/PHASE_1Y_OPERATIONAL_STAGING.md` for the offline sign-off workflow, examples and limitations.

## Rollback and operator evidence

Record approved change ticket, before/after dependency hashes, infrastructure reviewer confirmation, reverse proxy replacement rules, verified source CIDRs, certificate trust chain, app bind and firewall evidence, staging browser/test transcripts, restore time, backup location, two independent sign-offs and secure teardown. Keep private evidence out of the repository. Roll back by restoring the previously approved **application artifact and config** after human review; never drop tables, import legacy schema or edit production encryption keys as a routine rollback.

**Status: NOT PRODUCTION READY.** Draft PR only, main branch unchanged, external services and customer communications disabled.
