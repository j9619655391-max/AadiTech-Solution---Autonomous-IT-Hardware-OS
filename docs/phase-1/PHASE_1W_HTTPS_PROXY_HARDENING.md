# Phase 1W — Reverse-proxy trust, HTTPS and environment hardening

**Development status only.** This phase adds production-startup **fail-closed configuration validation** and HTTPS request enforcement. Nothing has been deployed to Hostinger, and a successful CI test does not verify the production reverse-proxy chain.

## Production configuration contract

The application must run behind an approved TLS-terminating reverse proxy. The proxy must **overwrite** (never merely append) client-supplied `X-Forwarded-Proto` and `X-Forwarded-For`. Configure its actual source addresses only, and restrict direct network access to the Node listener. Do not use `trust proxy=true`, hop-count settings, wildcard CIDRs, or unverified shared hosting proxy assumptions.

| Setting | Requirement |
| --- | --- |
| `NODE_ENV` | `production` activates fail-closed startup checks |
| `APP_URL` | HTTPS origin only, e.g. `https://staging.example.invalid` (not a route, HTTP URL or credential URL) |
| `APP_TRUSTED_PROXY_CIDRS` | Comma-separated literal ingress IPs or narrow CIDRs; max eight entries, no broad /0/private /8 trust |
| `APP_REQUIRE_HTTPS` | Exact `true`; insecure/mixed forwarded-proto requests get **403**, never redirects using untrusted Host |
| `APP_BIND_HOST` | Default `127.0.0.1`; any nonloopback bind requires deliberate `APP_ALLOW_PUBLIC_BIND=true` plus independently verified network firewall restriction |
| `DB_SSL` | Exact `true`, server-certificate verified; set `DB_SSL_CA_BASE64` when required by MySQL provider |
| `DB_HOST/PORT/USER/NAME/PASSWORD` | All required with valid numeric port |
| `MFA_REQUIRE_PRIVILEGED` | Exact `true`; enroll owner/reviewer before rollout |
| `MFA_ENCRYPTION_KEY` | Exactly 64 hex characters, managed outside repository and CI secrets; back up and test restore securely |

The server now configures Express `trust proxy` with the precise allowlisted CIDRs (never boolean `true`). HTTP middleware denies requests without **verified** HTTPS proxy context, sets `Strict-Transport-Security: max-age=31536000` only for accepted requests, disables Express `X-Powered-By`, sets `X-Content-Type-Options: nosniff`, and sets no-store headers for authentication APIs. Session cookies remain HttpOnly/SameSite and Secure when `NODE_ENV=production`.

**Operational caveat:** A proxy must strip/replace untrusted forwarded headers. An attacker who can connect directly to the app from an IP in the allowlist, or who controls a misconfigured trusted proxy, could still spoof identity/transport headers. CIDR validation alone is NOT a substitute for verified ingress isolation. Do not trust shared upstream subnets as proxy identities.

## CI evidence and test plan

Unit tests assert invalid production configurations fail, CIDRs cannot be broad/hostnames, untrusted forwarded headers do not force HTTPS or spoof client IP, only an explicitly trusted loopback proxy is accepted, and spoofed mixed proto is rejected. Existing CI also checks TypeScript, Bun patch audit, MySQL, MFA, retention, Chromium and read-only staging preflight. Tests use synthetic configuration only; no live infrastructure is contacted.

**Before deployment** independently validate the actual Hostinger ingress IP, header rewrite behavior, public listener isolation, host firewall, TLS certificate, HSTS suitability for host domains, provider MySQL CA, MFA enrollment/recovery, encrypted backup+restore and real HTTPS browser tests. Security owner must sign off. No production migration, customer send, quote dispatch, merge or deployment is authorized.
