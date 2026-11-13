# Phase 1X — Staging HTTPS, reverse-proxy and recovery acceptance

**State: CODE / SYNTHETIC CI TESTS ONLY. NO LIVE STAGING VALIDATION OR PRODUCTION RELEASE.**

## Optional, read-only HTTPS observation (requires staging approval)

An operator must approve a real *isolated* staging hostname and change ticket before running:

    STAGING_HTTPS_PROBE=YES STAGING_PROBE_APPROVED=YES \
      STAGING_CHANGE_TICKET=CHG-STAGING-APPROVED \
      STAGING_HTTPS_ORIGIN=https://staging.YOUR-APPROVED-HOST \
      STAGING_APPROVED_HOST=staging.YOUR-APPROVED-HOST \
      STAGING_APPROVED_IPV4S=VERIFIED_PUBLIC_IPV4
      bun run staging:https-probe

The hostname above is a **placeholder**, not an endpoint tested here. The script rejects production-looking hosts, non-HTTPS, IP literals, localhost, reserved example/test domains, credentials, paths and nonstandard ports. An exact approved hostname, **matching public IPv4 DNS inventory**, change ticket and two independent opt-in flags are mandatory. The probe verifies DNS answers against that inventory and pins all three TLS connections to one approved address, while preserving the approved SNI hostname for certificate validation. IPv6/private-only staging environments are intentionally unsupported until a separately reviewed transport policy is designed. No actual hostname has been supplied or probed.

The HSTS max-age must be at least 31,536,000 seconds (one year); lower values fail the gate. The probe performs exactly three **anonymous, read-only HTTPS GET** requests: /api/health, /api/auth/me and /api/health with deliberately forged X-Forwarded-Proto and X-Forwarded-For headers. Node verifies TLS certificate trust and hostname. Redirects are not followed, each request has a 5-second timeout and response content is limited to 16 KiB. HTTP 200/401/200, HSTS, nosniff, no X-Powered-By and authentication no-store are checked. It prints sanitized observations, not cookies, credentials, or response bodies.

The spoofed-header observation alone **does not independently verify** client-IP forwarding, public listener isolation, DB TLS/CA or backend network firewall; the report explicitly leaves those statuses false. No real connection from CI is permitted.

## Offline independent-evidence checklist

An approved operator may submit a **private** local JSON evidence package (never add it to GitHub or CI):

    STAGING_ACCEPTANCE_REVIEW=YES bun run staging:acceptance-review /private/path/staging-evidence.json /private/path/evidence-manifest.json /private/evidence-root

The package must contain an authorized change ticket, exact HTTPS staging origin, probe report (observed within 24 hours), distinct operator/security/infrastructure reviewers and separate restore witness, private approval references, reverse-proxy header overwrite and network isolation evidence, verified MySQL CA, real HTTPS device MFA/browser evidence, outbound dispatch blocked proof, and actual encrypted backup/restore results measured against the approved RTO/RPO objectives.

Field/chronology consistency failures, mixed change tickets, stale observations, absent external infrastructure attestations or signer role conflicts reject the submission. Phase 1Y also requires matching SHA-256 digests for 12 private evidence files, stored outside the source checkout. These checks do **not** prove the truth of reported observations or the identity of a signer.

**A JSON document can be falsified.** Even apparently complete evidence always returns independentIdentityAndSignaturesVerified:false, providerInfrastructureVerified:false, actualRestoreIndependentlyVerified:false and productionReleaseAuthorized:false. The evaluator does not verify actual signatures, restore bytes, certificate chain on any live host or firewall settings. Independent humans must validate underlying evidence outside this repository.

## Independent manual acceptance and rollback

Before any release: obtain written owner/security/ops approval; validate actual Hostinger plan and proxy overwrite behavior; prove direct Node listener cannot be reached; independently verify TLS chain and MySQL CA; perform a separately authorized encrypted backup into a **new isolated** staging database; reconcile data and MFA key recovery; witness RTO/RPO; test real HTTPS owner/reviewer MFA, session revocation, CSRF and auditing; confirm quote outbox is HELD/DISABLED and no external workers are running. Store sensitive evidence in an approved private system, not source control.

CI runs only synthetic/mocked staging tests, alongside existing TypeScript/build/dependency, disposable MySQL, retention, HTTP MFA and Chromium login tests. It never probes or restores Hostinger or production systems. Do not merge Draft PR or deploy without separate signed acceptance.
