# Phase 1Y — Operational staging verification and private evidence integrity

**Status:** Development-only tooling and synthetic CI verification. **No authorized real staging hostname/IP inventory was supplied. No Hostinger probe, database restore or production deployment was executed.**

## Objective and controls implemented

The Phase 1X HTTPS probe has been strengthened against DNS drift and unintended destinations. Its operator-controlled target is accepted only after an independently approved HTTPS staging hostname, an exact set of **public IPv4 addresses** (1–8 distinct IP literals), a change-ticket reference and two explicit opt-in flags. Local/private/metadata/reserved/documentation addresses and IPv6 DNS results fail closed, pending a separate network policy review. DNS is resolved once; the answers must exactly match the operator-approved inventory. The TLS connection is then **pinned to one approved IP** while keeping the original staging hostname as TLS SNI and hostname-verification identity. No redirects or off-origin follow-ups occur. A trusted certificate with less than 14 days remaining or missing one-year HSTS blocks the observation.

A DNS pin is not proof that a staging service is safe or that the IP is not shared with production. **Human infrastructure review must verify the actual provider ingress, network isolation, header overwrite and absence of live workloads at every approved address.** The script deliberately cannot certify those facts.

## Operator workflow — requires separate written authorization

1. Record an approved ticket, dedicated non-production hostname, independently verified public A records, provider certificate/CA chain, secure operator workstation and rollback plan. Do not probe if the host could route to production or expose customer data.
2. Only after approval, run the following **example template** with real approved values. No value in this example was used to contact a host in CI:

   ```bash
STAGING_HTTPS_PROBE=YES STAGING_PROBE_APPROVED=YES \
  STAGING_CHANGE_TICKET=CHG-STAGING-APPROVED \
  STAGING_HTTPS_ORIGIN=https://staging.YOUR-APPROVED-HOST \
  STAGING_APPROVED_HOST=staging.YOUR-APPROVED-HOST \
  STAGING_APPROVED_IPV4S=APPROVED_PUBLIC_IP_1,APPROVED_PUBLIC_IP_2 \
  bun run staging:https-probe
```

   The placeholder domain and IP literals are intentionally invalid. Approved private-only or IPv6 staging networks cannot use this public-IPv4-only tool. Coordinate a separate security-reviewed test approach for those environments.

3. Separately verify that the proxy **replaces** untrusted \`X-Forwarded-For\` and \`X-Forwarded-Proto\`, the Node listener cannot be reached directly from outside, MySQL TLS trusts the provider CA, real HTTPS owner/reviewer MFA login/CSRF works and outbound quote dispatch stays HELD/DISABLED.
4. Perform a **separately authorized, encrypted** backup and restoration into a *brand-new isolated* \`aaditech_staging_*\` database; reconcile counts and privacy-safe sample hashes; restore MFA encryption key securely, measure RTO/RPO and collect an independent witness signature. The existing 60-minute RTO / 5-minute RPO values are planning goals, not achieved measurements.
5. Store private files outside the Git checkout, for example under a protected \`/private/approved-staging-evidence/\` directory. Use a private JSON manifest containing \`schemaVersion:1\`, the approved \`changeTicket\`, exact \`stagingOrigin\` and twelve \`files\` entries with keys \`kind\`, relative \`path\` and actual lowercase SHA-256 digest of each file. The mandatory evidence categories are:

   \`tls-chain\`, \`proxy-headers\`, \`listener-isolation\`, \`mysql-ca\`, \`browser-mfa\`, \`encrypted-backup\`, \`restore-reconciliation\`, \`mfa-key-recovery\`, \`outbox-held\`, \`security-signoff\`, \`infrastructure-signoff\`, \`restore-witness\`.

   Never commit private evidence, customer records, keys, screenshots containing personal data or the actual manifest to GitHub.

6. Review the private Phase 1X acceptance JSON with **both** its corresponding manifest and evidence root:

   ```bash
STAGING_ACCEPTANCE_REVIEW=YES bun run staging:acceptance-review \
  /private/acceptance.json /private/evidence-manifest.json /private/approved-staging-evidence
```

   The tool verifies that all twelve real files exist outside the repository, are ordinary bounded-size files, have safe relative paths and match the recorded SHA-256 digests. It also checks the existing chronology, distinct roles, ticket/origin binding and RTO/RPO claims. Missing, modified, duplicated, symlinked or path-traversal references fail closed. The report prints **no evidence file contents, original paths, raw credentials or signer identities**.

## No release authority

- **SHA-256 matching confirms file bytes have not changed relative to the submitted manifest; it does not authenticate the manifest, identify a signer or prove that a restore actually happened.** Independent humans must validate provider records, signed approvals and evidence source authenticity.
- The HTTPS probe checks externally visible status, TLS trust, expiration, HSTS and cache/header controls only. It cannot verify private listener isolation or MySQL certificate trust. Public IP approval is necessary but not sufficient.
- \`productionReleaseAuthorized:false\` remains mandatory in both probe and acceptance reports. No repo script merges, releases, deploys, migrates, deletes, provisions live identities, sends customer messages or changes the \`HELD\`/\`DISABLED\` outbox.
- CI uses synthetic evidence files and mocked DNS/HTTPS only. **No real staging IP/Hostinger URL, signed operations approval or restore evidence exists in this repository.**

## CI tests and acceptance backlog

Tests cover exact DNS inventory match and pinning, private/reserved IP rejection, certificate expiry, HSTS, spoofed headers, unsafe evidence roots, symlink/path traversal, SHA digest mutation and misleading sign-off claims. The existing baseline TypeScript/build, dependency advisories, disposable MySQL, HTTP MFA, Chromium and read-only staging preflight also remain gated.

Next phase must collect **actual** approved staging host/IPs and separately witnessed real-world test evidence before security acceptance. Keep PR Draft and \`main\` unchanged.
