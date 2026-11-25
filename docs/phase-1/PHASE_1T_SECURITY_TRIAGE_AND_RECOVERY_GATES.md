# Phase 1T — Dependency triage, retention approval and recovery evidence

**Status: Development / Draft PR only.** No production migrations, cleanup, deployments, customer messaging, backups or restores were executed.

## Confirmed dependency advisory inventory

Source: the GitHub Actions `dependency-audit` artifact produced by the Phase 1S push workflow (run `42648642066`), containing `dependency-audit.json`. The reported dependency tree matched **11 advisories over 5 packages**. These are package advisory matches; they do **not** independently prove exploitable runtime paths, nor have they been remediated.

| Package | Severity and advisory | Initial triage |
| --- | --- | --- |
| `proxy-addr` | **Critical** `GHSA-jqcg-44mw-7w3h` | Investigate trust-proxy/IP-spoofing impact on Express request IP and rate limits; verify patched version and trusted reverse-proxy configuration |
| `body-parser` | **High** `GHSA-27r3-jxmh-p828` | Review compressed-payload DoS reachability and Express dependency fix |
| `source-map-js` | **High** `GHSA-68fv-2mgg-jv7q` | Review source-map parsing exposure and patched build chain |
| `vite` | 1 high, 3 moderate, 1 low: `GHSA-587h-7wmj-h5pm`, `GHSA-rq7h-c2jc-7f22`, `GHSA-698v-4r3x-3vcv`, `GHSA-r825-w8mm-5pxw`, `GHSA-9jrq-w75r-8gcw` | Audit dev server/middleware exposure, editor-launch surfaces, production build, and available patched Vite 6 / later supported release |
| `qs` | 3 moderate: `GHSA-x5fp-wj9c-mxmx`, `GHSA-4mjr-xmp4-gh2g`, `GHSA-6pq8-jhm2-2vcw` | Verify query parser DoS reachability and patched Express transitive chain |

**Severity breakdown:** 1 critical, 3 high, 6 moderate, 1 low. Dependency vulnerability findings are **still open** and require a reviewed, lockfile-updated remediation PR before release. No `npm audit fix`, `bun update` or unreviewed overrides were performed in Phase 1T. The Express runtime dependency chain deserves priority; Vite/editor risk must be assessed separately as development/build exposure.

CI now runs `node scripts/triage-dependencies.mjs dependency-audit.json dependency-triage.json` and attaches both raw and normalized artifacts. The parser sorts severity, emits advisory IDs, source URLs and package-specific recommended investigation; it never claims a zero-risk release. Audit and advisory findings remain non-gating for development CI; **production release remains blocked pending manual risk disposition**. A malformed audit report causes the triage command itself to fail rather than being silently treated as clean.

## Retention governance gate

Added `assessRetentionPolicyEvidence` and tests. Reviewers must reference an approved retention schedule, jurisdiction, controller, independent privacy reviewer, independent security reviewer, timestamp, change-control ticket, legal/incident hold procedure and backup/recovery reference.

The evaluator checks **field completeness and role separation only**. It does not verify identities/signatures, confer legal approval or authorize deletion. Even fully populated synthetic approval data reports `authorizesDataDeletion:false` and `productionRetentionEnabled:false`.

Existing retention tool remains strictly limited to `aaditech_ci`, dry-run by default, and can only delete expired test fixtures after explicit CI-only opt-in. Immutable security events, MFA secrets/recovery history and business records are not in its deletion list. **No production retention period has been approved or activated.**

## Disaster-recovery evidence gate

Added `assessRecoveryReviewPackage` and negative tests combining existing RTO/RPO/time-order checks with private change ticket, evidence reference, separate operator/witness identities, staged network isolation, disabled outbound dispatch and trusted TLS attestation.

The evaluator **cannot independently verify real backup bytes, signer identities or restore execution**; its output always declares `externallyWitnessedRestoreVerified:false` and `productionReleaseAuthorized:false`, even with apparently complete synthetic input. It does not access real systems. Proposed **60-minute RTO / 5-minute RPO** remain planning objectives, not measurements.

### Unfinished release gates
- Safely patch critical/high dependency chain after upgrade review, lockfile change, regression/build/browser tests and owner/security acceptance.
- Establish actual legal retention schedule and independently signed approval and incident hold controls before even designing production cleanup.
- Conduct authorized encrypted backup/export and fresh isolated staging restore, measure actual RTO/RPO, reconcile data, test MFA key recovery and HTTPS authenticator flows, and store private signed evidence.
- Review Hostinger/MySQL CA trust and service isolation, operational alerting, lost-factor recovery and real devices.
- Preserve Draft PR, `main`, real MySQL and HELD/DISABLED quote outbox; no outbound customer dispatch without explicit business approval.
