# Phase 1FS — M16 bounded SHA-256 application audit fingerprint (PRODUCTION HARD HOLD)

Date: 24 November 2026 IST. Branch `chore/phase0-foundation-20261106`; Draft PR #1; Issue #2. No independent legal, customer, provider, DBA or staging authority was supplied.

## Narrow internal engineering objective

Phase 1FQ introduced bounded history pages; Phase 1FR made each page internally consistent within a read-only snapshot and checked event sequence. A reviewer still had no deterministic on-demand **application database fingerprint** of a short, complete ticket history. Phase 1FS supplies a **local SHA-256 checksum-like fingerprint** for repeatability or comparison only. **It is not authenticated, externally anchored, WORM-backed, independently signed, legally accepted or customer-authorized evidence.** A privileged administrator can change the rows and recompute the hash; a newly computed digest alone cannot detect such a rewrite.

## Hard bounds, authorization and response

- `GET /api/service-desk/internal-tickets/:id/audit-fingerprint` is behind `requireOwner`, matching internal ticket `t.owner_user_id`, active CRM customer with owner-specific `CREATE` provenance and exact 36-character UUID route validation. All unexpected query parameters reject 400. Unknown/foreign ticket returns 404, non-OWNER is denied via session middleware, database/integrity failures generic 503.
- `readInternalTicketSnapshot` holds both owner-provenance check and all audit-window SELECTs on one InnoDB `REPEATABLE READ` / `WITH CONSISTENT SNAPSHOT, READ ONLY` transaction. Audit event SQL re-checks owner/customer provenance and uses `ORDER BY a.version_after DESC LIMIT 101`, strict keyset continuation and existing 1FR chain/genesis/sentinel verification per page. No unbounded OFFSET or table mutation.
- **1000-event absolute cap** checked against `ticket.version` **before** walking history. Oversize returns explicit HTTP 409 with `mode:'INTERNAL_HELD'` and `externalDispatchEnabled:false`, without partial hash or false success. Iteration also checks event count, cursor progression, SQL event payload types and source DB timestamp format. Up to ten 100-event pages, no raw notes in the response.
- SHA-256 input uses domain-separated versioned serialization: `aaditech/internal-ticket-audit/sha256/v1\n`, JSON `[ticketId,version,status]`, then JSON per event in **descending version** order: `[versionAfter,operation,fromStatus,toStatus,note,createdAtSql]`. Every record line ends with LF. SQL uses `DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s.%f')` for stable DB-stored `DATETIME` text, not host timezone-dependent JS `Date`. Digest is lowercase 64-hex SHA-256.
- Response: `algorithm:'SHA-256'`, `format:'aaditech/internal-ticket-audit/sha256/v1'`, `auditDigestSha256`, `eventCount`, `latestVersion`, `scope:'APPLICATION_UNATTESTED'`, `signatureVerified:false`, `externalAnchorVerified:false`, `customerConsentVerified:false`, `mode:'INTERNAL_HELD'`, `externalDispatchEnabled:false`. No raw customer data or audit notes returned. This is an application-generated view of database contents, NOT an external receipt.
- M16 workspace has an explicit optional **Compute unsigned audit fingerprint** button with a warning, version check and strict response contract. No automatic consent promotion, external send or service claim.

## CI-only verification (not independent attestation)

- Unit tests generate 103 synthetic sequential status events, verify two bounded windows, reproducibility across identical inputs and changed hash on edited audit note, reject missing event and malformed timestamp, reject version 1001 **before database access** and assert the absence of fictitious signature or external consent.
- Disposable `NODE_ENV=test`, `CRM_TEST_DB=1`, `DB_NAME=aaditech_ci`, `DB_SSL=false` MySQL HTTP tests reuse the 1FQ 103-version authenticated ticket. They cover stable repeated hash, 401 anonymous, 403 reviewer, 404 foreign OWNER, unknown query parameter 400, no-store/disabled dispatch, SHA change under deliberate synthetic DB note modification and exact return to original SHA after restoration, oversize 409 and no raw-note leakage. Existing 1FR read-snapshot/chain-tamper tests also run.
- Call integrated work VERIFIED only after both exact-HEAD push and Draft PR GitHub Actions report COMPLETED/SUCCESS; retain failed intermediate runs in the record.

## Trust boundaries and remaining dependencies

These fingerprints are **not** digital signatures or an evidence trust chain. A checksum of mutable data can be recomputed by an attacker with suitable database privileges and lacks independently authenticated timestamp, key custody, WORM archival, independent external anchoring or independently authenticated customer/technician identity. We deliberately do **not** write `customer_consent_state='VERIFIED'`, open external dispatch, alter `RESOLVED_HELD`, issue an eMudhra signature or imply CCA/RCAI/MCA authority. No single fingerprint proves complete history after the source was rewritten coherently.

Real separately provisioned TLS staging, true runtime/auth MySQL principal isolation and DBA routine authority, independently authenticated reviewer keys, provider-approved certificate/revocation sources, signed WORM/DR receipt, legal/Business/Security approval, source-grounded customer consent and real service delivery remain pending. M16 stays `SERVER_INTERNAL_HELD`, other M01–M30 external acceptance OPEN.

**HARD HOLD:** `productionReleaseAuthorized=false`; `productionReleaseBlocked=true`; `releaseDecision=HOLD`. Do not merge main, release/deploy production, install schemas on customer systems, send actual customer/supplier messages, issue official quotes/PO/GRN, post stock/finance/tax or remotely control customer Windows machines.

Related: [Phase 1FR](PHASE_1FR_M16_SNAPSHOT_AUDIT_CONTINUITY_HARD_HOLD.md), [Phase 1FQ](PHASE_1FQ_INTERNAL_TICKET_KEYSET_AUDIT_PAGINATION_HARD_HOLD.md), [master plan](../completion/MASTER_M01_M30_COMPLETION_PLAN.md).
