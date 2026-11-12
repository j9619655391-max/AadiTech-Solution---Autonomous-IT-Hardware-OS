import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {Pool,RowDataPacket} from 'mysql2/promise';

export const MIGRATIONS=[
 '0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency',
 '0005_quote_revisions','0006_quote_reviews','0007_quote_release_holds',
 '0008_reviewer_roles','0009_auth_security_events','0010_auth_login_security',
 '0011_totp_mfa','0012_mfa_audit_events','0013_mfa_recovery_rotation',
 '0014_inventory_opening_counts','0015_procurement_internal',
 '0016_quarantine_intake','0017_supplier_dispatch_holds',
 '0018_acknowledgment_grn_holds','0019_stock_release_planning',
 '0020_unposted_double_entry_journals',
 '0021_signed_proof_prerequisites',
 '0022_key_possession_lifecycle',
 '0023_external_trust_prerequisites',
 '0024_provider_identity_bridge'
] as const;

export function checkPreflightTarget(env:NodeJS.ProcessEnv):'ci'|'staging' {
 if(env.STAGING_PREFLIGHT!=='1')throw Error('STAGING_PREFLIGHT=1 explicit opt-in required');
 if(env.CRM_TEST_DB==='1' && env.DB_NAME==='aaditech_ci' &&
    env.NODE_ENV==='test')return 'ci';
 if(env.STAGING_DISPOSABLE_CONFIRMED==='YES' &&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'') &&
    env.DB_SSL==='true')return 'staging';
 throw Error('Refusing preflight: target is not disposable CI or explicitly confirmed TLS staging DB');
}

export function migrationChecksums(){
 return MIGRATIONS.map(id=>({
  id,checksum:createHash('sha256').update(
   readFileSync('database/migrations/'+id+'.sql')).digest('hex')
 }));
}
export async function runStagingPreflight(db:Pool,env:NodeJS.ProcessEnv) {
 const target=checkPreflightTarget(env);
 const problems:string[]=[];
 const expected=migrationChecksums();
 const [rows]=await db.query<RowDataPacket[]>('SELECT id,checksum FROM schema_migrations ORDER BY id');
 const actual=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
 for(const item of expected){
  if(actual.get(item.id)!==item.checksum)problems.push('Missing/mismatched migration: '+item.id);
 }
 for(const id of actual.keys())if(!expected.some(x=>x.id===id))problems.push('Unknown migration: '+id);
 const [holds]=await db.query<RowDataPacket[]>(`SELECT
  COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN p.status<>'HELD' OR o.dispatch_state<>'DISABLED'
   OR o.event_type<>'QUOTE_RELEASE_PREPARATION_HELD'
   OR p.snapshot_sha256<>o.payload_sha256 THEN 1 ELSE 0 END),0) AS unsafe
  FROM sales_quote_release_preparations p
  LEFT JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id`);
 const [orphaned]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS n
   FROM sales_quote_outbox_holds o LEFT JOIN sales_quote_release_preparations p
   ON p.id=o.release_preparation_id WHERE p.id IS NULL`);
 const [missingEvents]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS n
   FROM sales_quote_release_preparations p LEFT JOIN sales_quote_outbox_holds o
   ON o.release_preparation_id=p.id WHERE o.id IS NULL`);
 if(Number(holds[0].unsafe)!==0||Number(orphaned[0].n)!==0||
   Number(missingEvents[0].n)!==0)problems.push('Held/outbox invariant mismatch');
 // No externally executable supplier outbox exists; an approved internal
 // dispatch preparation MUST have exactly one HELD/DISABLED outbox.
 const [supplierOutbox]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
   COALESCE(SUM(CASE WHEN p.id IS NULL OR d.id IS NULL
    OR o.state<>'HELD' OR o.dispatch_state<>'DISABLED'
    OR p.status<>'APPROVED_INTERNAL' OR d.decision<>'APPROVED_INTERNAL'
    OR o.decision_id<>d.id
    OR JSON_UNQUOTE(JSON_EXTRACT(o.snapshot_json,'$.manifestSha256'))<>p.manifest_sha256
    OR JSON_UNQUOTE(JSON_EXTRACT(o.snapshot_json,'$.dispatchState'))<>'DISABLED'
    OR JSON_UNQUOTE(JSON_EXTRACT(o.snapshot_json,'$.externalPoIssued'))<>'false'
    THEN 1 ELSE 0 END),0) AS unsafe
   FROM proc_dispatch_outbox_holds o
   LEFT JOIN proc_dispatch_preparations p ON p.id=o.preparation_id
   LEFT JOIN proc_dispatch_review_decisions d ON d.id=o.decision_id`);
 const [missingSupplierHolds]=await db.query<RowDataPacket[]>(`
  SELECT COUNT(*) AS n FROM proc_dispatch_preparations p
  LEFT JOIN proc_dispatch_outbox_holds o ON o.preparation_id=p.id
  WHERE p.status='APPROVED_INTERNAL' AND o.id IS NULL`);
 if(Number(supplierOutbox[0].unsafe)!==0||Number(missingSupplierHolds[0].n)!==0)
  problems.push('Supplier dispatch HELD/DISABLED outbox invariant mismatch');
 // Phase 1AF: any approved GRN-reconciliation pack must have exactly one
 // evidence-only HELD row, permanently DISABLED and source-linked. This check
 // does NOT authorize stock availability, supplier acknowledgment or GRN posting.
 const [heldGrn]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
   COALESCE(SUM(CASE WHEN p.id IS NULL OR d.id IS NULL
    OR h.status<>'HELD' OR h.stock_posting_state<>'DISABLED'
    OR p.status<>'HELD_INTERNAL' OR d.decision<>'HELD_INTERNAL'
    OR d.id<>h.decision_id
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.packSha256'))<>p.pack_sha256
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.stockPostingState'))<>'DISABLED'
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.officialGrnCreated'))<>'false'
    THEN 1 ELSE 0 END),0) AS unsafe
   FROM inv_grn_held_records h
   LEFT JOIN inv_grn_reconciliation_packs p ON p.id=h.pack_id
   LEFT JOIN inv_grn_reconciliation_decisions d ON d.id=h.decision_id`);
 const [unheldGrn]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
   FROM inv_grn_reconciliation_packs p
   LEFT JOIN inv_grn_held_records h ON h.pack_id=p.id
   WHERE p.status='HELD_INTERNAL' AND h.id IS NULL`);
 const [unreviewedAcknowledgments]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
   FROM proc_ack_claims c
   LEFT JOIN proc_ack_claim_decisions d ON d.claim_id=c.id
   WHERE (c.status='ATTESTED_INTERNAL' AND
     (d.id IS NULL OR d.decision<>'ATTESTED_INTERNAL' OR NOT d.document_inspected))
   OR (c.status='DISPUTED_INTERNAL' AND
     (d.id IS NULL OR d.decision<>'DISPUTED_INTERNAL'))`);
 if(Number(heldGrn[0].unsafe)!==0||Number(unheldGrn[0].total)!==0||
    Number(unreviewedAcknowledgments[0].total)!==0)
  problems.push('Supplier claim or GRN evidence HELD/DISABLED invariant mismatch');
 // Phase 1AG: hard-zero stock positions and no orphaned, ENABLED or
 // unreviewed internal release evidence. No actual stock receipt exists.
 const [stockGate]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
   COALESCE(SUM(CASE WHEN available_quantity<>0 OR reserved_quantity<>0
    OR picked_quantity<>0 OR posted_quantity<>0 THEN 1 ELSE 0 END),0) AS unsafe
   FROM inv_stock_position_gates`);
 const [releaseHolds]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
   COALESCE(SUM(CASE WHEN i.id IS NULL OR d.id IS NULL
    OR h.state<>'HELD' OR h.posting_state<>'DISABLED'
    OR i.status<>'REVIEWED_HELD' OR d.decision<>'REVIEWED_HELD'
    OR h.decision_id<>d.id
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.intentSha256'))<>i.intent_sha256
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.postingState'))<>'DISABLED'
    OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.stockPosted'))<>'false'
    THEN 1 ELSE 0 END),0) AS unsafe
   FROM inv_stock_release_holds h
   LEFT JOIN inv_stock_release_intents i ON i.id=h.release_intent_id
   LEFT JOIN inv_stock_release_decisions d ON d.id=h.decision_id`);
 const [missingReleaseHolds]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
   FROM inv_stock_release_intents i
   LEFT JOIN inv_stock_release_holds h ON h.release_intent_id=i.id
   WHERE i.status='REVIEWED_HELD' AND h.id IS NULL`);
 const [plans]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
   COALESCE(SUM(CASE WHEN p.state<>'HELD' OR p.reservation_state<>'DISABLED'
    OR i.status<>'REVIEWED_HELD' OR l.observed_quantity<p.requested_quantity
    OR g.available_quantity<>0 OR g.reserved_quantity<>0 OR g.posted_quantity<>0
    OR g.picked_quantity<>0 OR l.id IS NULL OR i.id IS NULL OR g.site_id IS NULL
    THEN 1 ELSE 0 END),0) AS unsafe
   FROM inv_reservation_planning_intents p
   LEFT JOIN inv_stock_release_intents i ON i.id=p.release_intent_id
   LEFT JOIN inv_stock_release_intent_lines l
    ON l.release_intent_id=p.release_intent_id AND l.product_id=p.product_id
   LEFT JOIN inv_stock_position_gates g
    ON g.site_id=p.site_id AND g.product_id=p.product_id`);
 if(Number(stockGate[0].unsafe)!==0||Number(releaseHolds[0].unsafe)!==0||
    Number(missingReleaseHolds[0].total)!==0||Number(plans[0].unsafe)!==0)
  problems.push('Hard-zero stock foundation, HELD release or disabled reservation plan invariant mismatch');
 // Phase 1AH: do not certify operational stock; all journal and serial states
 // must remain UNPOSTED, external trust unavailable and stock hard-zero.
 const [journalSummary]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN b.journal_id IS NULL OR j.posting_state<>'DISABLED'
   OR b.external_po_verified<>'NO' OR b.supplier_ack_authenticated<>'NO'
   OR b.official_grn_verified<>'NO' OR b.warehouse_release_authorized<>'NO'
   OR b.stock_credit_state<>'DISABLED'
   OR (j.status='REVIEWED_HELD' AND
     (r.id IS NULL OR r.decision<>'REVIEWED_HELD' OR NOT r.balancing_inspected
      OR h.id IS NULL OR h.review_id<>r.id OR h.state<>'HELD'
      OR h.posting_state<>'DISABLED'
      OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.manifestSha256'))<>j.manifest_sha256
      OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.stockPosted'))<>'false'))
   OR (j.status='REJECTED_INTERNAL' AND
      (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL' OR h.id IS NOT NULL))
   OR (j.status='PENDING_INTERNAL' AND (r.id IS NOT NULL OR h.id IS NOT NULL))
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_unposted_journal_headers j
  LEFT JOIN inv_unposted_source_blockers b ON b.journal_id=j.id
  LEFT JOIN inv_unposted_journal_reviews r ON r.journal_id=j.id
  LEFT JOIN inv_unposted_journal_holds h ON h.journal_id=j.id`);
 const [unbalancedJournal]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS unsafe FROM (
   SELECT journal_id,product_id
   FROM inv_unposted_journal_legs
   GROUP BY journal_id,product_id HAVING COUNT(*)<>2
   OR SUM(CASE WHEN entry_side='CREDIT' AND account_code='QUARANTINE_EVIDENCE'
    THEN 1 ELSE 0 END)<>1
   OR SUM(CASE WHEN entry_side='DEBIT' AND account_code='RELEASE_CANDIDATE_EVIDENCE'
    THEN 1 ELSE 0 END)<>1
   OR SUM(CASE WHEN entry_side='CREDIT' THEN quantity ELSE -quantity END)<>0
   OR SUM(CASE WHEN posting_state<>'DISABLED' THEN 1 ELSE 0 END)<>0
 ) mismatches`);
 const [missingLegs]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
  FROM inv_unposted_journal_headers j LEFT JOIN inv_unposted_journal_legs l
  ON l.journal_id=j.id WHERE l.id IS NULL`);
 const [badCandidates]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total
  FROM inv_unposted_serial_candidates WHERE provenance_state<>'UNVERIFIED'
  OR ownership_state<>'NOT_ESTABLISHED'`);
 const [serialMismatch]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM (
  SELECT j.id,
   COALESCE(SUM(CASE WHEN l.account_code='QUARANTINE_EVIDENCE' AND
    l.tracking_mode='SERIAL' THEN JSON_LENGTH(l.serials_json) ELSE 0 END),0) AS expected
  FROM inv_unposted_journal_headers j
  LEFT JOIN inv_unposted_journal_legs l ON l.journal_id=j.id
  GROUP BY j.id
 ) counted LEFT JOIN (
   SELECT journal_id,COUNT(*) AS found FROM inv_unposted_serial_candidates GROUP BY journal_id
 ) c ON c.journal_id=counted.id WHERE counted.expected<>COALESCE(c.found,0)`);
 if(Number(journalSummary[0].unsafe)!==0||Number(unbalancedJournal[0].unsafe)!==0||
    Number(missingLegs[0].total)!==0||Number(badCandidates[0].total)!==0||
    Number(serialMismatch[0].total)!==0)
  problems.push('UNPOSTED double-entry, serial provenance or HELD journal authority invariant mismatch');
 // Phase 1AI: offline key proof candidate is cryptographic only, never a real
 // external trust root; all attestations/GRNs/stock must remain hard-denied.
 const [proofKeys]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   fingerprint_sha256<>SHA2(FROM_BASE64(public_key_spki_b64),256)
   OR (party_kind='SUPPLIER' AND (supplier_id IS NULL OR site_id IS NOT NULL))
   OR (party_kind='WAREHOUSE' AND (site_id IS NULL OR supplier_id IS NOT NULL))
   OR (status='REVIEWED_UNTRUSTED' AND
     (r.id IS NULL OR r.decision<>'REVIEWED_UNTRUSTED'
      OR r.reviewer_id=k.registered_by OR NOT r.document_inspected))
   OR (status='REJECTED_INTERNAL' AND
     (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL'))
   OR (status='PENDING_INTERNAL' AND r.id IS NOT NULL)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_proof_key_candidates k
  LEFT JOIN inv_proof_key_reviews r ON r.key_id=k.id`);
 const [proofClaims]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   b.claim_id IS NULL OR c.signature_matched<>1 OR
   b.party_identity<>'UNVERIFIED' OR b.actual_po_issued<>'NO' OR
   b.supplier_ack_authenticated<>'NO' OR
   b.official_grn_authenticated<>'NO' OR b.stock_posting<>'DISABLED'
   OR k.status<>'REVIEWED_UNTRUSTED'
   OR (c.status='REVIEWED_CRYPTO_ONLY' AND
      (r.id IS NULL OR r.decision<>'REVIEWED_CRYPTO_ONLY'
       OR r.reviewer_id=c.created_by OR NOT r.signature_inspected
       OR h.id IS NULL OR h.review_id<>r.id
       OR h.status<>'HELD' OR h.external_trust_state<>'UNVERIFIED'
       OR h.stock_posting<>'DISABLED'
       OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.messageSha256'))<>c.message_sha256
       OR JSON_UNQUOTE(JSON_EXTRACT(h.snapshot_json,'$.officialGrnVerified'))<>'false'))
   OR (c.status='REJECTED_INTERNAL' AND
      (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL' OR h.id IS NOT NULL))
   OR (c.status='PENDING_INTERNAL' AND (r.id IS NOT NULL OR h.id IS NOT NULL))
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_signed_proof_claims c
  JOIN inv_proof_key_candidates k ON k.id=c.key_id
  LEFT JOIN inv_signed_proof_blockers b ON b.claim_id=c.id
  LEFT JOIN inv_signed_proof_reviews r ON r.claim_id=c.id
  LEFT JOIN inv_signed_proof_holds h ON h.claim_id=c.id`);
 if(Number(proofKeys[0].unsafe)!==0||Number(proofClaims[0].unsafe)!==0)
  problems.push('Untrusted offline proof key, signature claim or HELD external authority invariant mismatch');
 // Phase 1AJ: cryptographic challenge possession remains internally attested only.
 // Check immediate retirement, one-time consumption, independent review, rotation
 // finality and no external trust, without mutating any live key or stock state.
 const [keyChallenges]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   (c.status='ISSUED' AND (c.consumed_at IS NOT NULL OR p.id IS NOT NULL))
   OR (c.status='MATCHED_INTERNAL' AND
    (c.consumed_at IS NULL OR c.consumed_at>c.expires_at OR p.id IS NULL))
   OR (p.id IS NOT NULL AND (p.key_id<>c.key_id OR p.status<>'MATCHED_INTERNAL'))
   OR (r.id IS NOT NULL AND
    (r.reviewer_id=k.registered_by OR
     (r.decision='REVIEWED_UNTRUSTED' AND NOT r.possession_inspected)))
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_key_possession_challenges c
  JOIN inv_proof_key_candidates k ON k.id=c.key_id
  LEFT JOIN inv_key_possession_receipts p ON p.challenge_id=c.id
  LEFT JOIN inv_key_possession_reviews r ON r.receipt_id=p.id`);
 const [keyRetirements]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
    (t.event_type='EMERGENCY_REVOKED' AND t.initiated_by<>k.registered_by)
    OR (t.event_type='ROTATION_RETIRED' AND NOT EXISTS(
     SELECT 1 FROM inv_key_rotation_proposals x
     JOIN inv_key_rotation_decisions d ON d.proposal_id=x.id
     WHERE x.old_key_id=t.key_id AND x.status='REVIEWED_UNTRUSTED'
       AND d.decision='REVIEWED_UNTRUSTED' AND d.reviewer_id=t.initiated_by))
    THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_key_retirements t
  JOIN inv_proof_key_candidates k ON k.id=t.key_id`);
 const [keyRotations]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   old.registered_by<>x.prepared_by OR fresh.registered_by<>x.prepared_by
   OR old.party_kind<>fresh.party_kind
   OR COALESCE(old.supplier_id,old.site_id)<>COALESCE(fresh.supplier_id,fresh.site_id)
   OR x.old_key_id=x.new_key_id
   OR (x.status='PENDING_INTERNAL' AND d.id IS NOT NULL)
   OR (x.status='REVIEWED_UNTRUSTED' AND (d.id IS NULL OR
      d.decision<>'REVIEWED_UNTRUSTED' OR NOT d.possession_inspected OR
      t.key_id IS NULL OR t.event_type<>'ROTATION_RETIRED'))
   OR (x.status='REJECTED_INTERNAL' AND
      (d.id IS NULL OR d.decision<>'REJECTED_INTERNAL'))
   OR (d.id IS NOT NULL AND d.reviewer_id=x.prepared_by)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_key_rotation_proposals x
  JOIN inv_proof_key_candidates old ON old.id=x.old_key_id
  JOIN inv_proof_key_candidates fresh ON fresh.id=x.new_key_id
  LEFT JOIN inv_key_rotation_decisions d ON d.proposal_id=x.id
  LEFT JOIN inv_key_retirements t ON t.key_id=x.old_key_id`);
 if(Number(keyChallenges[0].unsafe)!==0||Number(keyRetirements[0].unsafe)!==0||
    Number(keyRotations[0].unsafe)!==0)
  problems.push('Key possession expiry/replay, immediate retirement, independent review or internal rotation invariant mismatch');
 // Phase 1AK: only self-entered organizational issuer candidates exist.
 // These SQL integrity checks do not and cannot authenticate external roots.
 const [extIssuers]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   i.external_root_state<>'UNVERIFIED' OR
   i.fingerprint_sha256<>SHA2(FROM_BASE64(i.issuer_spki_b64),256)
   OR (i.status='REVIEWED_HELD' AND
    (r.id IS NULL OR r.decision<>'REVIEWED_HELD'
     OR r.reviewer_id=i.registered_by OR NOT r.registry_inspected))
   OR (i.status='REJECTED_INTERNAL' AND
    (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL'))
   OR (i.status='PENDING_INTERNAL' AND r.id IS NOT NULL)
   OR (f.issuer_id IS NOT NULL AND f.initiated_by<>i.registered_by)
   THEN 1 ELSE 0 END),0) AS unsafe,
   COALESCE(SUM(CASE WHEN f.issuer_id IS NOT NULL THEN 1 ELSE 0 END),0) AS frozen
  FROM inv_external_issuer_candidates i
  LEFT JOIN inv_external_issuer_reviews r ON r.issuer_id=i.id
  LEFT JOIN inv_external_issuer_freezes f ON f.issuer_id=i.id`);
 const [extAuthorities]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   a.external_authority_state<>'UNVERIFIED' OR a.stock_posting<>'DISABLED'
   OR a.prepared_by<>i.registered_by OR
   JSON_UNQUOTE(JSON_EXTRACT(a.statement_json,'$.issuerExternallyAuthenticated'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(a.statement_json,'$.organizationAuthorityVerified'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(a.statement_json,'$.stockPostingState'))<>'DISABLED'
   OR (a.status='REVIEWED_CRYPTO_HELD' AND
     (r.id IS NULL OR r.decision<>'REVIEWED_CRYPTO_HELD'
      OR r.reviewer_id=a.prepared_by OR NOT r.signature_inspected))
   OR (a.status='REJECTED_INTERNAL' AND
      (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL'))
   OR (a.status='PENDING_INTERNAL' AND r.id IS NOT NULL)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_external_authority_attestations a
  JOIN inv_external_issuer_candidates i ON i.id=a.issuer_id
  LEFT JOIN inv_external_authority_reviews r ON r.attestation_id=a.id`);
 const [extFeeds]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   b.status<>'SIGNED_UNTRUSTED' OR b.external_publisher_authenticated<>'NO'
   OR b.submitted_by<>i.registered_by
   OR JSON_UNQUOTE(JSON_EXTRACT(b.manifest_json,'$.publisherExternallyAuthenticated'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(b.manifest_json,'$.stockPostingState'))<>'DISABLED'
   OR JSON_LENGTH(JSON_EXTRACT(b.manifest_json,'$.revokedFingerprints'))<>
    (SELECT COUNT(*) FROM inv_external_revocation_entries e WHERE e.bundle_id=b.id)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_external_revocation_bundles b
  JOIN inv_external_issuer_candidates i ON i.id=b.issuer_id`);
 const [extSequence]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS invalid FROM(
  SELECT issuer_id,MIN(sequence_number) AS firstSeq,
   MAX(sequence_number) AS lastSeq,COUNT(*) AS n
  FROM inv_external_revocation_bundles
  GROUP BY issuer_id HAVING firstSeq<>1 OR lastSeq<>n
 ) gaps`);
 if(Number(extIssuers[0].unsafe)!==0||Number(extAuthorities[0].unsafe)!==0||
  Number(extFeeds[0].unsafe)!==0||Number(extSequence[0].invalid)!==0)
  problems.push('Issuer/organizational authority/revocation internal integrity mismatch');
 // Phase 1AL: preprovisioned root candidates and offline issuer credentials
 // never establish corporate authority or authenticated external provider.
 const [providerPins]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   p.external_root_state<>'UNVERIFIED'
   OR p.root_fingerprint_sha256<>SHA2(FROM_BASE64(p.root_spki_b64),256)
   OR (p.status='REVIEWED_HELD' AND
    (r.id IS NULL OR r.decision<>'REVIEWED_HELD'
     OR r.reviewer_id=p.provisioned_by OR NOT r.pin_inspected))
   OR (p.status='REJECTED_INTERNAL' AND
    (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL'))
   OR (p.status='PENDING_INTERNAL' AND r.id IS NOT NULL)
   OR (f.pin_id IS NOT NULL AND f.initiated_by<>p.provisioned_by)
   THEN 1 ELSE 0 END),0) AS unsafe,
   COALESCE(SUM(CASE WHEN f.pin_id IS NOT NULL THEN 1 ELSE 0 END),0) AS frozen
  FROM inv_provider_pin_candidates p
  LEFT JOIN inv_provider_pin_reviews r ON r.pin_id=p.id
  LEFT JOIN inv_provider_pin_freezes f ON f.pin_id=p.id`);
 const [providerCredentials]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   c.corporate_identity_state<>'UNVERIFIED'
   OR c.external_issuer_state<>'UNVERIFIED' OR c.stock_posting<>'DISABLED'
   OR c.submitted_by<>p.provisioned_by
   OR JSON_UNQUOTE(JSON_EXTRACT(c.message_json,'$.externallyAuthenticatedRoot'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(c.message_json,'$.independentCorporateVerification'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(c.message_json,'$.stockPosting'))<>'DISABLED'
   OR (c.status='REVIEWED_CRYPTO_HELD' AND
    (r.id IS NULL OR r.decision<>'REVIEWED_CRYPTO_HELD'
     OR r.reviewer_id=c.submitted_by OR NOT r.source_inspected))
   OR (c.status='REJECTED_INTERNAL' AND
    (r.id IS NULL OR r.decision<>'REJECTED_INTERNAL'))
   OR (c.status='PENDING_INTERNAL' AND r.id IS NOT NULL)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_provider_org_credentials c
  JOIN inv_provider_pin_candidates p ON p.id=c.pin_id
  LEFT JOIN inv_provider_org_reviews r ON r.credential_id=c.id`);
 const [providerFeeds]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS total,
  COALESCE(SUM(CASE WHEN
   f.status<>'SIGNED_CANDIDATE' OR f.external_publisher_state<>'UNVERIFIED'
   OR f.imported_by<>p.provisioned_by
   OR JSON_UNQUOTE(JSON_EXTRACT(f.message_json,'$.externalPublisherVerified'))<>'false'
   OR JSON_UNQUOTE(JSON_EXTRACT(f.message_json,'$.stockPosting'))<>'DISABLED'
   OR JSON_LENGTH(JSON_EXTRACT(f.message_json,'$.revokedFingerprints'))<>
    (SELECT COUNT(*) FROM inv_provider_revocation_entries e WHERE e.feed_id=f.id)
   THEN 1 ELSE 0 END),0) AS unsafe
  FROM inv_provider_revocation_feeds f
  JOIN inv_provider_pin_candidates p ON p.id=f.pin_id`);
 const [providerSeq]=await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS invalid FROM(
  SELECT pin_id,MIN(sequence_number) AS firstSeq,MAX(sequence_number) AS lastSeq,
   COUNT(*) AS n FROM inv_provider_revocation_feeds
  GROUP BY pin_id HAVING firstSeq<>1 OR lastSeq<>n
 ) gaps`);
 if(Number(providerPins[0].unsafe)!==0||Number(providerCredentials[0].unsafe)!==0||
  Number(providerFeeds[0].unsafe)!==0||Number(providerSeq[0].invalid)!==0)
  problems.push('Pinned provider/organization credential/revocation chain internal invariant mismatch');
 const [mfa]=await db.query<RowDataPacket[]>(`SELECT
   SUM(CASE WHEN role='OWNER' AND status='ACTIVE' THEN 1 ELSE 0 END) AS owners,
   SUM(CASE WHEN role='REVIEWER' AND status='ACTIVE' THEN 1 ELSE 0 END) AS reviewers,
   SUM(CASE WHEN role='OWNER' AND status='ACTIVE' AND t.enabled_at IS NOT NULL THEN 1 ELSE 0 END) AS owner_mfa,
   SUM(CASE WHEN role='REVIEWER' AND status='ACTIVE' AND t.enabled_at IS NOT NULL THEN 1 ELSE 0 END) AS reviewer_mfa
   FROM auth_users u LEFT JOIN auth_totp_credentials t ON u.id=t.user_id`);
 const activeOwners=Number(mfa[0].owners??0),activeReviewers=Number(mfa[0].reviewers??0);
 if(env.MFA_REQUIRE_PRIVILEGED==='true' &&
   (Number(mfa[0].owner_mfa??0)<1||Number(mfa[0].reviewer_mfa??0)<1))
   problems.push('Privileged MFA policy enabled without enrolled active owner and reviewer');
 if(!['true','false',undefined].includes(env.MFA_REQUIRE_PRIVILEGED))
   problems.push('Invalid privileged MFA setting');
 if(!/^[a-fA-F0-9]{64}$/.test(env.MFA_ENCRYPTION_KEY??''))
   problems.push('Missing/invalid MFA encryption key');
 if(target==='staging'&&env.DB_SSL!=='true')problems.push('TLS is required in staging');
 return {
  ready:problems.length===0,target,
  migrationCount:actual.size,expectedMigrationCount:expected.length,
  heldPreparations:Number(holds[0].total),
  heldSupplierDispatchOutboxes:Number(supplierOutbox[0].total),
  heldGrnReconciliationEvidence:Number(heldGrn[0].total),
  hardZeroStockPositions:Number(stockGate[0].total),
  heldStockReleaseOutboxes:Number(releaseHolds[0].total),
  nonallocatingReservationPlans:Number(plans[0].total),
  unpostedBalancedJournalProposals:Number(journalSummary[0].total),
  unverifiedSerialCandidatesCheck:Number(badCandidates[0].total),
  untrustedProofKeyCandidates:Number(proofKeys[0].total),
  cryptographicallyMatchedUntrustedClaims:Number(proofClaims[0].total),
  oneTimeKeyPossessionChallenges:Number(keyChallenges[0].total),
  irrevocablyRetiredCandidates:Number(keyRetirements[0].total),
  internalOnlyKeyRotations:Number(keyRotations[0].total),
  unverifiedExternalIssuerCandidates:Number(extIssuers[0].total),
  frozenExternalIssuerCandidates:Number(extIssuers[0].frozen),
  internalHeldOrganizationalClaims:Number(extAuthorities[0].total),
  selfSignedRevocationBundles:Number(extFeeds[0].total),
  unverifiedProviderRootCandidates:Number(providerPins[0].total),
  permanentlyFrozenProviderPins:Number(providerPins[0].frozen),
  rootSignedHeldOrganizationalCredentials:Number(providerCredentials[0].total),
  pinnedRootSignedRevocationFeeds:Number(providerFeeds[0].total),
  activeOwnerCount:activeOwners,
  activeReviewerCount:activeReviewers,
  privilegedMfaPolicy:env.MFA_REQUIRE_PRIVILEGED==='true',
  problems,
  externalGates:{
   encryptedBackupAndRestoreRehearsal:'NOT_VERIFIED',
   browserHttpsMfaEndToEnd:'NOT_VERIFIED',
   secretKeyRecoveryAndRotation:'NOT_VERIFIED',
   externalNotificationAndDispatch:'DISABLED',
   externalTrustRootAuthentication:'NOT_VERIFIED',
   officialSupplierAndWarehouseAuthority:'NOT_VERIFIED',
   externallyPublishedRevocationTrust:'NOT_VERIFIED',
   preprovisionedProviderRootOwnership:'NOT_VERIFIED',
   corporateRegistryAndSignatory:'NOT_VERIFIED',
   pinnedTlsPublisherProductionAcceptance:'NOT_VERIFIED'
  }
 };
}
