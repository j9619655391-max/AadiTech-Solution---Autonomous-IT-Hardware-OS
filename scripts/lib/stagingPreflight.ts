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
 '0018_acknowledgment_grn_holds'
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
  activeOwnerCount:activeOwners,
  activeReviewerCount:activeReviewers,
  privilegedMfaPolicy:env.MFA_REQUIRE_PRIVILEGED==='true',
  problems,
  externalGates:{
   encryptedBackupAndRestoreRehearsal:'NOT_VERIFIED',
   browserHttpsMfaEndToEnd:'NOT_VERIFIED',
   secretKeyRecoveryAndRotation:'NOT_VERIFIED',
   externalNotificationAndDispatch:'DISABLED'
  }
 };
}
