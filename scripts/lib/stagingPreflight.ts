import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {Pool,RowDataPacket} from 'mysql2/promise';

export const MIGRATIONS=[
 '0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency',
 '0005_quote_revisions','0006_quote_reviews','0007_quote_release_holds',
 '0008_reviewer_roles','0009_auth_security_events','0010_auth_login_security',
 '0011_totp_mfa','0012_mfa_audit_events','0013_mfa_recovery_rotation',
 '0014_inventory_opening_counts'
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
  heldPreparations:Number(holds[0].total),activeOwnerCount:activeOwners,
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
