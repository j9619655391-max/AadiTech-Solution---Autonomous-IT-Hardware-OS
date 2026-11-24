import 'dotenv/config';
import mysql from 'mysql2/promise';
import type {RowDataPacket} from 'mysql2/promise';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';

// This is read-only applicant-controlled observation, not independent DBA approval.
export function runtimePrivilegePreflightTarget(env:NodeJS.ProcessEnv):'staging'{
 if(env.RUNTIME_DB_PRIVILEGE_PREFLIGHT==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
    env.DB_SSL==='true'&&env.NODE_ENV==='staging'&&env.CRM_TEST_DB!=='1')
  return 'staging';
 throw Error('1FB privilege observation refused without explicit isolated TLS staging');
}
// Phase 1FG: MySQL 8 CURRENT_ROLE() returns NONE only when no session roles
// are active. Fail closed on null/empty/unknown values rather than granting
// effective role privileges to a service session.
export function inactiveRuntimeRoles(observed:unknown):boolean{
 return observed==='NONE';
}
export const OWNER_GUARD_ROUTINE='aaditech_guard_active_owner';
export type RuntimeGrantAssessment={allowed:boolean;grantCount:number;dataGrantCount:number;dataGrantTables:string[];routineGrantCount:number;reasons:string[]};
const DML=new Set(['SELECT','INSERT','UPDATE','DELETE']);
// 1GB: the application may read and append field-service planning records,
// never rewrite or remove existing plan or creation-audit evidence.
const FIELD_SERVICE_APPEND_ONLY_TABLES=new Set([
 'field_service_plans_internal','field_service_plan_audit_internal'
]);
// 1GD: CRM uses versioned soft deletion; quote evidence is append-only.
const CRM_QUOTE_APPEND_ONLY_TABLES=new Set([
 'crm_audit_events','sales_quote_drafts','sales_quote_draft_items',
 'sales_quote_draft_revisions'
]);
const CRM_QUOTE_NO_DELETE_TABLES=new Set([
 'crm_customers','crm_products','crm_leads','sales_quote_create_requests'
]);
// Phase 1FE: runtime grants are not allowed to bypass reviewer/identity
// quarantine by writing authority or authentication state tables directly.
// An approved isolated authority writer must use separate credentials and
// independently governed operations; it is NOT provisioned by this script.
const PROTECTED_AUTHORITY_TABLES=new Set([
 'auth_users','auth_sessions','app_reviewer_scope_grants',
 'app_reviewer_scope_events','auth_security_events',
 'auth_totp_credentials','auth_totp_recovery_codes','auth_mfa_challenges'
]);
export function assessRuntimeGrantEnvelope(grants:readonly string[],database:string):RuntimeGrantAssessment{
 const reasons:string[]=[];
 if(!/^[a-z0-9_]+$/.test(database)||database.length>64)
  reasons.push('Target schema identifier rejected');
 if(!Array.isArray(grants)||grants.length===0||grants.length>128)
  reasons.push('Grant inventory missing or oversized');
 let dataGrantCount=0;
 let routineGrantCount=0;
 const dataGrantTables=new Set<string>();
 for(const line of grants){
  if(typeof line!=='string'||line.length>8192||/[\r\n\0]/.test(line)){
   reasons.push('Grant entry malformed');continue;
  }
  const match=/^GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+(.+)$/i.exec(line.trim());
  if(!match||/\bWITH\b/i.test(line)){
   reasons.push('Grant statement/role delegation unrecognized');continue;
  }
  const privileges=match[1].split(',').map(part=>part.trim().toUpperCase());
  const scope=match[2].trim().replace(/\x60([A-Za-z0-9_]+)\x60/g,'$1');
  if(scope.includes(String.fromCharCode(96))||scope.includes('"')||scope.includes("'")){
   reasons.push('Grant SQL object quoting unrecognized');continue;
  }
  if(scope==='*.*'&&privileges.length===1&&privileges[0]==='USAGE')continue;
  // Phase 1FO: a SINGLE exact procedure-level EXECUTE exception can provide
  // same-transaction auth_users FOR UPDATE without table SELECT privileges.
  // Never admit EXECUTE on a schema, function, unrelated routine or wildcard.
  if(/^PROCEDURE\s+/i.test(scope)){
   const routine=/^PROCEDURE\s+([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$/i.exec(scope);
   if(!routine||routine[1].toLowerCase()!==database.toLowerCase()||
      routine[2].toLowerCase()!==OWNER_GUARD_ROUTINE||
      privileges.length!==1||privileges[0]!=='EXECUTE'){
    reasons.push('Runtime routine EXECUTE outside the exact OWNER guard is forbidden');
   }else{
    routineGrantCount++;
    if(routineGrantCount>1)
     reasons.push('Duplicate OWNER guard EXECUTE grants are forbidden');
   }
   continue;
  }
  const parts=scope.split('.');
  if(parts.length!==2||parts[0].toLowerCase()!==database.toLowerCase()||
     (parts[1]!=='*'&&!/^[A-Za-z0-9_]+$/.test(parts[1]))){
   reasons.push('Grant scope exceeds isolated target schema');continue;
  }
  if(!privileges.length||privileges.some(priv=>!DML.has(priv))){
   reasons.push('Grant includes schema/DDL/admin/unknown privilege');continue;
  }
  // Phase 1FF: schema-wide SELECT exposes passwords, MFA secrets,
  // private customer data and internal authority evidence on every table.
  // Runtime principals need explicit, reviewed table-level access.
  if(parts[1]==='*'){
   reasons.push('Runtime schema-wide data access forbidden');continue;
  }
  // Phase 1FH: an explicit table SELECT still exposes raw password/MFA and
  // reviewer-authority records. A separate credential-limited auth service
  // and redacted views require independent design and live acceptance.
  if(privileges.includes('SELECT')&&PROTECTED_AUTHORITY_TABLES.has(parts[1].toLowerCase())){
   reasons.push('Runtime authority/authentication table read forbidden');continue;
  }
  const hasWrite=privileges.some(priv=>priv!=='SELECT');
  if(hasWrite&&PROTECTED_AUTHORITY_TABLES.has(parts[1].toLowerCase())){
   reasons.push('Runtime authority/authentication table mutation forbidden');continue;
  }
  if(FIELD_SERVICE_APPEND_ONLY_TABLES.has(parts[1].toLowerCase())&&
     privileges.some(priv=>priv!=='SELECT'&&priv!=='INSERT')){
   reasons.push('Runtime field service immutable record mutation forbidden');continue;
  }
  // 1GC: M16 supports status updates, never ticket deletion or audit rewriting.
  const tableName=parts[1].toLowerCase();
  if((tableName==='service_ticket_audit_internal'&&
      privileges.some(priv=>priv!=='SELECT'&&priv!=='INSERT'))||
     (tableName==='service_tickets_internal'&&privileges.includes('DELETE'))){
   reasons.push('Runtime service ticket history mutation forbidden');continue;
  }
  if((CRM_QUOTE_APPEND_ONLY_TABLES.has(tableName)&&
      privileges.some(priv=>priv!=='SELECT'&&priv!=='INSERT'))||
     (CRM_QUOTE_NO_DELETE_TABLES.has(tableName)&&privileges.includes('DELETE'))){
   reasons.push('Runtime CRM/quote provenance mutation forbidden');continue;
  }
  dataGrantCount++;
  dataGrantTables.add(parts[1].toLowerCase());
 }
 if(!dataGrantCount)reasons.push('No bounded target-schema DML grant observed');
 return {allowed:reasons.length===0,grantCount:grants.length,dataGrantCount,
  dataGrantTables:[...dataGrantTables].sort(),routineGrantCount,reasons};
}

// Phase 1FJ: a table-scoped grant may actually target a SQL SECURITY DEFINER
// VIEW that reads otherwise quarantined tables. Classify every granted object
// from same-session information_schema metadata; absence, duplicates, denied
// metadata, or any VIEW are non-acceptance. No data or view body is read.
export function verifiedRuntimeBaseTableTargets(
 targetTables:readonly string[],metadata:readonly unknown[]
):boolean{
 if(!Array.isArray(targetTables)||!targetTables.length||targetTables.length>128||
    !Array.isArray(metadata)||metadata.length>4096)return false;
 const objects=new Map<string,string>();
 for(const candidate of metadata){
  if(!candidate||typeof candidate!=='object'||Array.isArray(candidate))return false;
  const row=candidate as {TABLE_NAME?:unknown;TABLE_TYPE?:unknown};
  if(typeof row.TABLE_NAME!=='string'||typeof row.TABLE_TYPE!=='string'||
     !/^[A-Za-z0-9_]{1,64}$/.test(row.TABLE_NAME))return false;
  const key=row.TABLE_NAME.toLowerCase();
  if(objects.has(key))return false; // case-collision or duplicate metadata
  objects.set(key,row.TABLE_TYPE);
 }
 return targetTables.every(table=>typeof table==='string'&&
  /^[a-z0-9_]{1,64}$/.test(table)&&objects.get(table)==='BASE TABLE');
}

// This classification cannot prove who controls the DEFINER account or that
// the installed routine body matches the reviewed source. External DBA trust
// and a separately verified routine-body digest are still mandatory.
export function verifiedRuntimeDefinerOwnerGuard(
 rows:readonly unknown[],database:string
):boolean{
 if(!Array.isArray(rows)||rows.length>4096||!(/^[a-z0-9_]{1,64}$/).test(database))
  return false;
 let found=0;
 for(const raw of rows){
  if(!raw||typeof raw!=='object'||Array.isArray(raw))return false;
  const row=raw as {ROUTINE_NAME?:unknown;ROUTINE_SCHEMA?:unknown;
   ROUTINE_TYPE?:unknown;SECURITY_TYPE?:unknown};
  if(typeof row.ROUTINE_NAME!=='string'||typeof row.ROUTINE_SCHEMA!=='string'||
     typeof row.ROUTINE_TYPE!=='string'||typeof row.SECURITY_TYPE!=='string')
   return false;
  if(row.ROUTINE_NAME.toLowerCase()===OWNER_GUARD_ROUTINE){
   found++;
   if(found>1||row.ROUTINE_NAME!==OWNER_GUARD_ROUTINE||
      row.ROUTINE_SCHEMA!==database||row.ROUTINE_TYPE!=='PROCEDURE'||
      row.SECURITY_TYPE!=='DEFINER')return false;
  }
 }
 return found===1;
}

async function main(){
 runtimePrivilegePreflightTarget(process.env);
 const cfg=getDatabaseConfig();
 if(!cfg.database||!cfg.host||!cfg.user||!cfg.password||!cfg.ssl)
  throw Error('1FB dedicated TLS staging DB settings missing');
 const conn=await mysql.createConnection(cfg);
 try{
  // Both statements are read-only; identify the connection's actual principal.
  const [who]=await conn.query<RowDataPacket[]>(
   'SELECT CURRENT_USER() AS authenticated_user, DATABASE() AS selected_schema, CURRENT_ROLE() AS active_roles');
  const authenticatedUser=String(who[0]?.authenticated_user??'');
  const selectedSchema=String(who[0]?.selected_schema??'');
  const [rows]=await conn.query<RowDataPacket[]>('SHOW GRANTS FOR CURRENT_USER()');
  const grants=rows.map(row=>{
   const values=Object.values(row);
   return values.length===1&&typeof values[0]==='string'?values[0]:'';
  });
  const receipt=assessRuntimeGrantEnvelope(grants,cfg.database);
  if(receipt.allowed){
   const [objects]=await conn.query<RowDataPacket[]>(
    'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()');
   if(!verifiedRuntimeBaseTableTargets(receipt.dataGrantTables,objects))
    receipt.reasons.push('1FJ runtime grant object type unverified');
  }
  // Staging runtime must possess exact procedure-level EXECUTE, not raw
  // authentication reads; same-session metadata must show a DEFINER PROCEDURE.
  if(receipt.routineGrantCount!==1)
   receipt.reasons.push('1FO runtime owner guard EXECUTE grant missing or duplicated');
  if(receipt.routineGrantCount===1){
   const [routines]=await conn.query<RowDataPacket[]>(
    'SELECT ROUTINE_NAME,ROUTINE_SCHEMA,ROUTINE_TYPE,SECURITY_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()');
   if(!verifiedRuntimeDefinerOwnerGuard(routines,cfg.database))
    receipt.reasons.push('1FO owner guard routine metadata unverified');
  }
  if(!authenticatedUser||selectedSchema!==cfg.database)
   receipt.reasons.push('Connected DB identity/schema did not match expected target');
  if(!inactiveRuntimeRoles(who[0]?.active_roles))
   receipt.reasons.push('1FG active runtime DB roles present or unverified');
  const allowed=receipt.reasons.length===0;
  // Never print raw grants, DB usernames, passwords or host names.
  process.stdout.write(JSON.stringify({
   technicalPrivilegeEnvelope:allowed?'PASS':'HOLD',
   grantCount:receipt.grantCount,dataGrantCount:receipt.dataGrantCount,
   reasons:receipt.reasons,
   accountFingerprint:authenticatedUser?
    createHash('sha256').update(authenticatedUser).digest('hex').slice(0,16):null,
   outsideDbaControlVerified:false,
   independentSecurityApproval:false,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'
  },null,2)+'\n');
  if(!allowed)process.exitCode=1;
 }finally{await conn.end();}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(()=>{console.error('1FB runtime privilege observation refused; inspect protected operator evidence');process.exitCode=1;});
