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
export type RuntimeGrantAssessment={allowed:boolean;grantCount:number;dataGrantCount:number;reasons:string[]};
const DML=new Set(['SELECT','INSERT','UPDATE','DELETE']);
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
  const parts=scope.split('.');
  if(parts.length!==2||parts[0].toLowerCase()!==database.toLowerCase()||
     (parts[1]!=='*'&&!/^[A-Za-z0-9_]+$/.test(parts[1]))){
   reasons.push('Grant scope exceeds isolated target schema');continue;
  }
  if(!privileges.length||privileges.some(priv=>!DML.has(priv))){
   reasons.push('Grant includes schema/DDL/admin/unknown privilege');continue;
  }
  const hasWrite=privileges.some(priv=>priv!=='SELECT');
  if(hasWrite&&parts[1]==='*'){
   reasons.push('Runtime schema-wide data mutation grant forbidden');continue;
  }
  if(hasWrite&&PROTECTED_AUTHORITY_TABLES.has(parts[1].toLowerCase())){
   reasons.push('Runtime authority/authentication table mutation forbidden');continue;
  }
  dataGrantCount++;
 }
 if(!dataGrantCount)reasons.push('No bounded target-schema DML grant observed');
 return {allowed:reasons.length===0,grantCount:grants.length,dataGrantCount,reasons};
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
   'SELECT CURRENT_USER() AS authenticated_user, DATABASE() AS selected_schema');
  const authenticatedUser=String(who[0]?.authenticated_user??'');
  const selectedSchema=String(who[0]?.selected_schema??'');
  const [rows]=await conn.query<RowDataPacket[]>('SHOW GRANTS FOR CURRENT_USER()');
  const grants=rows.map(row=>{
   const values=Object.values(row);
   return values.length===1&&typeof values[0]==='string'?values[0]:'';
  });
  const receipt=assessRuntimeGrantEnvelope(grants,cfg.database);
  if(!authenticatedUser||selectedSchema!==cfg.database)
   receipt.reasons.push('Connected DB identity/schema did not match expected target');
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
