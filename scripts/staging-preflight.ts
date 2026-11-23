import 'dotenv/config';
import mysql from 'mysql2/promise';
import {createHash} from 'node:crypto';
import {getDatabaseConfig,authDatabaseCredentialState} from '../server/db';
import {checkPreflightTarget,runStagingPreflight} from './lib/stagingPreflight';
import {verifyEwTriggerBodies,type EwInstalledTrigger} from './migrate-ew-role-cycle';
import {assessRuntimeGrantEnvelope,inactiveRuntimeRoles,runtimePrivilegePreflightTarget,verifiedRuntimeBaseTableTargets} from './phase1fb-runtime-db-privileges';

// Phase 1EZ: read installed enforcement metadata without running migrations,
// repairing triggers, opening reviewer scopes or elevating release status.
export async function checkInstalledEwTriggerIntegrity(db: Pick<mysql.Pool,'query'>):Promise<void>{
 const [rows]=await db.query<EwInstalledTrigger[] & mysql.RowDataPacket[]>(`SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING,EVENT_MANIPULATION FROM information_schema.TRIGGERS
  WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='auth_users'`);
 verifyEwTriggerBodies(rows);
}


// Phase 1FC: evaluate the staging *runtime* principal, not a claimed account.
// CURRENT_USER and SHOW GRANTS must run on the SAME checked-out connection;
// issuing them separately on a pool could observe different sessions.
export async function checkStagingRuntimeDbPrivilegeIntegrity(
 db:Pick<mysql.Pool,'getConnection'>,database:string
):Promise<{grantCount:number;dataGrantCount:number}>{
 const conn=await db.getConnection();
 try{
  const [identity]=await conn.query<mysql.RowDataPacket[]>(
   'SELECT CURRENT_USER() AS authenticated_user, DATABASE() AS selected_schema, CURRENT_ROLE() AS active_roles');
  if(identity.length!==1||typeof identity[0]?.authenticated_user!=='string'||
     !identity[0].authenticated_user||identity[0].selected_schema!==database||
     !inactiveRuntimeRoles(identity[0].active_roles))
   throw Error('1FC runtime database identity/schema mismatch');
  const [rows]=await conn.query<mysql.RowDataPacket[]>(
   'SHOW GRANTS FOR CURRENT_USER()');
  const grants=rows.map(row=>{
   const values=Object.values(row);
   return values.length===1&&typeof values[0]==='string'?values[0]:'';
  });
  const assessment=assessRuntimeGrantEnvelope(grants,database);
  if(!assessment.allowed)throw Error('1FC runtime database grant envelope unverified');
  // 1FJ: a narrow GRANT may target a DEFINER view instead of a base table.
  // Observe type on the same authenticated connection without reading data.
  const [objects]=await conn.query<mysql.RowDataPacket[]>(
   'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()');
  if(!verifiedRuntimeBaseTableTargets(assessment.dataGrantTables,objects))
   throw Error('1FJ runtime grant target base-table metadata unverified');
  return {grantCount:assessment.grantCount,
   dataGrantCount:assessment.dataGrantCount};
 }finally{conn.release();}
}

// Phase 1FO: an AUTH_DB_USER value is not evidence of a different MySQL
// security principal. Observe both authenticated identities on actual,
// independent checked-out sessions, and prove the general runtime connection
// cannot even SELECT a zero-row probe of auth_users while the auth candidate
// can. The probe returns no private records, and errors never expose raw grants.
export async function checkStagingAuthPrincipalBoundary(
 runtimePool:Pick<mysql.Pool,'getConnection'>,
 candidateAuthPool:Pick<mysql.Pool,'getConnection'>,
 database:string,expectedRuntimeUser:string,expectedAuthUser:string
):Promise<{runtimeFingerprint:string;authFingerprint:string}>{
 if(!/^[a-z0-9_]{1,64}$/.test(database)||
    !/^[A-Za-z0-9_.-]{1,32}$/.test(expectedRuntimeUser)||
    !/^[A-Za-z0-9_.-]{1,32}$/.test(expectedAuthUser)||
    expectedRuntimeUser===expectedAuthUser)
  throw Error('1FO distinct authenticated DB principal inputs unverified');
 const runtime=await runtimePool.getConnection();
 try{
  const auth=await candidateAuthPool.getConnection();
  try{
   const identitySQL='SELECT CURRENT_USER() AS principal_name, DATABASE() AS selected_schema, CURRENT_ROLE() AS active_roles';
   const [runtimeRows]=await runtime.query<mysql.RowDataPacket[]>(identitySQL);
   const [authRows]=await auth.query<mysql.RowDataPacket[]>(identitySQL);
   const valid=(rows:mysql.RowDataPacket[],expected:string)=>{
    if(!Array.isArray(rows)||rows.length!==1)return false;
    const record=rows[0];
    return typeof record.principal_name==='string'&&
     record.principal_name.startsWith(expected+'@')&&
     record.principal_name.length>expected.length+1&&
     record.selected_schema===database&&inactiveRuntimeRoles(record.active_roles);
   };
   if(!valid(runtimeRows,expectedRuntimeUser)||
      !valid(authRows,expectedAuthUser)||
      runtimeRows[0].principal_name===authRows[0].principal_name)
    throw Error('1FO authenticated DB principal/schema/role mismatch');
   let runtimeDenied=false;
   try{await runtime.query('SELECT id FROM auth_users LIMIT 0');}
   catch(error){
    const code=error&&typeof error==='object'&&'code' in error?error.code:null;
    runtimeDenied=code==='ER_TABLEACCESS_DENIED_ERROR'||
     code==='ER_COLUMNACCESS_DENIED_ERROR'||code==='ER_DBACCESS_DENIED_ERROR';
   }
   if(!runtimeDenied)throw Error('1FO runtime protected table denial unverified');
   // Auth candidate must have its own bounded SELECT, without fetching data.
   await auth.query('SELECT id FROM auth_users LIMIT 0');
   const fingerprint=(name:string)=>createHash('sha256').update(name).digest('hex').slice(0,16);
   return {runtimeFingerprint:fingerprint(runtimeRows[0].principal_name),
    authFingerprint:fingerprint(authRows[0].principal_name)};
  }finally{auth.release();}
 }finally{runtime.release();}
}

async function main(){
 const target=checkPreflightTarget(process.env);
 const cfg=getDatabaseConfig();
 if(!cfg.database||!cfg.host||!cfg.user||!cfg.password)
  throw Error('Complete database connection settings are required');
 const connection= mysql.createPool({...cfg,connectionLimit:1});
 try{
  const result=await runStagingPreflight(connection,process.env);
  // Migration checksum checks alone cannot attest the installed SQL bodies.
  // Preserve a red, non-sensitive receipt on denied metadata access or drift.
  let triggerIntegrity:'PASS'|'HOLD'='HOLD';
  try {await checkInstalledEwTriggerIntegrity(connection);triggerIntegrity='PASS';}
  catch { /* absence, metadata denial, extra BEFORE trigger or body drift: HOLD */ }
  // CI exercises migration/trigger invariants, but cannot prove independent
  // staging runtime privileges. Never label CI as a real-DB grant PASS.
  let runtimeDbPrivileges:'PASS'|'HOLD'|'NOT_EVALUATED_CI'=
   target==='ci'?'NOT_EVALUATED_CI':'HOLD';
  if(target==='staging'){
   try{
    runtimePrivilegePreflightTarget(process.env);
    if(!cfg.ssl)throw Error('1FC staging TLS configuration absent');
    await checkStagingRuntimeDbPrivilegeIntegrity(connection,cfg.database);
    runtimeDbPrivileges='PASS';
   }catch{ /* denied metadata, wide grants, missing opt-in, wrong DB: HOLD */ }
  }
  // Phase 1FL is a candidate pool split, not proof that all application
  // transactions can run under genuinely restricted DB privileges.
  const authCredentialSeparation=target==='ci'?'NOT_EVALUATED_CI':
   authDatabaseCredentialState(process.env)==='SEPARATE_CANDIDATE'? 'UNVERIFIED_CANDIDATE':'HOLD';
  let authPrincipalBoundary:'PASS'|'HOLD'|'NOT_EVALUATED_CI'=
   target==='ci'?'NOT_EVALUATED_CI':'HOLD';
  let authPrincipalFingerprints:{runtimeFingerprint:string;authFingerprint:string}|null=null;
  if(target==='staging'&&authCredentialSeparation==='UNVERIFIED_CANDIDATE'){
   let authCandidate:mysql.Pool|undefined;
   try{
    runtimePrivilegePreflightTarget(process.env);
    if(!cfg.ssl)throw Error('1FO staged TLS absent');
    authCandidate=mysql.createPool({...cfg,user:process.env.AUTH_DB_USER!,
     password:process.env.AUTH_DB_PASSWORD!,connectionLimit:1});
    authPrincipalFingerprints=await checkStagingAuthPrincipalBoundary(
     connection,authCandidate,cfg.database,cfg.user,process.env.AUTH_DB_USER!);
    authPrincipalBoundary='PASS';
   }catch{/* Missing, identical, unauthorized, active-role or SQL error -> HOLD. */}
   finally{if(authCandidate)await authCandidate.end();}
  }
  const problems=[...result.problems];
  if(target==='staging'&&authPrincipalBoundary!=='PASS')
   problems.push('1FO authenticated dual-principal and runtime protected-table denial unverified');
  if(target==='staging')problems.push('1FL auth/runtime credential and end-to-end service separation not independently verified');
  if(triggerIntegrity!=='PASS')
   problems.push('1EZ installed auth_users UPDATE trigger integrity unverified');
  if(target==='staging'&&runtimeDbPrivileges!=='PASS')
   problems.push('1FC staging runtime DB grant envelope unverified');
  const inspected={...result,
   ready:result.ready&&triggerIntegrity==='PASS'&&
    (target==='ci'||runtimeDbPrivileges==='PASS')&&target==='ci',
   triggerIntegrity,runtimeDbPrivileges,authCredentialSeparation,
   authPrincipalBoundary,authPrincipalFingerprints,
   authFunctionalSeparationVerified:false,
   independentDbaApprovalVerified:false,
   problems};
  process.stdout.write(JSON.stringify(inspected,null,2)+'\n');
  if(!inspected.ready)process.exitCode=1;
  if(target!==result.target)throw Error('Target changed during preflight');
 }finally{await connection.end();}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Preflight refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
