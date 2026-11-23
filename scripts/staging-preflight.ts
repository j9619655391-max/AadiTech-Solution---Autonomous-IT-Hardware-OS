import 'dotenv/config';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
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
  const problems=[...result.problems];
  if(triggerIntegrity!=='PASS')
   problems.push('1EZ installed auth_users UPDATE trigger integrity unverified');
  if(target==='staging'&&runtimeDbPrivileges!=='PASS')
   problems.push('1FC staging runtime DB grant envelope unverified');
  const inspected={...result,
   ready:result.ready&&triggerIntegrity==='PASS'&&
    (target==='ci'||runtimeDbPrivileges==='PASS'),
   triggerIntegrity,runtimeDbPrivileges,
   independentDbaApprovalVerified:false,
   problems};
  process.stdout.write(JSON.stringify(inspected,null,2)+'\n');
  if(!inspected.ready)process.exitCode=1;
  if(target!==result.target)throw Error('Target changed during preflight');
 }finally{await connection.end();}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Preflight refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
