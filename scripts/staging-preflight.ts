import 'dotenv/config';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {checkPreflightTarget,runStagingPreflight} from './lib/stagingPreflight';
import {verifyEwTriggerBodies,type EwInstalledTrigger} from './migrate-ew-role-cycle';

// Phase 1EZ: read installed enforcement metadata without running migrations,
// repairing triggers, opening reviewer scopes or elevating release status.
export async function checkInstalledEwTriggerIntegrity(db: Pick<mysql.Pool,'query'>):Promise<void>{
 const [rows]=await db.query<EwInstalledTrigger[] & mysql.RowDataPacket[]>(`SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING,EVENT_MANIPULATION FROM information_schema.TRIGGERS
  WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='auth_users'`);
 verifyEwTriggerBodies(rows);
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
  const inspected={...result,
   ready:result.ready&&triggerIntegrity==='PASS',triggerIntegrity,
   problems:triggerIntegrity==='PASS'?result.problems:
    [...result.problems,'1EZ installed auth_users UPDATE trigger integrity unverified']};
  process.stdout.write(JSON.stringify(inspected,null,2)+'\n');
  if(!inspected.ready)process.exitCode=1;
  if(target!==result.target)throw Error('Target changed during preflight');
 }finally{await connection.end();}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Preflight refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
