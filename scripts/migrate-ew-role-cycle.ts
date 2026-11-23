import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

// Explicitly bounded to disposable CI or approved isolated TLS staging.
// Not a production migration path and not authority for reviewer reactivation.
export function ewRoleCycleMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.EW_ROLE_CYCLE_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
    env.DB_SSL==='true'&&env.NODE_ENV!=='production')return 'staging';
 throw Error('1EW migration denied outside disposable CI or explicitly approved isolated TLS staging');
}
// Phase 1EX: a trigger name alone is insufficient evidence that the installed
// trigger still revokes reviewer grants and invalidates sessions. This validates
// observed MySQL ACTION_STATEMENT bodies; it is NOT an external attestation or
// protection against privileged SQL actors changing them after this check.
export type EwInstalledTrigger={TRIGGER_NAME:string;ACTION_STATEMENT:string|null};
const expectedTriggerBodies=new Map([
 ['trg_ew_reviewer_grant_quarantine',
  "UPDATE app_reviewer_scope_grants SET state='REVOKED' WHERE reviewer_user_id=NEW.id AND state='ACTIVE' AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)"],
 ['trg_ew_reviewer_session_quarantine',
  'DELETE FROM auth_sessions WHERE user_id=NEW.id AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)']
]);
// MySQL can preserve formatting differently. Ignore ONLY whitespace and
// identifier quoting, never operators, predicates, tables or string literals.
// In particular preserve string literal case; do not mask a changed grant state.
function canonicalTriggerStatement(sql:string){
 return sql.replace(/`/g,'').replace(/\s+/g,' ').replace(/\s*([=<>(),])\s*/g,'$1').trim();
}
export function verifyEwTriggerBodies(rows:EwInstalledTrigger[]):void{
 if(rows.length!==expectedTriggerBodies.size)
  throw Error('1EX missing or unexpected auth_users AFTER UPDATE trigger');
 const seen=new Set<string>();
 for(const row of rows){
  const name=String(row.TRIGGER_NAME??'').toLowerCase();
  const expected=expectedTriggerBodies.get(name);
  if(!expected||seen.has(name))throw Error('1EX unknown or duplicate auth_users AFTER UPDATE trigger');
  if(canonicalTriggerStatement(String(row.ACTION_STATEMENT??''))!==canonicalTriggerStatement(expected))
   throw Error('1EX trigger ACTION_STATEMENT drift: '+name);
  seen.add(name);
 }
 if(seen.size!==expectedTriggerBodies.size)throw Error('1EX required trigger missing');
}
async function assertInstalled(conn:mysql.Connection){
 const [rows]=await conn.query<EwInstalledTrigger[] & mysql.RowDataPacket[]>(`SELECT TRIGGER_NAME,ACTION_STATEMENT FROM information_schema.TRIGGERS
  WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='auth_users'
    AND ACTION_TIMING='AFTER' AND EVENT_MANIPULATION='UPDATE'`);
 verifyEwTriggerBodies(rows);
}
async function main(){
 ewRoleCycleMigrationTarget(process.env);
 const id='0048_ew_role_cycle_quarantine';
 if(MIGRATIONS[47]!==id||MIGRATIONS.length<48)
  throw Error('1EW exact migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('1EW DB config incomplete');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)throw Error('1EW migration mutex unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
  for(const old of MIGRATIONS.slice(0,47)){
   const checksum=createHash('sha256').update(readFileSync('database/migrations/'+old+'.sql')).digest('hex');
   if(applied.get(old)!==checksum)throw Error('1EW missing/mismatched prerequisite '+old);
  }
  for(const old of applied.keys())
   if(!MIGRATIONS.includes(old as typeof MIGRATIONS[number]))
    throw Error('1EW unexpected schema migration '+old);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==checksum)throw Error('1EW migration checksum drift');
   await assertInstalled(conn);
   console.log('Already applied:',id);return;
  }
  // No silent preexisting grant repair: quarantine and investigate under
  // separate explicit owner/security approval before a staging migration.
  const [invalid]=await conn.query<any[]>(`SELECT COUNT(*) AS n
   FROM app_reviewer_scope_grants g JOIN auth_users u ON u.id=g.reviewer_user_id
   WHERE g.state='ACTIVE' AND (u.role<>'REVIEWER' OR u.status<>'ACTIVE')`);
  if(Number(invalid[0].n)!==0)throw Error('1EW active grants for inactive/nonreviewer identities: manual quarantine required');
  // MySQL DDL commits independently: an interrupted partial trigger install
  // is fail-closed and must be manually reconciled on the disposable target.
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(statement);
  await assertInstalled(conn);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1EW migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
