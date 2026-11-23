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
const expectedTriggers=['trg_ew_reviewer_grant_quarantine','trg_ew_reviewer_session_quarantine'];
async function assertInstalled(conn:mysql.Connection){
 const [rows]=await conn.query<any[]>(`SELECT TRIGGER_NAME FROM information_schema.TRIGGERS
  WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='auth_users'
    AND ACTION_TIMING='AFTER' AND EVENT_MANIPULATION='UPDATE'`);
 const actual=new Set(rows.map(row=>String(row.TRIGGER_NAME)));
 if(!expectedTriggers.every(name=>actual.has(name)))
  throw Error('1EW required database transition trigger missing');
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
