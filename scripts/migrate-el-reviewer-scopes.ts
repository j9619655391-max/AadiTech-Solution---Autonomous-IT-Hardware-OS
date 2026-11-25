import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

// Phase 1EL: no production migration target and no legacy row re-attribution.
export function reviewerScopeMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.EL_REVIEW_SCOPE_MIGRATION_APPROVED==='YES' &&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES' &&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'') &&
    env.DB_SSL==='true' && env.NODE_ENV!=='production')return 'staging';
 throw Error('1EL migration denied outside disposable CI or explicitly approved TLS staging');
}
async function main(){
 reviewerScopeMigrationTarget(process.env);
 const id='0043_el_reviewer_scope_candidates';
 if(MIGRATIONS[42]!==id||MIGRATIONS.length<43)
  throw Error('1EL exact migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('1EL DB config incomplete');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)throw Error('1EL migration mutex unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const found=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
  for(const old of MIGRATIONS.slice(0,42)){
   const expected=createHash('sha256').update(readFileSync('database/migrations/'+old+'.sql')).digest('hex');
   if(found.get(old)!==expected)throw Error('1EL missing or modified prerequisite '+old);
  }
  for(const old of found.keys())
   if(!MIGRATIONS.includes(old as typeof MIGRATIONS[number]))
    throw Error('1EL unexpected schema migration '+old);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(found.has(id)){
   if(found.get(id)!==checksum)throw Error('1EL migration checksum changed');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(statement);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1EL migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
