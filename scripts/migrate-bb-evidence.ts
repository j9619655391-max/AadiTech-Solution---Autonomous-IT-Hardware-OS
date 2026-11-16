import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function bbMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&
    env.BB_EVIDENCE_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&env.DB_SSL==='true'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))return 'staging';
 throw Error('Phase 1BB migration only permits disposable CI or approved TLS staging');
}
async function main(){
 bbMigrationTarget(process.env);
 const id='0030_bb_evidence_intake_holds';
 if(MIGRATIONS.at(-1)!==id||MIGRATIONS.length!==30)
  throw Error('Phase 1BB migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Phase 1BB requires complete DB configuration');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Phase 1BB migration lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const prior of MIGRATIONS.slice(0,-1)){
   const hash=createHash('sha256').update(
    readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(actual.get(prior)!==hash)throw Error('Phase 1BB prerequisite mismatch: '+prior);
  }
  for(const found of actual.keys())
   if(!MIGRATIONS.includes(found as typeof MIGRATIONS[number]))
    throw Error('Phase 1BB unknown applied migration');
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const hash=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==hash)throw Error('Phase 1BB checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,hash]);
  console.log('Applied:',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BB migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
