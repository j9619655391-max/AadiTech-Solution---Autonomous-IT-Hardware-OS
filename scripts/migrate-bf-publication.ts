import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function bfMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BF_PUBLICATION_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BF migration only allowed in disposable CI or approved isolated TLS staging');
}
async function main(){
 bfMigrationTarget(process.env);
 const id='0034_bf_revocation_publication_holds';
 if(MIGRATIONS[33]!==id||MIGRATIONS.length<34)
  throw Error('1BF expected migration 0034 registry');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('1BF isolated DB configuration required');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [leases]=await conn.query<any[]>(
   "SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(leases[0]?.acquired)!==1)
   throw Error('1BF schema migration advisory lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const existing=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const prior of MIGRATIONS.slice(0,33)){
   const checksum=createHash('sha256').update(
    readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(existing.get(prior)!==checksum)
    throw Error('1BF missing/mismatched predecessor migration '+prior);
  }
  for(const applied of existing.keys())
   if(!MIGRATIONS.includes(applied as typeof MIGRATIONS[number]))
    throw Error('1BF unknown migration found '+applied);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(existing.has(id)){
   if(existing.get(id)!==checksum)throw Error('1BF applied schema checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BF migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
