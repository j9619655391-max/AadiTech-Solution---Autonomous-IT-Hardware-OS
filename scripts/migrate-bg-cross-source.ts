import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function bgMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BG_CROSS_SOURCE_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BG migration refuses production or unapproved staging');
}
async function main(){
 bgMigrationTarget(process.env);
 const id='0035_bg_cross_source_acceptance_holds';
 if(MIGRATIONS[34]!==id||MIGRATIONS.length<35)
  throw Error('Phase 1BG schema registry expected migration 0035');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Phase 1BG complete isolated database config required');
 const db=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await db.query<any[]>(
   "SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)
   throw Error('Phase 1BG migration advisory mutex not acquired');
  locked=true;
  const [rows]=await db.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const prior of MIGRATIONS.slice(0,34)){
   const expected=createHash('sha256').update(
    readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(applied.get(prior)!==expected)
    throw Error('Phase 1BG missing or modified predecessor schema '+prior);
  }
  for(const id of applied.keys())
   if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
    throw Error('Phase 1BG unexpected applied schema '+id);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==checksum)
    throw Error('Phase 1BG schema checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await db.query(stmt);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await db.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BG migration rejected:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
