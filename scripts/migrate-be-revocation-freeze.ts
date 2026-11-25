import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function beMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BE_FREEZE_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BE migration refuses production and non-disposable environments');
}
async function main(){
 beMigrationTarget(process.env);
 const id='0033_be_revocation_freeze_holds';
 if(MIGRATIONS[32]!==id||MIGRATIONS.length<33)
  throw Error('1BE migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('1BE complete isolated DB configuration required');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>(
   "SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)
   throw Error('1BE migration advisory lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const prior of MIGRATIONS.slice(0,32)){
   const checksum=createHash('sha256').update(
    readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(actual.get(prior)!==checksum)
    throw Error('1BE missing/mismatched predecessor '+prior);
  }
  for(const applied of actual.keys())
   if(!MIGRATIONS.includes(applied as typeof MIGRATIONS[number]))
    throw Error('1BE unknown applied schema: '+applied);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==checksum)throw Error('1BE SQL checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{
   if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  }finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BE migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
