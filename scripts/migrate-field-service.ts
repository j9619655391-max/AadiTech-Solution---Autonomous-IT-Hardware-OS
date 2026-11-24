import 'dotenv/config';
import mysql from 'mysql2/promise';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function fieldServiceMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test'&&env.DB_SSL==='false')return 'ci';
 if(env.NODE_ENV==='staging'&&env.FIELD_SERVICE_MIGRATION_APPROVED==='YES'&&
  env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
  /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true')
  return 'staging';
 throw Error('1GA ticket schema is restricted to disposable CI or expressly approved isolated TLS staging');
}
async function main(){
 fieldServiceMigrationTarget(process.env);
 const id='0050_ga_field_service_plans_internal';
 if(MIGRATIONS[49]!==id)throw Error('1GA schema not registered as final additive migration');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('Complete SQL settings required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try{
  const [lk]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(lk[0]?.acquired!==1)throw Error('Could not acquire migration lock');
  locked=true;
  const [rows]=await db.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const previous of MIGRATIONS.slice(0,49)){
   const expected=createHash('sha256').update(readFileSync('database/migrations/'+previous+'.sql')).digest('hex');
   if(actual.get(previous)!==expected)throw Error('1GA missing/drifted previous migration: '+previous);
  }
  for(const previous of actual.keys())if(!MIGRATIONS.some(x=>x===previous))
   throw Error('1GA unknown migration: '+previous);
  const file='database/migrations/'+id+'.sql';
  const sql=readFileSync(file,'utf8'),checksum=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==checksum)throw Error('1GA migration checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await db.query(statement);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1GA migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
