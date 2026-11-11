import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function intakeMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')
  return 'ci';
 if(env.INTAKE_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
    env.NODE_ENV!=='production')return 'staging';
 throw Error('Inbound quarantine migration restricted to disposable CI or explicitly approved isolated TLS staging');
}
async function main(){
 intakeMigrationTarget(process.env);
 if(MIGRATIONS[MIGRATIONS.length-1]!=='0016_quarantine_intake')
  throw Error('Inbound quarantine migration must be final registered schema');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Complete database configuration required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try{
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const ids=MIGRATIONS.slice(0,-1);
  const [rows]=await db.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
  for(const id of ids){
   const expected=createHash('sha256').update(readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==expected)throw Error('Missing or modified prerequisite checksum: '+id);
  }
  for(const id of actual.keys())if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
   throw Error('Unregistered migration present: '+id);
  const id='0016_quarantine_intake',file='database/migrations/'+id+'.sql';
  const sql=readFileSync(file,'utf8'),checksum=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==checksum)throw Error('Inbound quarantine migration checksum drift');
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
 main().catch(e=>{console.error('Inbound migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
