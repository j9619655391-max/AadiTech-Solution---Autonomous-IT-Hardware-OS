import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function dispatchMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.DISPATCH_HOLDS_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
  /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
  env.NODE_ENV!=='production')return 'staging';
 throw Error('Supplier dispatch holds migration restricted to disposable CI or approved TLS isolated staging');
}
async function main(){
 dispatchMigrationTarget(process.env);
 if(MIGRATIONS[MIGRATIONS.length-1]!=='0017_supplier_dispatch_holds')
  throw Error('Dispatch holds migration must be last registered schema');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Complete database configuration required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try{
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const [rows]=await db.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const id of MIGRATIONS.slice(0,-1)){
   const checksum=createHash('sha256').update(
    readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==checksum)throw Error('Missing/altered prerequisite migration: '+id);
  }
  for(const id of actual.keys())if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
   throw Error('Unknown schema migration: '+id);
  const id='0017_supplier_dispatch_holds',file='database/migrations/'+id+'.sql';
  const sql=readFileSync(file,'utf8'),hash=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==hash)throw Error('Supplier dispatch holds checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(v=>v.trim()).filter(Boolean))
   await db.query(statement);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,hash]);
  console.log('Applied:',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Supplier dispatch holds migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
