import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function inventoryMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1' && env.DB_NAME==='aaditech_ci' && env.NODE_ENV==='test')
  return 'ci';
 if(env.INVENTORY_MIGRATION_APPROVED==='YES' &&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES' &&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'') &&
    env.DB_SSL==='true') return 'staging';
 throw Error('Inventory migration restricted to disposable CI or explicitly approved TLS isolated staging');
}
async function main(){
 inventoryMigrationTarget(process.env);
 const config=getDatabaseConfig();
 if(!config.host||!config.user||!config.password||!config.database)
  throw Error('Complete database configuration required');
 const db=await mysql.createConnection(config);
 let locked=false;
 try{
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  if(MIGRATIONS[13]!=='0014_inventory_opening_counts')
   throw Error('Inventory migration must be last in registry');
  const previous=MIGRATIONS.slice(0,13);
  const [deps]=await db.query<any[]>('SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('+
   previous.map(()=>'?').join(',')+')',previous);
  if(Number(deps[0]?.n)!==previous.length)
   throw Error('Apply all earlier checksum migrations before inventory');
  const id='0014_inventory_opening_counts',path='database/migrations/'+id+'.sql';
  const sql=readFileSync(path,'utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  const [applied]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
  if(applied.length){
   if(applied[0].checksum!==checksum)throw Error('Inventory migration checksum mismatch');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await db.query(statement);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href){
 main().catch(e=>{console.error('Inventory migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
}
