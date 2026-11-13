import 'dotenv/config';
import mysql from 'mysql2/promise';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function stockFoundationMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.STOCK_FOUNDATION_MIGRATION_APPROVED==='YES'&&
  env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
  /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
  env.DB_SSL==='true'&&env.NODE_ENV!=='production')return 'staging';
 throw Error('Stock foundation migration restricted to disposable CI or approved isolated TLS staging');
}
async function main(){
 stockFoundationMigrationTarget(process.env);
 if(MIGRATIONS[18]!=='0019_stock_release_planning')
  throw Error('Stock foundation migration must be final registered schema');
 const config=getDatabaseConfig();
 if(!config.host||!config.user||!config.password||!config.database)
  throw Error('Complete DB configuration required');
 const conn=await mysql.createConnection(config);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const id of MIGRATIONS.slice(0,18)){
   const checksum=createHash('sha256').update(
    readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==checksum)throw Error('Missing/mismatched prerequisite migration: '+id);
  }
  for(const id of actual.keys())if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
   throw Error('Unknown migration: '+id);
  const id='0019_stock_release_planning',file='database/migrations/'+id+'.sql';
  const sql=readFileSync(file,'utf8'),checksum=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==checksum)throw Error('Stock foundation schema checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await conn.query(statement);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Stock foundation migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
