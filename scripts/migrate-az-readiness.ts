import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function azMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.AZ_READINESS_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&env.DB_SSL==='true'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
    env.NODE_ENV!=='production')return 'staging';
 throw Error('1AZ migration accepts only disposable CI or approved isolated TLS staging');
}
async function main(){
 azMigrationTarget(process.env);
 const id='0029_az_external_readiness_holds';
 if(MIGRATIONS[28]!==id||MIGRATIONS.length<29)
  throw Error('1AZ expected registered final migration 0029');
 const config=getDatabaseConfig();
 if(!config.host||!config.user||!config.password||!config.database)
  throw Error('1AZ migration requires full DB configuration');
 const conn=await mysql.createConnection(config);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('1AZ migration lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
  for(const item of MIGRATIONS.slice(0,28)){
   const sum=createHash('sha256').update(readFileSync('database/migrations/'+item+'.sql')).digest('hex');
   if(applied.get(item)!==sum)throw Error('1AZ missing or changed prerequisite migration '+item);
  }
  for(const found of applied.keys())if(!MIGRATIONS.includes(found as typeof MIGRATIONS[number]))
   throw Error('1AZ unknown migration '+found);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const sum=createHash('sha256').update(sql).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==sum)throw Error('1AZ checksum mismatch');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,sum]);
  console.log('Applied:',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(err=>{console.error('1AZ migration refused:',err instanceof Error?err.message:'Unknown');process.exitCode=1;});
