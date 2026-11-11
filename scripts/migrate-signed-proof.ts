import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';
export function signedProofMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.SIGNED_PROOF_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
  /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
  env.NODE_ENV!=='production')return 'staging';
 throw Error('Signed proof migration restricted to disposable CI or explicitly approved isolated TLS staging');
}
async function main(){
 signedProofMigrationTarget(process.env);
 if(MIGRATIONS[MIGRATIONS.length-1]!=='0021_signed_proof_prerequisites')
  throw Error('Signed proof prerequisite schema must be final registered migration');
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
  for(const id of MIGRATIONS.slice(0,-1)){
   const hash=createHash('sha256').update(readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==hash)throw Error('Missing/mismatched prerequisite migration: '+id);
  }
  for(const id of actual.keys())if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
   throw Error('Unknown migration: '+id);
  const id='0021_signed_proof_prerequisites',sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const hash=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==hash)throw Error('Signed proof migration checksum drift');
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
 main().catch(e=>{console.error('Signed proof migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
