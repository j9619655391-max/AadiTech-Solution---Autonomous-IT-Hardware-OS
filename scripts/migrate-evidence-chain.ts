import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function evidenceChainMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')
  return 'ci';
 if(env.EVIDENCE_CHAIN_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
    env.NODE_ENV!=='production')return 'staging';
 throw Error('Evidence-chain migration restricted to disposable CI or explicitly approved isolated TLS staging');
}
async function main(){
 evidenceChainMigrationTarget(process.env);
 if(MIGRATIONS[17]!=='0018_acknowledgment_grn_holds')
  throw Error('Evidence chain migration must be final registered schema');
 const config=getDatabaseConfig();
 if(!config.host||!config.user||!config.password||!config.database)
  throw Error('Complete database configuration required');
 const db=await mysql.createConnection(config);let locked=false;
 try{
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const [rows]=await db.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const id of MIGRATIONS.slice(0,17)){
   const hash=createHash('sha256').update(readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==hash)throw Error('Missing/modified prerequisite migration: '+id);
  }
  for(const id of actual.keys())
   if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
    throw Error('Unregistered migration present: '+id);
  const id='0018_acknowledgment_grn_holds';
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const hash=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==hash)throw Error('Evidence-chain migration checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await db.query(statement);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,hash]);
  console.log('Applied:',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Evidence-chain migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
