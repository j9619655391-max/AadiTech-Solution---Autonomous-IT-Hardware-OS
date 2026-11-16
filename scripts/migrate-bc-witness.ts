import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function bcMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
   env.BC_WITNESS_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
   /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))return 'staging';
 throw Error('Phase 1BC migration only permits disposable CI or approved isolated TLS staging');
}
async function main(){
 bcMigrationTarget(process.env);
 const id='0031_bc_witness_continuity_holds';
 if(MIGRATIONS.at(-1)!==id||MIGRATIONS.length!==31)
  throw Error('Phase 1BC migration registry must end in 0031');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Phase 1BC missing DB connection configuration');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Phase 1BC migration lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const prior of MIGRATIONS.slice(0,-1)){
   const hash=createHash('sha256').update(readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(actual.get(prior)!==hash)throw Error('Phase 1BC prerequisite checksum mismatch '+prior);
  }
  for(const applied of actual.keys())
   if(!MIGRATIONS.includes(applied as typeof MIGRATIONS[number]))
    throw Error('Phase 1BC unexpected applied migration');
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==checksum)throw Error('Phase 1BC migration checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BC migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
