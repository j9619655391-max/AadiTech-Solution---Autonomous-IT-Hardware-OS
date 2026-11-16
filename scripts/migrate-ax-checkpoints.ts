import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

export function axMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging' {
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.AX_CHECKPOINT_MIGRATION_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
    env.NODE_ENV!=='production')return 'staging';
 throw Error('Phase 1AX migration restricted to disposable CI or explicitly authorized TLS staging');
}
async function main(){
 axMigrationTarget(process.env);
 if(MIGRATIONS.at(-1)!=='0028_ax_checkpoint_governance')
  throw Error('Phase 1AX migration must be last registered migration');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Phase 1AX requires complete database configuration');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Phase 1AX migration lock unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const actual=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const id of MIGRATIONS.slice(0,-1)){
   const sha=createHash('sha256').update(readFileSync('database/migrations/'+id+'.sql')).digest('hex');
   if(actual.get(id)!==sha)throw Error('Missing/mismatched prerequisite migration: '+id);
  }
  for(const id of actual.keys())if(!MIGRATIONS.includes(id as typeof MIGRATIONS[number]))
   throw Error('Unknown migration: '+id);
  const id='0028_ax_checkpoint_governance';
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const sha=createHash('sha256').update(sql).digest('hex');
  if(actual.has(id)){
   if(actual.get(id)!==sha)throw Error('Phase 1AX checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const stmt of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(stmt);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,sha]);
  console.log('Applied:',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1AX migration refused:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
