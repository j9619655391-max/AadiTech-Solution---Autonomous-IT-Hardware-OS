import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

// Strictly disposable; no production migration, destructive changes, or auto-grants.
export function epReviewerScopeMigrationTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.EP_REVIEW_SCOPE_MIGRATION_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
    env.DB_SSL==='true'&&env.NODE_ENV!=='production')return 'staging';
 throw Error('1EP reviewer-scope migration denied outside disposable CI or approved isolated TLS staging');
}
async function main(){
 epReviewerScopeMigrationTarget(process.env);
 const id='0046_ep_proof_key_trust_review_scopes';
 if(MIGRATIONS[45]!==id)
  throw Error('1EP exact schema-migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('1EP DB config incomplete');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)throw Error('1EP migration mutex unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(row=>[String(row.id),String(row.checksum)]));
  for(const old of MIGRATIONS.slice(0,45)){
   const expected=createHash('sha256').update(readFileSync('database/migrations/'+old+'.sql')).digest('hex');
   if(applied.get(old)!==expected)throw Error('1EP missing/mismatched predecessor '+old);
  }
  for(const old of applied.keys())
   if(!MIGRATIONS.includes(old as typeof MIGRATIONS[number]))
    throw Error('1EP unexpected historical schema '+old);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==checksum)throw Error('1EP checksum drift');
   console.log('Already applied:',id);return;
  }
  // ALTER TABLE in MySQL commits separately. Repeating the same additive
  // enum extension is intentionally idempotent after a partial interruption.
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(statement);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1EP migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
