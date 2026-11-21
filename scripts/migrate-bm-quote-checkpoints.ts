import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';
import {bmQuoteCheckpointWriteTarget} from '../server/commercialIntegrity/quoteCheckpointCustody';

async function main(){
 bmQuoteCheckpointWriteTarget(process.env);
 const id='0036_bm_quote_candidate_checkpoints';
 if(MIGRATIONS[35]!==id||MIGRATIONS.length<36)
  throw Error('Phase 1BM migration registry mismatch');
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)
  throw Error('Phase 1BM complete isolated database configuration required');
 const conn=await mysql.createConnection(cfg);
 let locked=false;
 try{
  const [locks]=await conn.query<any[]>(
   "SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(locks[0]?.acquired)!==1)throw Error('Phase 1BM migration mutex unavailable');
  locked=true;
  const [rows]=await conn.query<any[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(r=>[String(r.id),String(r.checksum)]));
  for(const prior of MIGRATIONS.slice(0,35)){
   const checksum=createHash('sha256').update(
    readFileSync('database/migrations/'+prior+'.sql')).digest('hex');
   if(applied.get(prior)!==checksum)throw Error('Phase 1BM modified/missing predecessor '+prior);
  }
  for(const existing of applied.keys())
   if(!MIGRATIONS.includes(existing as typeof MIGRATIONS[number]))
    throw Error('Phase 1BM unexpected migration '+existing);
  const sql=readFileSync('database/migrations/'+id+'.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==checksum)throw Error('Phase 1BM migration checksum drift');
   console.log('Already applied:',id);return;
  }
  for(const part of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))
   await conn.query(part);
  await conn.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{
  try{if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}
  finally{await conn.end();}
 }
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('Phase 1BM migration blocked:',
  e instanceof Error?e.message:'Unknown');process.exitCode=1;});
