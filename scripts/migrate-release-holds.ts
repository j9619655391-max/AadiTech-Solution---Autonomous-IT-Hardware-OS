import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { getDatabaseConfig } from '../server/db';

async function main(){
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('Database configuration required');
 const conn=await mysql.createConnection(cfg);let locked=false;
 try{
  const [locks]=await conn.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const [deps]=await conn.query<any[]>("SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency','0005_quote_revisions','0006_quote_reviews')");
  if(Number(deps[0].n)!==6)throw Error('Apply migrations 0001–0006 first');
  const id='0007_quote_release_holds',file='database/migrations/0007_quote_release_holds.sql';
  const sql=readFileSync(file,'utf8'),checksum=createHash('sha256').update(sql).digest('hex');
  const [seen]=await conn.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
  if(seen.length){if(seen[0].checksum!==checksum)throw Error('Applied migration checksum changed');console.log('Already applied',id);return;}
  for(const part of sql.replace(/^\s*--.*$/gm,'').split(';').map(v=>v.trim()).filter(Boolean))await conn.query(part);
  await conn.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied',id);
 }finally{
  if(locked)await conn.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await conn.end();
 }
}
main().catch(e=>{console.error('Migration failed:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
