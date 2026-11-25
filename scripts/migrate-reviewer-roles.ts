import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
async function main(){
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.database||!cfg.user||!cfg.password)throw Error('Database configuration required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try {
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const [deps]=await db.query<any[]>("SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency','0005_quote_revisions','0006_quote_reviews','0007_quote_release_holds')");
  if(Number(deps[0].n)!==7)throw Error('Apply migrations 0001–0007 first');
  const id='0008_reviewer_roles',sql=readFileSync('database/migrations/0008_reviewer_roles.sql','utf8');
  const digest=createHash('sha256').update(sql).digest('hex');
  const [seen]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
  if(seen.length){if(seen[0].checksum!==digest)throw Error('Migration checksum changed');console.log('Already applied',id);return;}
  // MySQL DDL commits implicitly; rerun after any failure. Do not run in production without backup/staging rehearsal.
  const parts=sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean);
  for(const part of parts)await db.query(part);
  await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,digest]);
  console.log('Applied',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
main().catch(e=>{console.error('Migration failed',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
