import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';

async function main(){
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('Database configuration required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try{
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const ids=['0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency','0005_quote_revisions','0006_quote_reviews','0007_quote_release_holds','0008_reviewer_roles','0009_auth_security_events'];
  const [deps]=await db.query<any[]>('SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('+ids.map(()=>'?').join(',')+')',ids);
  if(Number(deps[0].n)!==9)throw Error('Apply migrations 0001–0009 first');
  const id='0010_auth_login_security',sql=readFileSync('database/migrations/0010_auth_login_security.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  const [seen]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
  if(seen.length){if(seen[0].checksum!==checksum)throw Error('Applied migration checksum changed');console.log('Already applied',id);return;}
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))await db.query(statement);
  await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
main().catch(err=>{console.error('Migration failed:',err instanceof Error?err.message:'Unknown');process.exitCode=1;});
