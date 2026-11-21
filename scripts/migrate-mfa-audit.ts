import 'dotenv/config';
import mysql from 'mysql2/promise';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';

async function main(){
 const config=getDatabaseConfig();
 if(!config.host||!config.user||!config.password||!config.database)throw Error('Database configuration required');
 const db=await mysql.createConnection(config);let locked=false;
 try {
  const [locks]=await db.query<any[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(locks[0]?.acquired!==1)throw Error('Migration lock unavailable');
  locked=true;
  const ids=['0001_auth','0002_crm','0003_quote_drafts','0004_quote_idempotency','0005_quote_revisions','0006_quote_reviews','0007_quote_release_holds','0008_reviewer_roles','0009_auth_security_events','0010_auth_login_security','0011_totp_mfa'];
  const [deps]=await db.execute<any[]>('SELECT COUNT(*) AS n FROM schema_migrations WHERE id IN ('+ids.map(()=>'?').join(',')+')',ids);
  if(Number(deps[0].n)!==11)throw Error('Apply migrations 0001–0011 first');
  const id='0012_mfa_audit_events',sql=readFileSync('database/migrations/0012_mfa_audit_events.sql','utf8');
  const checksum=createHash('sha256').update(sql).digest('hex');
  const [existing]=await db.execute<any[]>('SELECT checksum FROM schema_migrations WHERE id=?',[id]);
  if(existing.length){
   if(existing[0].checksum!==checksum)throw Error('Applied migration checksum differs');
   console.log('Already applied',id);return;
  }
  for(const statement of sql.replace(/^\s*--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean))await db.query(statement);
  await db.execute('INSERT INTO schema_migrations (id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied',id);
 }finally{
  if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");
  await db.end();
 }
}
main().catch(e=>{console.error('MFA audit migration failed',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
