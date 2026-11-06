import 'dotenv/config';
import mysql from 'mysql2/promise';
import {randomUUID} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {hashPassword} from '../server/auth/crypto';
async function main(){
 const email=(process.env.AADITECH_REVIEWER_EMAIL||'').trim().toLowerCase();
 const name=(process.env.AADITECH_REVIEWER_NAME||'').trim();
 const secret=process.env.AADITECH_REVIEWER_PASSWORD||'';
 const ownerEmail=(process.env.AADITECH_PROVISIONING_OWNER_EMAIL||'').trim().toLowerCase();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||name.length<2||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail)||ownerEmail===email)
   throw Error('Set distinct valid reviewer email/name and existing owner email');
 const hash=await hashPassword(secret);
 const cfg=getDatabaseConfig();
 if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('Database config required');
 const db=await mysql.createConnection(cfg);
 try{
  await db.beginTransaction();
  const [owners]=await db.execute<any[]>('SELECT id FROM auth_users WHERE email=? AND role=? AND status=? FOR UPDATE',[ownerEmail,'OWNER','ACTIVE']);
  if(owners.length!==1)throw Error('An active named owner is required to provision a reviewer');
  const [existing]=await db.execute<any[]>('SELECT id FROM auth_users WHERE email=? FOR UPDATE',[email]);
  if(existing.length)throw Error('Reviewer email already exists; no overwrite allowed');
  const id=randomUUID();
  await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role,status) VALUES (?,?,?,?,?,?)',
    [id,email,name,hash,'REVIEWER','ACTIVE']);
  await db.execute('INSERT INTO auth_reviewer_provision_events (id,reviewer_user_id,provisioned_by) VALUES (?,?,?)',
    [randomUUID(),id,owners[0].id]);
  await db.commit();
  console.log('Created independent REVIEWER account:',email);
 }catch(e){await db.rollback();throw e;}finally{await db.end();}
}
main().catch(e=>{console.error('Reviewer provisioning failed',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
