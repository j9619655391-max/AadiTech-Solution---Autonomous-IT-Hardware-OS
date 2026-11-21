import 'dotenv/config';
import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {getPool} from '../server/db';
import {hashToken} from '../server/auth/crypto';
import {rateWindowBucket} from '../server/auth/limiter';
import {runRetention} from '../scripts/lib/authRetention';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Retention integration restricted to disposable CI database');
const db=getPool();if(!db)throw Error('MySQL unavailable');
after(async()=>{await db.end();});
const env={...process.env,RETENTION_APPLY:'YES_DELETE_TEST_ONLY'};

test('dry run preserves records; explicit retention deletes expired only and keeps audit',async()=>{
 const id=randomUUID(),expired=randomBytes(32).toString('base64url'),
  active=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 const eventId=randomUUID(),oldKey=randomBytes(32).toString('hex'),newKey=randomBytes(32).toString('hex');
 await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role,status) VALUES (?,?,?,?,?,?)',
  [id,'retention-'+id.slice(0,8)+'@example.invalid','Retention Fixture','test-only','OWNER','ACTIVE']);
 await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 2 DAY))',
  [hashToken(expired),id,csrf]);
 await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 2 HOUR))',
  [hashToken(active),id,csrf]);
 await db.execute('INSERT INTO auth_step_up_sessions (session_token_hash,step_up_token_hash,expires_at) VALUES (?,?,DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(active),hashToken(expired)]);
 await db.execute('INSERT INTO auth_mfa_challenges (token_hash,user_id,expires_at) VALUES (?,?,DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(expired),id]);
 const now=Date.now();
 await db.execute('INSERT INTO auth_login_rate_buckets (key_hash,window_bucket,attempt_count) VALUES (?,?,?)',
  [oldKey,rateWindowBucket(now-10*86400000),3]);
 await db.execute('INSERT INTO auth_login_rate_buckets (key_hash,window_bucket,attempt_count) VALUES (?,?,?)',
  [newKey,rateWindowBucket(now),1]);
 await db.execute('INSERT INTO auth_security_events (id,actor_user_id,target_user_id,event_type) VALUES (?,?,?,?)',
  [eventId,id,id,'MFA_LOGIN_FAILED']);
 const dry=await runRetention(db,env,false);
 assert.equal(dry.mode,'dry-run');
 assert.ok(dry.counts.auth_sessions>=1);
 assert.equal(dry.deleted.auth_sessions,0);
 assert.ok(dry.protectedTables.includes('auth_security_events'));
 let [stillThere]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_sessions WHERE token_hash=?',[hashToken(expired)]);
 assert.equal(Number(stillThere[0].n),1);
 const applied=await runRetention(db,env,true);
 assert.equal(applied.mode,'apply');
 assert.ok(applied.deleted.auth_sessions>=1);
 assert.ok(applied.deleted.auth_step_up_sessions>=1);
 assert.ok(applied.deleted.auth_mfa_challenges>=1);
 assert.ok(applied.deleted.auth_login_rate_buckets>=1);
 const [sessionRows]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT token_hash FROM auth_sessions WHERE user_id=?',[id]);
 assert.deepEqual(sessionRows.map(v=>String(v.token_hash)),[hashToken(active)]);
 const [steps]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_step_up_sessions WHERE session_token_hash=?',[hashToken(active)]);
 assert.equal(Number(steps[0].n),0);
 const [tokens]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_mfa_challenges WHERE user_id=?',[id]);
 assert.equal(Number(tokens[0].n),0);
 const [old]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_login_rate_buckets WHERE key_hash=?',[oldKey]);
 assert.equal(Number(old[0].n),0);
 const [recent]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_login_rate_buckets WHERE key_hash=?',[newKey]);
 assert.equal(Number(recent[0].n),1);
 const [events]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_security_events WHERE id=?',[eventId]);
 assert.equal(Number(events[0].n),1);
 const repeated=await runRetention(db,env,true);
 assert.equal(Object.values(repeated.deleted).reduce((a,b)=>a+b,0),0);
});
