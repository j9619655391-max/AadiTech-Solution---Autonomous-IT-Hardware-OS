import 'dotenv/config';
import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken} from '../server/auth/crypto';
import {totpAt,encryptSecret,generateTotpSecret} from '../server/auth/totp';
import authRouter from '../server/auth/router';
import mfaRouter from '../server/auth/mfaRouter';
import crmRouter from '../server/crm/router';
import quoteDraftRouter from '../server/quotes/router';
import reviewRouter from '../server/quotes/reviewRouter';
import releaseRouter from '../server/quotes/releaseHoldRouter';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Smoke suite requires disposable CI database only');
const db=getPool();
if(!db)throw Error('MySQL unavailable');
let stop:()=>Promise<void>;
after(async()=>{if(stop)await stop();await db.end();});

test('HTTP auth smoke: password -> TOTP -> MFA session -> owner only -> logout',async()=>{
 const userId=randomUUID(),email='smoke-'+userId.slice(0,8)+'@example.invalid';
 const password='CI-MFA-Smoke-Password-2026',secret=generateTotpSecret();
 await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role,status) VALUES (?,?,?,?,?,?)',
  [userId,email,'Smoke Owner',await hashPassword(password),'OWNER','ACTIVE']);
 await db.execute('INSERT INTO auth_totp_credentials (user_id,secret_encrypted,enabled_at) VALUES (?,?,UTC_TIMESTAMP(3))',
  [userId,encryptSecret(secret)]);
 const app=express();
 app.use(express.json({limit:'256kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/auth/mfa',mfaRouter);
 app.use('/api/crm',crmRouter);
 app.use('/api/quotes/drafts',quoteDraftRouter);
 app.use('/api/quotes/reviews',reviewRouter);
 app.use('/api/quotes/release-preparations',releaseRouter);
 const server=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>server.once('listening',resolve));
 stop=()=>new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
 const addr=server.address();assert.ok(addr&&typeof addr!=='string');
 const base='http://127.0.0.1:'+addr.port;
 const request=async(path:string,options:RequestInit={})=>{
  const response=await fetch(base+path,{...options,redirect:'manual'});
  const raw=await response.text();
  const data=raw?JSON.parse(raw):null;
  return {response,data};
 };
 const without=await request('/api/crm/customers');
 assert.equal(without.response.status,401);
 const bad=await request('/api/auth/login',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email,password:'not-the-password'})
 });
 assert.equal(bad.response.status,401);
 const login=await request('/api/auth/login',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({email,password})
 });
 assert.equal(login.response.status,202);
 assert.equal(login.data.mfaRequired,true);
 assert.equal(login.response.headers.get('set-cookie'),null);
 assert.ok(!('csrfToken' in login.data));
 const token=login.data.challengeToken as string;
 const incorrect=await request('/api/auth/mfa/challenge/verify',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({challengeToken:token,code:'000000'})
 });
 assert.equal(incorrect.response.status,401);
 const valid=await request('/api/auth/mfa/challenge/verify',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({challengeToken:token,code:totpAt(secret,Math.floor(Date.now()/30000))})
 });
 assert.equal(valid.response.status,200);
 const cookie=valid.response.headers.get('set-cookie')?.split(';')[0];
 assert.ok(cookie?.startsWith('aaditech_session='));
 assert.match(valid.response.headers.get('set-cookie')??'',/HttpOnly/i);
 assert.match(valid.response.headers.get('set-cookie')??'',/SameSite=Lax/i);
 const me=await request('/api/auth/me',{headers:{cookie:cookie!}});
 assert.equal(me.response.status,200);
 assert.equal(me.data.user.id,userId);
 const read=await request('/api/crm/customers',{headers:{cookie:cookie!}});
 assert.equal(read.response.status,200);
 const forbidden=await request('/api/quotes/reviews/queue',{headers:{cookie:cookie!}});
 assert.equal(forbidden.response.status,403);
 const noCsrf=await request('/api/auth/logout',{method:'POST',headers:{cookie:cookie!}});
 assert.equal(noCsrf.response.status,403);
 const logout=await request('/api/auth/logout',{method:'POST',
  headers:{cookie:cookie!,'x-csrf-token':valid.data.csrfToken}});
 assert.equal(logout.response.status,200);
 const expired=await request('/api/auth/me',{headers:{cookie:cookie!}});
 assert.equal(expired.response.status,401);
 const retry=await request('/api/auth/mfa/challenge/verify',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({challengeToken:token,code:totpAt(secret,Math.floor(Date.now()/30000)+1)})
 });
 assert.equal(retry.response.status,401);
 const [active]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?',[userId]);
 assert.equal(Number(active[0].n),0);
});
