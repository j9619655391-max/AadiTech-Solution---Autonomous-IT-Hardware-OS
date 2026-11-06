import {Router} from 'express';
import type {RowDataPacket,ResultSetHeader} from 'mysql2/promise';
import {getPool} from '../db';
import {requireAuthenticated,requireStepUp} from './router';
import {hashToken,newSecret} from './crypto';
import {generateTotpSecret,encryptSecret,decryptSecret,matchTotp,newRecoveryCodes} from './totp';

const router=Router();
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const COOKIE='aaditech_session';
const cookieOptions={httpOnly:true,path:'/api',sameSite:'lax' as const,secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000};
const originValid=(req:import('express').Request)=>{
 const origin=req.header('origin');if(!origin)return true;
 const allowed=process.env.APP_URL;
 if(!allowed)return process.env.NODE_ENV!=='production';
 try{return new URL(origin).origin===new URL(allowed).origin;}catch{return false;}
};
function error(res:import('express').Response,e:unknown){
 console.error('MFA operation failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'MFA service unavailable'});
}
router.get('/status',requireAuthenticated,async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.execute<RowDataPacket[]>('SELECT enabled_at FROM auth_totp_credentials WHERE user_id=?',[res.locals.auth.userId]);
  res.json({enabled:!!rows[0]?.enabled_at});
 }catch(e){error(res,e);}
});
router.post('/enroll/start',requireAuthenticated,requireStepUp,async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const secret=generateTotpSecret(),cipher=encryptSecret(secret);
  const conn=await db.getConnection();
  try{
   await conn.beginTransaction();
   const [rows]=await conn.query<RowDataPacket[]>('SELECT enabled_at FROM auth_totp_credentials WHERE user_id=? FOR UPDATE',[res.locals.auth.userId]);
   if(rows[0]?.enabled_at){await conn.rollback();res.status(409).json({error:'MFA already enabled'});return;}
   await conn.execute('INSERT INTO auth_totp_credentials (user_id,secret_encrypted,enrollment_expires_at) VALUES (?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 10 MINUTE)) ON DUPLICATE KEY UPDATE secret_encrypted=VALUES(secret_encrypted),enrollment_expires_at=VALUES(enrollment_expires_at),last_counter=-1',
     [res.locals.auth.userId,cipher]);
   await conn.commit();
  }catch(e){await conn.rollback();throw e;}finally{conn.release();}
  const label='AadiTech:'+res.locals.auth.email;
  const uri='otpauth://totp/'+encodeURIComponent(label)+'?secret='+secret+'&issuer='+encodeURIComponent('AadiTech Solution')+'&algorithm=SHA1&digits=6&period=30';
  res.json({secret,otpauthUri:uri,expiresInSeconds:600,
   message:'Record the secret in your authenticator. Enable only after the first code verifies.'});
 }catch(e){error(res,e);}
});
router.post('/enroll/activate',requireAuthenticated,requireStepUp,async(req,res)=>{
 const code=req.body?.code;
 if(!req.body||Object.keys(req.body).join(',')!=='code'||typeof code!=='string'||!/^\d{6}$/.test(code)){
  res.status(400).json({error:'A six-digit authenticator code is required'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const [rows]=await conn.query<RowDataPacket[]>('SELECT secret_encrypted,enabled_at FROM auth_totp_credentials WHERE user_id=? FOR UPDATE',[res.locals.auth.userId]);
  if(!rows.length||rows[0].enabled_at){await conn.rollback();res.status(409).json({error:'No pending MFA enrollment'});return;}
  const [expires]=await conn.query<RowDataPacket[]>('SELECT enrollment_expires_at>UTC_TIMESTAMP(3) AS valid FROM auth_totp_credentials WHERE user_id=?',[res.locals.auth.userId]);
  if(!expires[0]?.valid){await conn.rollback();res.status(410).json({error:'MFA enrollment expired'});return;}
  const matched=matchTotp(decryptSecret(String(rows[0].secret_encrypted)),code);
  if(matched===null){await conn.rollback();res.status(401).json({error:'Incorrect authenticator code'});return;}
  const codes=newRecoveryCodes();
  await conn.execute('UPDATE auth_totp_credentials SET enabled_at=UTC_TIMESTAMP(3),enrollment_expires_at=NULL,last_counter=? WHERE user_id=?',[matched,res.locals.auth.userId]);
  await conn.execute('DELETE FROM auth_totp_recovery_codes WHERE user_id=?',[res.locals.auth.userId]);
  for(const recovery of codes)await conn.execute('INSERT INTO auth_totp_recovery_codes (user_id,code_hash) VALUES (?,?)',
    [res.locals.auth.userId,hashToken(res.locals.auth.userId+':'+recovery)]);
  await conn.execute('DELETE FROM auth_sessions WHERE user_id=?',[res.locals.auth.userId]);
  await conn.commit();
  res.clearCookie(COOKIE,{path:'/api',httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production'});
  res.json({enabled:true,recoveryCodes:codes,signInRequired:true,
   message:'MFA enabled. Store recovery codes securely now; they cannot be displayed again. Sign in again.'});
 }catch(e){await conn.rollback();error(res,e);}finally{conn.release();}
});
router.post('/challenge/verify',async(req,res)=>{
 if(!originValid(req)){res.status(403).json({error:'Invalid request origin'});return;}
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||
   Object.keys(body).some(k=>!['challengeToken','code'].includes(k))||
   Object.keys(body).length!==2||
   typeof body.challengeToken!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(body.challengeToken)||
   typeof body.code!=='string'||!(/^\d{6}$/.test(body.code)||/^[A-F0-9]{20}$/i.test(body.code))){
  res.status(400).json({error:'MFA challenge and code required'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'MFA service unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const [challenges]=await conn.query<RowDataPacket[]>('SELECT user_id,attempts,expires_at>UTC_TIMESTAMP(3) AS valid FROM auth_mfa_challenges WHERE token_hash=? FOR UPDATE',[hashToken(body.challengeToken)]);
  const challenge=challenges[0];
  if(!challenge||!challenge.valid||challenge.attempts>=5){
   await conn.rollback();res.status(401).json({error:'MFA challenge expired or unavailable'});return;
  }
  const userId=String(challenge.user_id);
  const [credentials]=await conn.query<RowDataPacket[]>('SELECT c.secret_encrypted,c.last_counter,u.email,u.role FROM auth_totp_credentials c JOIN auth_users u ON u.id=c.user_id WHERE c.user_id=? AND c.enabled_at IS NOT NULL AND u.status=? FOR UPDATE',[userId,'ACTIVE']);
  if(!credentials.length){await conn.rollback();res.status(401).json({error:'MFA challenge unavailable'});return;}
  const user=credentials[0],given=String(body.code).toUpperCase();
  let good=false;
  if(/^\d{6}$/.test(given)){
   const counter=matchTotp(decryptSecret(String(user.secret_encrypted)),given,Number(user.last_counter));
   if(counter!==null){await conn.execute('UPDATE auth_totp_credentials SET last_counter=? WHERE user_id=?',[counter,userId]);good=true;}
  }else{
   const [recovered]=await conn.execute<ResultSetHeader>('UPDATE auth_totp_recovery_codes SET used_at=UTC_TIMESTAMP(3) WHERE user_id=? AND code_hash=? AND used_at IS NULL',[userId,hashToken(userId+':'+given)]);
   good=recovered.affectedRows===1;
  }
  if(!good){
   await conn.execute('UPDATE auth_mfa_challenges SET attempts=attempts+1 WHERE token_hash=?',[hashToken(body.challengeToken)]);
   await conn.commit();
   res.status(401).json({error:'Invalid MFA code'});return;
  }
  const token=newSecret(),csrf=newSecret();
  await conn.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 8 HOUR))',[hashToken(token),userId,csrf]);
  await conn.execute('DELETE FROM auth_mfa_challenges WHERE user_id=?',[userId]);
  await conn.commit();
  res.cookie(COOKIE,token,cookieOptions);
  res.json({user:{id:userId,email:user.email,role:user.role},csrfToken:csrf});
 }catch(e){await conn.rollback();error(res,e);}finally{conn.release();}
});
export default router;
