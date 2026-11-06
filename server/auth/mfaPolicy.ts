import type {Request,Response,NextFunction} from 'express';
import {randomUUID} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import type {Session} from './router';

export function privilegedMfaRequired():boolean {
 const raw=process.env.MFA_REQUIRE_PRIVILEGED;
 if(raw===undefined || raw==='false')return false;
 if(raw==='true')return true;
 throw Error('MFA_REQUIRE_PRIVILEGED must be true or false');
}
export async function recordMfaEvent(
 db:Pool|PoolConnection,
 userId:string,
 eventType:'MFA_ENROLLED'|'MFA_LOGIN_SUCCEEDED'|'MFA_LOGIN_FAILED'|'MFA_RECOVERY_USED'|'MFA_POLICY_DENIED'
):Promise<void> {
 await db.execute(
  'INSERT INTO auth_security_events (id,actor_user_id,target_user_id,event_type,revoked_session_count) VALUES (?,?,?,?,0)',
  [randomUUID(),userId,userId,eventType]);
}
export async function requirePrivilegedMfa(req:Request,res:Response,next:NextFunction):Promise<void>{
 let required:boolean;
 try{required=privilegedMfaRequired();}
 catch{res.status(503).json({error:'MFA policy configuration invalid'});return;}
 if(!required){next();return;}
 const session=res.locals.auth as Session|undefined;
 if(!session){res.status(401).json({error:'Authentication required'});return;}
 const db=getPool();
 if(!db){res.status(503).json({error:'MFA policy unavailable'});return;}
 try{
  const [rows]=await db.execute<RowDataPacket[]>(
   'SELECT enabled_at FROM auth_totp_credentials WHERE user_id=? LIMIT 1',[session.userId]);
  if(!rows[0]?.enabled_at || !session.mfaVerifiedAt){
   await recordMfaEvent(db,session.userId,'MFA_POLICY_DENIED');
   res.status(403).json({error:'MFA-verified session required for privileged action'});return;
  }
  next();
 }catch{
  res.status(503).json({error:'MFA policy verification unavailable'});
 }
}
