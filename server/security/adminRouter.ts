import {Router} from 'express';
import {randomUUID} from 'node:crypto';
import type {ResultSetHeader,RowDataPacket} from 'mysql2/promise';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {getPool} from '../db';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function fail(res:import('express').Response,e:unknown){
 console.error('Staff security operation failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Security administration unavailable'});
}
router.get('/reviewers',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try {
  const [rows]=await db.query<RowDataPacket[]>(`SELECT u.id,u.email,u.full_name,u.status,
   (SELECT COUNT(*) FROM auth_sessions s WHERE s.user_id=u.id AND s.expires_at>UTC_TIMESTAMP(3)) AS active_sessions
   FROM auth_users u WHERE u.role='REVIEWER' ORDER BY u.created_at DESC,u.id DESC LIMIT 200`);
  res.json({items:rows});
 }catch(e){fail(res,e);}
});
router.get('/events',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const limit=req.query.limit===undefined?50:Number(req.query.limit);
 if(!Number.isSafeInteger(limit)||limit<1||limit>100){res.status(400).json({error:'Invalid limit'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>('SELECT id,actor_user_id,target_user_id,event_type,revoked_session_count,created_at FROM auth_security_events ORDER BY created_at DESC,id DESC LIMIT ?',[limit]);
  res.json({items:rows});
 }catch(e){fail(res,e);}
});
async function change(req:import('express').Request,res:import('express').Response,action:'status'|'revoke'){
 if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid reviewer ID'});return;}
 const input=req.body;
 if(action==='status'&&(!input||typeof input!=='object'||Array.isArray(input)||
   Object.keys(input).join(',')!=='status'||!['ACTIVE','DISABLED'].includes(input.status))){
  res.status(400).json({error:'Exact ACTIVE or DISABLED status required'});return;
 }
 if(action==='revoke'&&input!==undefined&&(typeof input!=='object'||Array.isArray(input)||Object.keys(input).length!==0)){
  res.status(400).json({error:'No user-selected scope permitted'});return;
 }
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const [rows]=await conn.query<RowDataPacket[]>('SELECT id,role,status,email FROM auth_users WHERE id=? FOR UPDATE',[req.params.id]);
  if(!rows.length||rows[0].role!=='REVIEWER'){
   await conn.rollback();res.status(404).json({error:'Reviewer not found'});return;
  }
  const target=rows[0];
  if(action==='status'&&target.status===input.status){
   await conn.rollback();res.status(409).json({error:'Reviewer is already in requested state'});return;
  }
  if(action==='status'){
   await conn.execute('UPDATE auth_users SET status=? WHERE id=? AND role=?',[input.status,req.params.id,'REVIEWER']);
  }
  // Every status change and explicit session-revocation operation invalidates all
  // previously issued reviewer sessions, including other devices.
  const [revoked]=await conn.execute<ResultSetHeader>('DELETE FROM auth_sessions WHERE user_id=?',[req.params.id]);
  const eventType=action==='revoke'?'SESSIONS_REVOKED':input.status==='DISABLED'?'REVIEWER_DISABLED':'REVIEWER_ENABLED';
  await conn.execute('INSERT INTO auth_security_events (id,actor_user_id,target_user_id,event_type,revoked_session_count) VALUES (?,?,?,?,?)',
   [randomUUID(),res.locals.auth.userId,req.params.id,eventType,revoked.affectedRows]);
  await conn.commit();
  res.json({reviewerId:req.params.id,status:action==='status'?input.status:target.status,revokedSessions:revoked.affectedRows,eventType});
 }catch(e){await conn.rollback();fail(res,e);}finally{conn.release();}
}
router.patch('/reviewers/:id/status',requirePrivilegedMfa,requireStepUp,(req,res)=>{void change(req,res,'status');});
router.post('/reviewers/:id/revoke-sessions',requirePrivilegedMfa,requireStepUp,(req,res)=>{void change(req,res,'revoke');});
export default router;
