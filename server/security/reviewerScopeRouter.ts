import {randomUUID} from 'node:crypto';
import {Router} from 'express';
import type {RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';

// First-party workflow nominations only. These do not establish corporate,
// eMudhra, CCA or independent Security approval and confer no customer dispatch.
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const validId=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
type Scope='QUOTES'|'PROCUREMENT'|'INTAKE'|'DISPATCH'|'EVIDENCE'|'STOCK'|'JOURNAL'|'PROOF'|'KEY_LIFECYCLE'|'EXTERNAL_TRUST'|'PROVIDER_BRIDGE'|'PROVIDER_SANDBOX'|'PROVIDER_SELECTION'|'PROVIDER_ONBOARDING';
type Decision='GRANT'|'REVOKE';
router.get('/',async(_req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.execute<RowDataPacket[]>(`SELECT reviewer_user_id AS reviewerId,
   workflow_scope AS scope,state,nominated_at AS nominatedAt
   FROM app_reviewer_scope_grants WHERE owner_user_id=?
   ORDER BY workflow_scope,reviewer_user_id LIMIT 200`,
   [res.locals.auth.userId]);
  res.json({items:rows,internalWorkflowNominationsOnly:true,
   externallyAuthenticatedReviewer:false,productionReleaseAuthorized:false});
 }catch{
  res.status(503).json({error:'Reviewer scope service unavailable'});
 }
});
router.post('/',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 const body=req.body;
 if(!body||typeof body!=='object'||Array.isArray(body)||
    Object.keys(body).sort().join(',')!=='decision,reason,reviewerId,scope' ||
    typeof body.reviewerId!=='string'||!validId.test(body.reviewerId)||
    !['QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL','PROOF','KEY_LIFECYCLE','EXTERNAL_TRUST','PROVIDER_BRIDGE','PROVIDER_SANDBOX','PROVIDER_SELECTION','PROVIDER_ONBOARDING'].includes(body.scope)||
    !['GRANT','REVOKE'].includes(body.decision)||
    typeof body.reason!=='string'||body.reason.trim().length<16||
    body.reason.trim().length>500){
  res.status(400).json({error:'Exact reviewerId, QUOTES/PROCUREMENT/INTAKE/DISPATCH/EVIDENCE/STOCK/JOURNAL/PROOF/KEY_LIFECYCLE/EXTERNAL_TRUST/PROVIDER_BRIDGE/PROVIDER_SANDBOX/PROVIDER_SELECTION/PROVIDER_ONBOARDING scope, GRANT/REVOKE and 16-500 character reason required'});return;
 }
 const reviewerId=body.reviewerId as string,scope=body.scope as Scope,
  decision=body.decision as Decision,reason=body.reason.trim() as string,
  owner=String(res.locals.auth.userId);
 if(reviewerId===owner){res.status(400).json({error:'Owner cannot be own independent reviewer'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  // Session authorization is checked before entering this transaction. Recheck
  // and lock the nominating OWNER here so concurrent demotion/disable cannot
  // race a new nomination or revocation audit event.
  const [sourceOwners]=await conn.query<RowDataPacket[]>(
   'SELECT id,role,status FROM auth_users WHERE id=? FOR UPDATE',[owner]);
  if(sourceOwners.length!==1||sourceOwners[0].role!=='OWNER'||
     sourceOwners[0].status!=='ACTIVE'){
   await conn.rollback();res.status(403).json({error:'Active OWNER account required for reviewer scope changes'});return;
  }
  const [users]=await conn.query<RowDataPacket[]>(
   'SELECT id,role,status FROM auth_users WHERE id=? FOR UPDATE',[reviewerId]);
  if(!users.length||users[0].role!=='REVIEWER'||
      (decision==='GRANT'&&users[0].status!=='ACTIVE')){
   await conn.rollback();res.status(400).json({error:'Active REVIEWER account required for a grant'});return;
  }
  const [rows]=await conn.query<RowDataPacket[]>(
   `SELECT state FROM app_reviewer_scope_grants
    WHERE owner_user_id=? AND reviewer_user_id=? AND workflow_scope=? FOR UPDATE`,
   [owner,reviewerId,scope]);
  const prior=rows[0]?.state??null;
  if((decision==='GRANT'&&prior==='ACTIVE')||
     (decision==='REVOKE'&&prior!=='ACTIVE')){
   await conn.rollback();res.status(409).json({error:'Reviewer scope transition conflict'});return;
  }
  if(decision==='GRANT'){
   if(prior==='REVOKED')
    await conn.execute(`UPDATE app_reviewer_scope_grants SET state='ACTIVE',
      nominated_at=UTC_TIMESTAMP(3) WHERE owner_user_id=? AND reviewer_user_id=?
      AND workflow_scope=? AND state='REVOKED'`,[owner,reviewerId,scope]);
   else
    await conn.execute(`INSERT INTO app_reviewer_scope_grants
      (owner_user_id,reviewer_user_id,workflow_scope) VALUES (?,?,?)`,
      [owner,reviewerId,scope]);
  }else{
   await conn.execute(`UPDATE app_reviewer_scope_grants SET state='REVOKED'
     WHERE owner_user_id=? AND reviewer_user_id=? AND workflow_scope=?
     AND state='ACTIVE'`,[owner,reviewerId,scope]);
  }
  await conn.execute(`INSERT INTO app_reviewer_scope_events
   (id,owner_user_id,reviewer_user_id,workflow_scope,decision,reason)
   VALUES (?,?,?,?,?,?)`,[randomUUID(),owner,reviewerId,scope,decision,reason]);
  await conn.commit();
  res.status(201).json({reviewerId,scope,state:decision==='GRANT'?'ACTIVE':'REVOKED',
   internalNominationOnly:true,independentAuthorityAuthenticated:false,
   externalActionEnabled:false,productionReleaseAuthorized:false,releaseDecision:'HOLD'});
 }catch(e){
  await conn.rollback().catch(()=>{});
  if(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY'){
   res.status(409).json({error:'Reviewer scope transition conflict'});return;
  }
  res.status(503).json({error:'Reviewer scope service unavailable'});
 }finally{conn.release();}
});
export default router;
