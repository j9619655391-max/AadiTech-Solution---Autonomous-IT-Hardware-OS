import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {ChainInputError,ChainConflictError,releaseDecisionInput,
 releaseHoldSnapshot} from './validation';
import {checkReleaseIntent,zeroPosition} from './integrity';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Independent held stock source or review conflicts with frozen evidence'});return;
 }
 console.error('Stock foundation independent review failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Stock release review unavailable'});
}
async function audit(c:PoolConnection,actor:string,id:string,event:'RELEASE_HELD'|'RELEASE_REJECTED',details:object){
 await c.execute(`INSERT INTO inv_stock_foundation_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256)
  VALUES (?,?,'RELEASE',?,?,?)`,
  [randomUUID(),actor,id,event,sha(JSON.stringify(details))]);
}
router.get('/release-intents',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT r.id,r.held_grn_id AS heldGrnId,
   r.observation_id AS observationId,r.prepared_by AS preparedBy,
   r.intent_sha256 AS intentSha256,r.status,r.created_at AS createdAt
   FROM inv_stock_release_intents r
   JOIN inv_grn_held_records h ON h.id=r.held_grn_id
   JOIN inv_grn_reconciliation_packs pack ON pack.id=h.pack_id
   JOIN proc_ack_claims claim ON claim.id=pack.claim_id
   JOIN proc_dispatch_preparations preparation ON preparation.id=claim.preparation_id
   JOIN proc_po_holds po ON po.id=preparation.hold_id
   JOIN proc_requests request_record ON request_record.id=po.request_id
   WHERE r.prepared_by<>? AND pack.prepared_by=r.prepared_by
     AND request_record.created_by=r.prepared_by
     AND EXISTS (SELECT 1 FROM app_reviewer_scope_grants g
       JOIN auth_users scope_owner ON scope_owner.id=g.owner_user_id
         AND scope_owner.role='OWNER' AND scope_owner.status='ACTIVE'
       JOIN auth_users scope_reviewer ON scope_reviewer.id=g.reviewer_user_id
         AND scope_reviewer.role='REVIEWER' AND scope_reviewer.status='ACTIVE'
       WHERE g.owner_user_id=r.prepared_by AND g.reviewer_user_id=?
        AND g.workflow_scope='STOCK' AND g.state='ACTIVE')
   ORDER BY r.created_at DESC,r.id DESC LIMIT 100`,
   [res.locals.auth.userId,res.locals.auth.userId]);
  res.json({items:rows,externalGrnVerified:false,postingAllowed:false});
 }catch(e){fail(res,e);}
});
router.get('/release-intents/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid intent ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const state=await checkReleaseIntent(conn,req.params.id);
  if(state.source.ownerId===res.locals.auth.userId){
   await conn.rollback();res.status(404).json({error:'Not independent'});return;
  }
  const [scope]=await conn.query<RowDataPacket[]>(`SELECT state
   FROM app_reviewer_scope_grants
       JOIN auth_users scope_owner ON scope_owner.id=app_reviewer_scope_grants.owner_user_id
         AND scope_owner.role='OWNER' AND scope_owner.status='ACTIVE'
       JOIN auth_users scope_reviewer ON scope_reviewer.id=app_reviewer_scope_grants.reviewer_user_id
         AND scope_reviewer.role='REVIEWER' AND scope_reviewer.status='ACTIVE'
   WHERE owner_user_id=? AND reviewer_user_id=? AND workflow_scope='STOCK'`,
   [state.source.ownerId,res.locals.auth.userId]);
  if(scope[0]?.state!=='ACTIVE'){
   await conn.rollback();res.status(404).json({error:'Release intent unavailable for review'});return;
  }
  await conn.commit();
  res.json({intent:{id:state.id,status:state.status,sha256:state.intentSha256},
   source:{heldGrnId:state.source.heldGrnId,observationId:state.source.observationId,
    siteId:state.source.siteId,holdId:state.source.holdId,lines:state.source.lines},
   postingState:'DISABLED',availableToSell:null,verifiedOfficialGrn:false});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.post('/release-intents/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid release intent ID'});return;}
 let input:ReturnType<typeof releaseDecisionInput>;
 try{input=releaseDecisionInput(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const state=await checkReleaseIntent(conn,req.params.id);
  if(state.source.ownerId===actor){
   await conn.rollback();res.status(404).json({error:'No self-review'});return;
  }
  // The current owner assignment is locked with the release write. A later
  // revocation cannot race ahead of a stale reviewer queue authorization.
  const [scope]=await conn.query<RowDataPacket[]>(`SELECT state
   FROM app_reviewer_scope_grants
       JOIN auth_users scope_owner ON scope_owner.id=app_reviewer_scope_grants.owner_user_id
         AND scope_owner.role='OWNER' AND scope_owner.status='ACTIVE'
       JOIN auth_users scope_reviewer ON scope_reviewer.id=app_reviewer_scope_grants.reviewer_user_id
         AND scope_reviewer.role='REVIEWER' AND scope_reviewer.status='ACTIVE' WHERE owner_user_id=? AND reviewer_user_id=?
    AND workflow_scope='STOCK' FOR UPDATE`,[state.source.ownerId,actor]);
  if(scope[0]?.state!=='ACTIVE'){
   await conn.rollback();res.status(404).json({error:'Release intent unavailable for review'});return;
  }
  if(state.status!=='PENDING_INTERNAL')
   throw new ChainConflictError('Release intent already reviewed');
  for(const line of state.source.lines)await zeroPosition(conn,state.source.siteId,line.productId);
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_stock_release_decisions
   (id,release_intent_id,reviewer_id,decision,reason,evidence_ref,source_inspected)
   VALUES (?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,input.decision,input.reason,
    input.evidenceRef,input.sourceInspected]);
  await conn.execute(`UPDATE inv_stock_release_intents
   SET status=?,reviewed_at=UTC_TIMESTAMP(3) WHERE id=? AND status='PENDING_INTERNAL'`,
   [input.decision,req.params.id]);
  if(input.decision==='REVIEWED_HELD'){
   const snapshot=releaseHoldSnapshot(req.params.id,state.intentSha256,id);
   await conn.execute(`INSERT INTO inv_stock_release_holds
    (id,release_intent_id,decision_id,snapshot_sha256,snapshot_json) VALUES (?,?,?,?,?)`,
    [randomUUID(),req.params.id,id,sha(JSON.stringify(snapshot)),JSON.stringify(snapshot)]);
  }
  await audit(conn,actor,req.params.id,input.decision==='REVIEWED_HELD'?'RELEASE_HELD':'RELEASE_REJECTED',
   {intentSha256:state.intentSha256,decisionId:id,sourceInspected:input.sourceInspected});
  await conn.commit();
  res.status(201).json({decisionId:id,status:input.decision,
   holdCreated:input.decision==='REVIEWED_HELD',postingState:'DISABLED',
   stockPosted:0,stockReserved:0,availableToSell:null,externalGrnVerified:false,
   message:'Independent INTERNAL release evidence reviewed; NO stock posted or allocated.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
