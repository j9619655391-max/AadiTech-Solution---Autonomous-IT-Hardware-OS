import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {checkJournal} from './integrity';
import {validateReview,ChainInputError,ChainConflictError,
 journalHoldSnapshot} from './validation';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Unposted journal review conflicts with independently checked source'});return;
 }
 console.error('Journal reviewer failure',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Unposted journal review unavailable'});
}
async function audit(c:PoolConnection,journalId:string,actor:string,
 event:'JOURNAL_HELD'|'JOURNAL_REJECTED',details:object){
 await c.execute(`INSERT INTO inv_unposted_journal_audit
  (id,journal_id,actor_id,event_type,event_sha256) VALUES(?,?,?,?,?)`,
  [randomUUID(),journalId,actor,event,sha(JSON.stringify(details))]);
}
router.get('/journals',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT j.id,j.release_intent_id AS releaseIntentId,
   j.site_id AS siteId,j.prepared_by AS preparedBy,
   j.manifest_sha256 AS manifestSha256,j.status,j.created_at AS createdAt
   FROM inv_unposted_journal_headers j
   JOIN inv_stock_release_intents release_intent ON release_intent.id=j.release_intent_id
   JOIN inventory_sites site ON site.id=j.site_id
   JOIN inv_grn_held_records h ON h.id=release_intent.held_grn_id
   JOIN inv_grn_reconciliation_packs pack ON pack.id=h.pack_id
   JOIN proc_ack_claims claim ON claim.id=pack.claim_id
   JOIN proc_dispatch_preparations prep ON prep.id=claim.preparation_id
   JOIN proc_po_holds po ON po.id=prep.hold_id
   JOIN proc_requests request_record ON request_record.id=po.request_id
   WHERE j.prepared_by<>? AND j.prepared_by=release_intent.prepared_by
    AND j.prepared_by=pack.prepared_by AND j.prepared_by=site.created_by
    AND j.prepared_by=request_record.created_by
    AND EXISTS (SELECT 1 FROM app_reviewer_scope_grants g
      WHERE g.owner_user_id=j.prepared_by AND g.reviewer_user_id=?
       AND g.workflow_scope='JOURNAL' AND g.state='ACTIVE')
   ORDER BY j.created_at DESC,j.id DESC LIMIT 100`,
   [res.locals.auth.userId,res.locals.auth.userId]);
  res.json({items:rows,actualStockLedger:false,realGrnVerified:false});
 }catch(e){fail(res,e);}
});
router.get('/journals/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid journal ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const state=await checkJournal(conn,req.params.id);
  if(state.release.source.ownerId===res.locals.auth.userId){
   await conn.rollback();res.status(404).json({error:'Journal unavailable for independent review'});return;
  }
  const [scope]=await conn.query<RowDataPacket[]>(`SELECT state
   FROM app_reviewer_scope_grants WHERE owner_user_id=? AND reviewer_user_id=?
     AND workflow_scope='JOURNAL'`,[state.release.source.ownerId,res.locals.auth.userId]);
  if(scope[0]?.state!=='ACTIVE'){
   await conn.rollback();res.status(404).json({error:'Journal unavailable for independent review'});return;
  }
  await conn.commit();
  res.json({journal:{id:state.journalId,status:state.status,
   manifestSha256:state.manifestSha256},manifest:state.manifest,
   totals:state.balanced,externalSupplierVerified:false,stockPostingEnabled:false,
   serialOwnershipEstablished:false,availableToSell:null});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.post('/journals/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid journal ID'});return;}
 let input:ReturnType<typeof validateReview>;
 try{input=validateReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const state=await checkJournal(conn,req.params.id);
  if(state.release.source.ownerId===actor){
   await conn.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  // Re-validate exact scope under lock in the decision transaction, so a
  // revoked reviewer cannot write an unposted journal HOLD from stale UI.
  const [scope]=await conn.query<RowDataPacket[]>(`SELECT state
   FROM app_reviewer_scope_grants WHERE owner_user_id=? AND reviewer_user_id=?
     AND workflow_scope='JOURNAL' FOR UPDATE`,[state.release.source.ownerId,actor]);
  if(scope[0]?.state!=='ACTIVE'){
   await conn.rollback();res.status(404).json({error:'Journal unavailable for independent review'});return;
  }
  if(state.status!=='PENDING_INTERNAL')
   throw new ChainConflictError('Journal review decision already recorded');
  const decisionId=randomUUID();
  await conn.execute(`INSERT INTO inv_unposted_journal_reviews
   (id,journal_id,reviewer_id,decision,reason,review_evidence_ref,balancing_inspected)
   VALUES(?,?,?,?,?,?,?)`,
   [decisionId,req.params.id,actor,input.decision,input.reason,
    input.evidenceRef,input.balancingInspected]);
  await conn.execute(`UPDATE inv_unposted_journal_headers
   SET status=?,reviewed_at=UTC_TIMESTAMP(3)
   WHERE id=? AND status='PENDING_INTERNAL'`,[input.decision,req.params.id]);
  if(input.decision==='REVIEWED_HELD'){
   const hold=journalHoldSnapshot(req.params.id,state.manifestSha256,decisionId);
   await conn.execute(`INSERT INTO inv_unposted_journal_holds
    (id,journal_id,review_id,snapshot_sha256,snapshot_json) VALUES (?,?,?,?,?)`,
    [randomUUID(),req.params.id,decisionId,sha(JSON.stringify(hold)),JSON.stringify(hold)]);
  }
  await audit(conn,req.params.id,actor,
   input.decision==='REVIEWED_HELD'?'JOURNAL_HELD':'JOURNAL_REJECTED',
   {manifestSha256:state.manifestSha256,decisionId,
    balancedEvidenceUnits:state.balanced.evidenceUnits});
  await conn.commit();
  res.status(201).json({decisionId,journalId:req.params.id,status:input.decision,
   heldRecordCreated:input.decision==='REVIEWED_HELD',
   evidenceLegCount:state.balanced.legCount,
   balancedEvidenceUnits:state.balanced.evidenceUnits,
   postingState:'DISABLED',stockPosted:0,realStockReserved:0,
   supplierAuthenticated:false,officialGrnVerified:false,
   serialOwnershipEstablished:false,availableToSell:null,
   message:'Independently reviewed UNPOSTED double-entry evidence only; no real stock transfer, title or availability.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
