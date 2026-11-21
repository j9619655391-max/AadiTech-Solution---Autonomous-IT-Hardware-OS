import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {reconstructHoldHash} from '../intake/validation';
import {DispatchInputError,DispatchConflictError,validateDestinationReview,validateDispatchReview,
 dispatchManifest,verifyManifestJson,sha} from './validation';
const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,error:unknown){
 if(error instanceof DispatchInputError){res.status(400).json({error:error.message});return;}
 if(error instanceof DispatchConflictError||(error&&typeof error==='object'&&'code' in error&&error.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Destination or dispatch review state conflicts with immutable internal evidence'});return;
 }
 console.error('Independent dispatch review failure',error instanceof Error?error.name:'Unknown');
 res.status(503).json({error:'Independent supplier dispatch review unavailable'});
}
async function audit(conn:PoolConnection,actor:string,entityId:string,
 event:'DESTINATION_ATTESTED'|'DESTINATION_REJECTED'|'PREPARATION_APPROVED_HELD'|'PREPARATION_REJECTED',
 payload:object){
 await conn.execute('INSERT INTO proc_dispatch_audit(id,actor_id,entity_id,event_type,event_sha256) VALUES (?,?,?,?,?)',
  [randomUUID(),actor,entityId,event,sha(JSON.stringify(payload))]);
}
router.get('/destinations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT d.id,d.supplier_id AS supplierId,
   s.code AS supplierCode,d.email,d.status,d.evidence_ref AS evidenceRef,d.review_reason AS reviewReason,d.created_by AS createdBy
   FROM proc_delivery_destinations d JOIN proc_suppliers s ON s.id=d.supplier_id
   WHERE d.created_by<>? ORDER BY d.created_at DESC,d.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externallyVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/destinations/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid destination ID'});return;}
 let input:ReturnType<typeof validateDestinationReview>;
 try{input=validateDestinationReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT d.id,d.status,
   d.created_by AS createdBy,s.status AS supplierStatus
   FROM proc_delivery_destinations d JOIN proc_suppliers s ON s.id=d.supplier_id
   WHERE d.id=? FOR UPDATE`,[req.params.id]);
  if(!rows.length||rows[0].createdBy===actor){
   await conn.rollback();res.status(404).json({error:'Destination not available for independent review'});return;
  }
  if(rows[0].status!=='PENDING_INTERNAL')
   throw new DispatchConflictError('Destination already reviewed');
  if(input.decision==='REVIEWED_INTERNAL'&&rows[0].supplierStatus!=='REVIEWED_INTERNAL')
   throw new DispatchConflictError('Supplier internal identity review required');
  await conn.execute(`UPDATE proc_delivery_destinations SET
   status=?,reviewed_by=?,review_evidence_ref=?,review_reason=?,reviewed_at=UTC_TIMESTAMP(3)
   WHERE id=? AND status='PENDING_INTERNAL'`,
   [input.decision,actor,input.evidenceRef,input.reason,req.params.id]);
  await audit(conn,actor,req.params.id,
   input.decision==='REVIEWED_INTERNAL'?'DESTINATION_ATTESTED':'DESTINATION_REJECTED',
   {reviewEvidenceRef:input.evidenceRef,reason:input.reason,identityAttested:input.identityAttested});
  await conn.commit();
  res.status(201).json({id:req.params.id,status:input.decision,
   externallyVerified:false,dispatchEnabled:false,
   message:'Independent INTERNAL destination decision recorded; no proof of supplier inbox control.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/requests',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.hold_id AS holdId,
   p.status,p.manifest_sha256 AS manifestSha256,d.email,d.status AS destinationStatus,
   s.code AS supplierCode,p.created_at AS createdAt
   FROM proc_dispatch_preparations p
   JOIN proc_delivery_destinations d ON d.id=p.destination_id
   JOIN proc_po_holds h ON h.id=p.hold_id
   JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_suppliers s ON s.id=r.supplier_id
   WHERE p.prepared_by<>? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externalPoIssued:false,supplierAcknowledged:false});
 }catch(e){fail(res,e);}
});
router.get('/requests/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid preparation ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.status,
   p.prepared_by AS preparedBy,p.manifest_sha256 AS manifestSha256,
   p.manifest_json AS manifestJson,d.status AS destinationStatus
   FROM proc_dispatch_preparations p
   JOIN proc_delivery_destinations d ON d.id=p.destination_id
   WHERE p.id=? AND p.prepared_by<>?`,[req.params.id,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'Preparation not available'});return;}
  const manifest=verifyManifestJson(rows[0].manifestJson,rows[0].manifestSha256);
  res.json({preparation:{id:rows[0].id,status:rows[0].status,
   destinationStatus:rows[0].destinationStatus},manifest,
   externalPoIssued:false,dispatchEnabled:false});
 }catch(e){fail(res,e);}
});
router.post('/requests/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid preparation ID'});return;}
 let input:ReturnType<typeof validateDispatchReview>;
 try{input=validateDispatchReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT p.id,p.hold_id AS holdId,
   p.prepared_by AS preparedBy,p.status,p.hold_sha256 AS holdSha256,
   p.manifest_json AS manifestJson,p.manifest_sha256 AS manifestSha256,
   p.destination_id AS destinationId,p.authorization_evidence_ref AS authorizationEvidenceRef,
   d.supplier_id AS supplierId,d.email,d.status AS destinationStatus,
   h.snapshot_sha256 AS recordedHoldSha,h.snapshot_json AS holdJson,
   h.status AS holdStatus,h.dispatch_state AS dispatchState,
   r.id AS requestId,r.supplier_id AS heldSupplierId,r.created_by AS ownerId,
   r.status AS requestStatus
   FROM proc_dispatch_preparations p
   JOIN proc_delivery_destinations d ON d.id=p.destination_id
   JOIN proc_po_holds h ON h.id=p.hold_id
   JOIN proc_requests r ON r.id=h.request_id
   WHERE p.id=? FOR UPDATE`,[req.params.id]);
  if(!rows.length||rows[0].preparedBy===actor){
   await conn.rollback();res.status(404).json({error:'Preparation not available for independent review'});return;
  }
  const p=rows[0];
  if(p.status!=='PENDING_INTERNAL')
   throw new DispatchConflictError('Preparation decision already recorded');
  if(p.destinationStatus!=='REVIEWED_INTERNAL'||p.holdStatus!=='HELD'||
   p.dispatchState!=='DISABLED'||p.requestStatus!=='APPROVED_INTERNAL'||
   p.preparedBy!==p.ownerId||p.supplierId!==p.heldSupplierId||
   p.holdSha256!==p.recordedHoldSha||reconstructHoldHash(p.holdJson)!==p.holdSha256)
   throw new DispatchConflictError('Held PO or supplier destination state changed');
  const manifest=verifyManifestJson(p.manifestJson,p.manifestSha256);
  const expected=dispatchManifest({holdId:p.holdId,holdSha256:p.holdSha256,
   destinationId:p.destinationId,supplierId:p.supplierId,email:p.email,
   authorizationEvidenceRef:p.authorizationEvidenceRef});
  if(JSON.stringify(manifest)!==JSON.stringify(expected))
   throw new DispatchConflictError('Supplier destination or held snapshot integrity mismatch');
  const [inbound]=await conn.query<RowDataPacket[]>(
   'SELECT id FROM inv_inbound_observations WHERE hold_id=? LIMIT 1',[p.holdId]);
  if(inbound.length)throw new DispatchConflictError('Inbound observation already recorded for held PO');
  const decisionId=randomUUID();
  await conn.execute(`INSERT INTO proc_dispatch_review_decisions
   (id,preparation_id,reviewer_id,decision,reason,evidence_ref,destination_attested)
   VALUES (?,?,?,?,?,?,?)`,[decisionId,req.params.id,actor,input.decision,
    input.reason,input.evidenceRef,input.destinationAttested]);
  await conn.execute(`UPDATE proc_dispatch_preparations
    SET status=?,reviewed_at=UTC_TIMESTAMP(3) WHERE id=? AND status='PENDING_INTERNAL'`,
   [input.decision,req.params.id]);
  if(input.decision==='APPROVED_INTERNAL'){
   // Internal outbox HOLD only; no network integration or ENABLED state exists.
   const snapshot={format:'aaditech-supplier-PO-outbox-HELD-v1',
    preparationId:req.params.id,manifestSha256:p.manifestSha256,
    decisionId,dispatchState:'DISABLED',externalPoIssued:false};
   const serialized=JSON.stringify(snapshot),digest=sha(serialized);
   await conn.execute(`INSERT INTO proc_dispatch_outbox_holds
    (id,preparation_id,decision_id,snapshot_sha256,snapshot_json)
    VALUES(?,?,?,?,?)`,
    [randomUUID(),req.params.id,decisionId,digest,serialized]);
  }
  await audit(conn,actor,req.params.id,
   input.decision==='APPROVED_INTERNAL'?'PREPARATION_APPROVED_HELD':'PREPARATION_REJECTED',
   {manifestSha256:p.manifestSha256,decisionId,evidenceRef:input.evidenceRef,
    destinationAttested:input.destinationAttested});
  await conn.commit();
  res.status(201).json({id:decisionId,preparationId:req.params.id,
   status:input.decision,outboxState:input.decision==='APPROVED_INTERNAL'?'HELD':null,
   dispatchState:'DISABLED',externalPoIssued:false,supplierAcknowledged:false,
   availableToSell:null,realGoodsReceiptAccepted:false,
   message:'Independent INTERNAL supplier PO dispatch review only. Approved preparation stays in a permanently disabled held outbox.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
