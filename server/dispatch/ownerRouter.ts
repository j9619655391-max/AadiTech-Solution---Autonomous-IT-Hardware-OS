import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {reconstructHoldHash} from '../intake/validation';
import {DispatchInputError,DispatchConflictError,validateDestination,validatePreparation,
 dispatchManifest,sha,verifyManifestJson} from './validation';
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,error:unknown){
 if(error instanceof DispatchInputError){res.status(400).json({error:error.message});return;}
 if(error instanceof DispatchConflictError||(error&&typeof error==='object'&&'code' in error&&error.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Supplier dispatch preparation conflicts with immutable approved source or recorded request'});return;
 }
 console.error('Dispatch preparation failure',error instanceof Error?error.name:'Unknown');
 res.status(503).json({error:'Supplier dispatch preparation unavailable'});
}
async function audit(conn:PoolConnection,actor:string,entityId:string,
 event:'DESTINATION_PROPOSED'|'PREPARATION_CREATED',data:object){
 await conn.execute('INSERT INTO proc_dispatch_audit(id,actor_id,entity_id,event_type,event_sha256) VALUES(?,?,?,?,?)',
  [randomUUID(),actor,entityId,event,sha(JSON.stringify(data))]);
}
router.get('/destinations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT d.id,d.supplier_id AS supplierId,
   s.code AS supplierCode,d.email,d.status,d.evidence_ref AS evidenceRef,
   d.created_at AS createdAt
   FROM proc_delivery_destinations d JOIN proc_suppliers s ON s.id=d.supplier_id
   WHERE d.created_by=? ORDER BY d.created_at DESC,d.id DESC LIMIT 200`,
   [res.locals.auth.userId]);
  res.json({items:rows,destinationExternallyVerified:false,dispatchEnabled:false});
 }catch(e){fail(res,e);}
});
router.post('/destinations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateDestination>;
 try{input=validateDestination(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [suppliers]=await conn.query<RowDataPacket[]>(
   'SELECT id,status FROM proc_suppliers WHERE id=? AND created_by=? FOR UPDATE',
   [input.supplierId,actor]);
  if(suppliers.length!==1||suppliers[0].status!=='REVIEWED_INTERNAL')
   throw new DispatchConflictError('Independently reviewed supplier ownership required');
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_delivery_destinations
   (id,supplier_id,email,evidence_ref,created_by) VALUES(?,?,?,?,?)`,
   [id,input.supplierId,input.email,input.evidenceRef,actor]);
  await audit(conn,actor,id,'DESTINATION_PROPOSED',{
   supplierId:input.supplierId,emailHash:sha(input.email),evidenceRef:input.evidenceRef});
  await conn.commit();
  res.status(201).json({id,supplierId:input.supplierId,email:input.email,
   status:'PENDING_INTERNAL',externalVerification:false,dispatchEnabled:false,
   message:'Destination proposed internally, NOT validated by supplier or usable for sending.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/holds',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT h.id AS holdId,h.snapshot_sha256 AS holdSha256,
   r.id AS requestId,s.code AS supplierCode,s.id AS supplierId,
   h.status AS holdStatus,h.dispatch_state AS dispatchState,
   d.id AS destinationId,d.status AS destinationStatus,d.email AS destinationEmail,
   p.id AS preparationId,p.status AS preparationStatus
   FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_suppliers s ON s.id=r.supplier_id
   LEFT JOIN proc_delivery_destinations d ON d.supplier_id=s.id
   LEFT JOIN proc_dispatch_preparations p ON p.hold_id=h.id
   WHERE r.created_by=? AND h.status='HELD' AND h.dispatch_state='DISABLED'
   ORDER BY h.created_at DESC,h.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPoIssued:false,outboundIntegrationEnabled:false});
 }catch(e){fail(res,e);}
});
router.get('/requests',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.hold_id AS holdId,
   p.destination_id AS destinationId,p.manifest_sha256 AS manifestSha256,
   p.status,p.created_at AS createdAt,o.id AS outboxId,o.state AS outboxState,
   o.dispatch_state AS dispatchState
   FROM proc_dispatch_preparations p
   LEFT JOIN proc_dispatch_outbox_holds o ON o.preparation_id=p.id
   WHERE p.prepared_by=? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPoIssued:false,supplierAcknowledged:false,dispatchEnabled:false});
 }catch(e){fail(res,e);}
});
router.post('/requests',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validatePreparation>;
 try{input=validatePreparation(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [holds]=await conn.query<RowDataPacket[]>(`SELECT h.id,h.status AS holdStatus,
   h.dispatch_state AS dispatchState,h.snapshot_sha256 AS holdSha256,
   h.snapshot_json AS snapshotJson,h.decision_id AS decisionId,
   r.id AS requestId,r.created_by AS ownerId,r.status AS requestStatus,
   r.supplier_id AS supplierId,r.site_id AS siteId,
   s.status AS supplierStatus
   FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_suppliers s ON s.id=r.supplier_id
   WHERE h.id=? FOR UPDATE`,[input.holdId]);
  if(!holds.length||holds[0].ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Held purchase snapshot not found for owner'});return;
  }
  const h=holds[0];
  if(h.holdStatus!=='HELD'||h.dispatchState!=='DISABLED'||
   h.requestStatus!=='APPROVED_INTERNAL'||h.supplierStatus!=='REVIEWED_INTERNAL')
   throw new DispatchConflictError('Unapproved supplier or changed HELD purchase authority');
  if(reconstructHoldHash(h.snapshotJson)!==h.holdSha256)
   throw new DispatchConflictError('Held purchase snapshot checksum mismatch');
  const held=typeof h.snapshotJson==='string'?JSON.parse(h.snapshotJson):h.snapshotJson;
  if(held.requestId!==h.requestId||held.supplierId!==h.supplierId||
   held.siteId!==h.siteId||held.reviewId!==h.decisionId)
   throw new DispatchConflictError('Held purchase owner/site/reviewer mismatch');
  // Never create an outbound request retrospectively for a hold already used
  // as inbound physical observation evidence.
  const [inbounds]=await conn.query<RowDataPacket[]>(
   'SELECT id FROM inv_inbound_observations WHERE hold_id=? LIMIT 1',[input.holdId]);
  if(inbounds.length)throw new DispatchConflictError('Inbound observation exists for this held PO');
  const [destinations]=await conn.query<RowDataPacket[]>(`SELECT id,supplier_id AS supplierId,
   email,status,created_by AS createdBy FROM proc_delivery_destinations
   WHERE id=? FOR UPDATE`,[input.destinationId]);
  if(destinations.length!==1||destinations[0].status!=='REVIEWED_INTERNAL'||
   destinations[0].supplierId!==h.supplierId||destinations[0].createdBy!==actor)
   throw new DispatchConflictError('Independent review of matching supplier destination required');
  const d=destinations[0],manifest=dispatchManifest({
   holdId:input.holdId,holdSha256:h.holdSha256,destinationId:input.destinationId,
   supplierId:h.supplierId,email:d.email,authorizationEvidenceRef:input.authorizationEvidenceRef});
  const payload=JSON.stringify(manifest),hash=sha(payload);
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,manifest_sha256 AS digest,
   manifest_json AS json,status FROM proc_dispatch_preparations WHERE hold_id=?`,[input.holdId]);
  if(existing.length){
   verifyManifestJson(existing[0].json,existing[0].digest);
   if(existing[0].digest!==hash)throw new DispatchConflictError('Purchase dispatch was prepared with a different destination or evidence');
   await conn.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,
    manifestSha256:hash,replayed:true,dispatchEnabled:false,externalPoIssued:false});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_dispatch_preparations
   (id,hold_id,destination_id,prepared_by,authorization_evidence_ref,hold_sha256,
    manifest_sha256,manifest_json) VALUES (?,?,?,?,?,?,?,?)`,
   [id,input.holdId,input.destinationId,actor,input.authorizationEvidenceRef,h.holdSha256,
    hash,payload]);
  await audit(conn,actor,id,'PREPARATION_CREATED',{
   holdId:input.holdId,destinationId:input.destinationId,manifestSha256:hash});
  await conn.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',manifestSha256:hash,
   replayed:false,dispatchEnabled:false,externalPoIssued:false,
   message:'Internal supplier PO dispatch review requested only. No external purchase order issued or sent.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
