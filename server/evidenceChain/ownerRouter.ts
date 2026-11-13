import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ChainInputError,ChainConflictError,validateClaim,validatePack,
 claimDigest,sha} from './validation';
import {checkHeldSource,checkClaim,checkInternallyAttestedClaim,
 checkQuarantine,makePack,verifyPersistedPack} from './integrity';

const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Claim or GRN evidence chain conflict; no supplier verification or stock posting'});return;
 }
 console.error('Held evidence preparation failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Internal supplier evidence service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'ACK_CLAIM'|'GRN_PACK',
 id:string,event:'CLAIM_RECORDED'|'PACK_PREPARED',details:object){
 await c.execute(`INSERT INTO inv_grn_evidence_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256) VALUES (?,?,?,?,?,?)`,
  [randomUUID(),actor,type,id,event,sha(JSON.stringify(details))]);
}
router.get('/eligible',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT
   p.id AS preparationId,p.hold_id AS holdId,p.status AS preparationStatus,
   s.code AS supplierCode,o.id AS outboxId,
   c.id AS claimId,c.status AS claimStatus,
   i.id AS observationId,i.status AS observationStatus
   FROM proc_dispatch_preparations p
   JOIN proc_po_holds h ON h.id=p.hold_id
   JOIN proc_requests r ON r.id=h.request_id
   JOIN proc_suppliers s ON s.id=r.supplier_id
   JOIN proc_dispatch_outbox_holds o ON o.preparation_id=p.id
   LEFT JOIN proc_ack_claims c ON c.preparation_id=p.id
   LEFT JOIN inv_inbound_observations i ON i.hold_id=p.hold_id
   WHERE p.prepared_by=? AND p.status='APPROVED_INTERNAL'
   AND o.state='HELD' AND o.dispatch_state='DISABLED'
   ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPoIssued:false,acknowledgmentVerified:false,
   actualGrnAllowed:false,stockPostingEnabled:false});
 }catch(e){fail(res,e);}
});
router.get('/claims',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT c.id,c.preparation_id AS preparationId,
   c.supplier_ack_ref AS supplierAckRef,c.evidence_ref AS evidenceRef,
   c.document_sha256 AS documentSha256,c.claim_sha256 AS claimSha256,c.status,
   c.created_at AS createdAt
   FROM proc_ack_claims c WHERE c.recorded_by=?
   ORDER BY c.created_at DESC,c.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,verifiedBySupplier:false});
 }catch(e){fail(res,e);}
});
router.post('/claims',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateClaim>;
 try{input=validateClaim(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const source=await checkHeldSource(conn,input.preparationId);
  if(source.ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Preparation unavailable to owner'});return;
  }
  const digest=claimDigest(input,source.outboxSha256);
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,claim_sha256 AS digest,status
   FROM proc_ack_claims WHERE preparation_id=?`,[input.preparationId]);
  if(existing.length){
   if(existing[0].digest!==digest)throw new ChainConflictError('Claim changed after recording');
   await conn.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,replayed:true,
    supplierAuthenticated:false,externalPoIssued:false});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_ack_claims
   (id,preparation_id,outbox_id,recorded_by,supplier_ack_ref,evidence_ref,
    document_sha256,outbox_sha256,claim_sha256) VALUES (?,?,?,?,?,?,?,?,?)`,
   [id,input.preparationId,source.outboxId,actor,input.supplierAckRef,
    input.evidenceRef,input.documentSha256,source.outboxSha256,digest]);
  await audit(conn,actor,'ACK_CLAIM',id,'CLAIM_RECORDED',{
   preparationId:input.preparationId,claimSha256:digest,outboxSha256:source.outboxSha256});
  await conn.commit();
  res.status(201).json({id,status:'AWAITING_INTERNAL_REVIEW',claimSha256:digest,
   replayed:false,supplierAuthenticated:false,supplierAcknowledged:false,
   externalPoIssued:false,
   message:'Unverified operator assertion captured; evidence hash is not supplier authentication or purchase order issuance.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/grn-packs',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.claim_id AS claimId,
   p.observation_id AS observationId,p.pack_sha256 AS packSha256,p.status,
   h.id AS holdId,h.status AS heldStatus,h.stock_posting_state AS stockPostingState
   FROM inv_grn_reconciliation_packs p
   LEFT JOIN inv_grn_held_records h ON h.pack_id=p.id
   WHERE p.prepared_by=? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,officialGrnCreated:false,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/grn-packs',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validatePack>;
 try{input=validatePack(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [claimRows]=await conn.query<RowDataPacket[]>(
   'SELECT preparation_id AS preparationId FROM proc_ack_claims WHERE id=?',[input.claimId]);
  if(claimRows.length!==1){
   await conn.rollback();res.status(404).json({error:'Claim not available'});return;
  }
  const source=await checkHeldSource(conn,claimRows[0].preparationId);
  if(source.ownerId!==actor){
   await conn.rollback();res.status(404).json({error:'Claim not available to owner'});return;
  }
  const claim=await checkClaim(conn,input.claimId,source);
  await checkInternallyAttestedClaim(conn,claim);
  const observation=await checkQuarantine(conn,input.observationId,source);
  const snapshot=makePack(source,claim,observation),digest=sha(JSON.stringify(snapshot));
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,status,pack_sha256 AS digest,
    pack_json AS snapshot FROM inv_grn_reconciliation_packs WHERE claim_id=? OR observation_id=?
    FOR UPDATE`,[input.claimId,input.observationId]);
  if(existing.length){
   if(existing.length!==1||existing[0].digest!==digest)
    throw new ChainConflictError('GRN evidence already bound to other immutable source');
   verifyPersistedPack(existing[0].snapshot,existing[0].digest,snapshot);
   await conn.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,replayed:true,
    officialGrnCreated:false,stockPosted:false,availableToSell:null});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_grn_reconciliation_packs
   (id,claim_id,observation_id,prepared_by,pack_sha256,pack_json)
   VALUES (?,?,?,?,?,?)`,
   [id,input.claimId,input.observationId,actor,digest,JSON.stringify(snapshot)]);
  await audit(conn,actor,'GRN_PACK',id,'PACK_PREPARED',{
   claimId:input.claimId,observationId:input.observationId,packSha256:digest});
  await conn.commit();
  res.status(201).json({id,status:'AWAITING_INTERNAL_REVIEW',packSha256:digest,
   quantityTotal:observation.quantityTotal,lineCount:observation.lineCount,
   supplierAuthenticated:false,officialGrnCreated:false,stockPosted:false,
   availableToSell:null,dispatchEnabled:false,
   message:'Internal source reconciliation only; NO supplier-authenticated PO, issued GRN, stock receipt or available inventory.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/readiness',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT
    (SELECT COUNT(*) FROM proc_ack_claims c WHERE c.recorded_by=?) AS claims,
    (SELECT COUNT(*) FROM inv_grn_reconciliation_packs p WHERE p.prepared_by=?) AS packs,
    (SELECT COUNT(*) FROM inv_grn_held_records h
      JOIN inv_grn_reconciliation_packs p ON p.id=h.pack_id WHERE p.prepared_by=?) AS heldPacks`,
   [res.locals.auth.userId,res.locals.auth.userId,res.locals.auth.userId]);
  res.json({evidenceOnly:rows[0],productionGrnReady:false,externalPoIssued:false,
   supplierAcknowledgmentAuthenticated:false,sellableStockRecognized:false,
   availableToSell:null,stockPostingState:'DISABLED'});
 }catch(e){fail(res,e);}
});
export default router;
