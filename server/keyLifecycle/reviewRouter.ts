import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {inspectReceipt,inspectRotation} from './integrity';
import {ChainInputError,ChainConflictError,reviewBody,sha256} from './validation';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Independent possession/rotation review conflicts with frozen or retired source'});return;
 }
 console.error('Key lifecycle independent reviewer refused',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Key lifecycle reviewer service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'POSSESSION'|'ROTATION',id:string,
 event:'POSSESSION_REVIEWED'|'POSSESSION_REJECTED'|'ROTATION_REVIEWED'|'ROTATION_REJECTED',
 details:object){
 await c.execute(`INSERT INTO inv_key_lifecycle_audit
 (id,actor_id,entity_type,entity_id,event_type,event_sha256)
 VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,event,sha256(JSON.stringify(details))]);
}
router.get('/receipts',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id AS receiptId,
   p.key_id AS keyId,k.fingerprint_sha256 AS fingerprint,k.party_kind AS partyKind,
   k.registered_by AS registeredBy,r.decision AS reviewState,
   p.status,p.created_at AS createdAt
   FROM inv_key_possession_receipts p
   JOIN inv_proof_key_candidates k ON k.id=p.key_id
   LEFT JOIN inv_key_possession_reviews r ON r.receipt_id=p.id
   WHERE k.registered_by<>? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externalPartyAuthentication:false});
 }catch(e){fail(res,e);}
});
router.get('/receipts/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid possession receipt'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const rec=await inspectReceipt(c,req.params.id);
  if(rec.key.registeredBy===res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Independent inspection required'});return;
  }
  await c.commit();
  res.json({receiptId:rec.id,format:rec.message.format,message:rec.message,
   candidateFingerprint:rec.key.fingerprint,signatureMatched:true,
   actualSupplierIdentityVerified:false,actualWarehouseIdentityVerified:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/receipts/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid possession receipt'});return;}
 let data:ReturnType<typeof reviewBody>;
 try{data=reviewBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),rec=await inspectReceipt(c,req.params.id);
  if(rec.key.registeredBy===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_key_possession_reviews
   WHERE receipt_id=? FOR UPDATE`,[req.params.id]);
  if(prior.length)throw new ChainConflictError('Receipt already reviewed');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_key_possession_reviews
   (id,receipt_id,reviewer_id,decision,reason,evidence_ref,possession_inspected)
   VALUES(?,?,?,?,?,?,?)`,[id,req.params.id,actor,data.decision,data.reason,
    data.evidenceRef,data.possessionInspected]);
  await audit(c,actor,'POSSESSION',req.params.id,
   data.decision==='REVIEWED_UNTRUSTED'?'POSSESSION_REVIEWED':'POSSESSION_REJECTED',
   {keyFingerprint:rec.key.fingerprint,decision:data.decision});
  await c.commit();
  res.status(201).json({reviewId:id,status:data.decision,ownershipClaim:'CRYPTO_POSSESSION_ONLY',
   externalIdentityVerified:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/rotations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT x.id AS rotationId,
   x.old_key_id AS oldKeyId,x.new_key_id AS newKeyId,
   x.prepared_by AS preparedBy,x.status,
   a.fingerprint_sha256 AS oldFingerprint,b.fingerprint_sha256 AS newFingerprint,
   x.reason,x.evidence_ref AS evidenceRef
   FROM inv_key_rotation_proposals x
   JOIN inv_proof_key_candidates a ON a.id=x.old_key_id
   JOIN inv_proof_key_candidates b ON b.id=x.new_key_id
   WHERE x.prepared_by<>? ORDER BY x.created_at DESC,x.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externalAuthorityGranted:false});
 }catch(e){fail(res,e);}
});
router.post('/rotations/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid rotation ID'});return;}
 let data:ReturnType<typeof reviewBody>;
 try{data=reviewBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  // Rejections remain available even if the owner emergency-revoked the old key.
  const [pending]=await c.query<RowDataPacket[]>(`SELECT id,old_key_id AS oldKeyId,
   new_key_id AS newKeyId,prepared_by AS preparedBy,status
   FROM inv_key_rotation_proposals WHERE id=? FOR UPDATE`,[req.params.id]);
  if(pending.length!==1||pending[0].status!=='PENDING_INTERNAL')
   throw new ChainConflictError('Rotation review no longer pending');
  if(pending[0].preparedBy===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(data.decision==='REVIEWED_UNTRUSTED'){
   const checked=await inspectRotation(c,req.params.id);
   if(checked.preparedBy!==pending[0].preparedBy)
    throw new ChainConflictError('Rotation owner changed');
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_key_rotation_decisions
   (id,proposal_id,reviewer_id,decision,reason,evidence_ref,possession_inspected)
   VALUES(?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,data.decision,data.reason,data.evidenceRef,data.possessionInspected]);
  await c.execute(`UPDATE inv_key_rotation_proposals
   SET status=?,reviewed_at=UTC_TIMESTAMP(3)
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,req.params.id]);
  if(data.decision==='REVIEWED_UNTRUSTED'){
   // Old key is retired *in the same transaction* as positive rotation review.
   await c.execute(`INSERT INTO inv_key_retirements
    (key_id,initiated_by,reason,evidence_ref,event_type)
    VALUES(?,?,?,?,'ROTATION_RETIRED')`,
    [pending[0].oldKeyId,actor,data.reason,data.evidenceRef]);
  }
  await audit(c,actor,'ROTATION',req.params.id,
   data.decision==='REVIEWED_UNTRUSTED'?'ROTATION_REVIEWED':'ROTATION_REJECTED',
   {oldKeyId:pending[0].oldKeyId,newKeyId:pending[0].newKeyId,
    decision:data.decision,oldKeyRetired:data.decision==='REVIEWED_UNTRUSTED'});
  await c.commit();
  res.status(201).json({rotationId:req.params.id,decision:data.decision,
   oldKeyRetired:data.decision==='REVIEWED_UNTRUSTED',
   newKeyExternalTrustEstablished:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
export default router;
