import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {RowDataPacket,PoolConnection} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {ChainInputError,ChainConflictError,validateClaimDecision,validatePackDecision,
 sha,heldGrnSnapshot} from './validation';
import {checkHeldSource,checkClaim,checkInternallyAttestedClaim,
 checkQuarantine,makePack,verifyPersistedPack} from './integrity';

const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Independent evidence review conflicts with immutable held source'});return;
 }
 console.error('Independent GRN evidence review failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Independent evidence review unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'ACK_CLAIM'|'GRN_PACK',
 id:string,event:'CLAIM_ATTESTED'|'CLAIM_DISPUTED'|'PACK_HELD'|'PACK_REJECTED',value:object){
 await c.execute(`INSERT INTO inv_grn_evidence_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256)
  VALUES(?,?,?,?,?,?)`,
  [randomUUID(),actor,type,id,event,sha(JSON.stringify(value))]);
}
router.get('/claims',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT c.id,c.preparation_id AS preparationId,
   c.supplier_ack_ref AS supplierAckRef,c.evidence_ref AS evidenceRef,
   c.document_sha256 AS documentSha256,c.status,c.recorded_by AS recordedBy,
   c.claim_sha256 AS claimSha256
   FROM proc_ack_claims c WHERE c.recorded_by<>?
   ORDER BY c.created_at DESC,c.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,realSupplierVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/claims/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid claim ID'});return;}
 let decision:ReturnType<typeof validateClaimDecision>;
 try{decision=validateClaimDecision(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [ident]=await conn.query<RowDataPacket[]>(
   'SELECT preparation_id AS preparationId FROM proc_ack_claims WHERE id=?',[req.params.id]);
  if(ident.length!==1){await conn.rollback();res.status(404).json({error:'Claim not found'});return;}
  const source=await checkHeldSource(conn,ident[0].preparationId);
  if(source.ownerId===actor){
   await conn.rollback();res.status(404).json({error:'Independent review only'});return;
  }
  const claim=await checkClaim(conn,req.params.id,source);
  if(claim.status!=='AWAITING_INTERNAL_REVIEW')
   throw new ChainConflictError('Claim already reviewed');
  const id=randomUUID();
  await conn.execute(`INSERT INTO proc_ack_claim_decisions
   (id,claim_id,reviewer_id,decision,reason,review_evidence_ref,document_inspected)
   VALUES (?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,decision.decision,decision.reason,
    decision.reviewEvidenceRef,decision.documentInspected]);
  await conn.execute(`UPDATE proc_ack_claims
   SET status=?,reviewed_at=UTC_TIMESTAMP(3) WHERE id=? AND status='AWAITING_INTERNAL_REVIEW'`,
   [decision.decision,req.params.id]);
  await audit(conn,actor,'ACK_CLAIM',req.params.id,
   decision.decision==='ATTESTED_INTERNAL'?'CLAIM_ATTESTED':'CLAIM_DISPUTED',
   {claimSha256:claim.claimSha256,decisionId:id,reviewEvidenceRef:decision.reviewEvidenceRef});
  await conn.commit();
  res.status(201).json({id,claimId:req.params.id,status:decision.decision,
   realSupplierVerified:false,externalPoIssued:false,supplierAcknowledged:false,
   message:'Independent INTERNAL evidence claim review; no proof of source authentication or real supplier acknowledgment.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/grn-packs',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.claim_id AS claimId,
   p.observation_id AS observationId,p.status,p.pack_sha256 AS packSha256,
   p.prepared_by AS preparedBy,p.created_at AS createdAt
   FROM inv_grn_reconciliation_packs p WHERE p.prepared_by<>?
   ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,officialGrnAvailable:false,stockPostingEnabled:false});
 }catch(e){fail(res,e);}
});
router.get('/grn-packs/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid GRN pack ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,claim_id AS claimId,
   observation_id AS observationId,pack_sha256 AS packSha256,
   pack_json AS packJson,status FROM inv_grn_reconciliation_packs
   WHERE id=? AND prepared_by<>?`,[req.params.id,res.locals.auth.userId]);
  if(!rows.length){res.status(404).json({error:'GRN pack not found'});return;}
  const row=rows[0];
  res.json({pack:{id:row.id,status:row.status,claimId:row.claimId,
   observationId:row.observationId},snapshot:row.packJson,recordedSha256:row.packSha256,
   claimedSupplierAckOnly:true,officialGrnCreated:false,availableToSell:null});
 }catch(e){fail(res,e);}
});
router.post('/grn-packs/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid GRN pack ID'});return;}
 let input:ReturnType<typeof validatePackDecision>;
 try{input=validatePackDecision(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await conn.query<RowDataPacket[]>(`SELECT p.id,p.claim_id AS claimId,
   p.observation_id AS observationId,p.prepared_by AS preparedBy,
   p.pack_sha256 AS packSha256,p.pack_json AS packJson,p.status,
   c.preparation_id AS preparationId
   FROM inv_grn_reconciliation_packs p
   JOIN proc_ack_claims c ON c.id=p.claim_id WHERE p.id=?`,[req.params.id]);
  if(!rows.length||rows[0].preparedBy===actor){
   await conn.rollback();res.status(404).json({error:'GRN pack unavailable to independent reviewer'});return;
  }
  const source=await checkHeldSource(conn,rows[0].preparationId);
  const [locked]=await conn.query<RowDataPacket[]>(
   'SELECT status,pack_sha256 AS packSha256,pack_json AS packJson FROM inv_grn_reconciliation_packs WHERE id=? FOR UPDATE',
   [req.params.id]);
  if(locked.length!==1||locked[0].status!=='AWAITING_INTERNAL_REVIEW')
   throw new ChainConflictError('GRN evidence decision already recorded');
  if(source.ownerId!==rows[0].preparedBy||source.ownerId===actor)
   throw new ChainConflictError('GRN preparer and independent reviewer mismatch');
  const claim=await checkClaim(conn,rows[0].claimId,source);
  await checkInternallyAttestedClaim(conn,claim);
  const quarantine=await checkQuarantine(conn,rows[0].observationId,source);
  const expected=makePack(source,claim,quarantine);
  verifyPersistedPack(locked[0].packJson,locked[0].packSha256,expected);
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_grn_reconciliation_decisions
   (id,pack_id,reviewer_id,decision,reason,review_evidence_ref,custody_inspected)
   VALUES(?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,input.decision,input.reason,
    input.reviewEvidenceRef,input.custodyInspected]);
  await conn.execute(`UPDATE inv_grn_reconciliation_packs
   SET status=?,reviewed_at=UTC_TIMESTAMP(3)
   WHERE id=? AND status='AWAITING_INTERNAL_REVIEW'`,[input.decision,req.params.id]);
  if(input.decision==='HELD_INTERNAL'){
   const snapshot=heldGrnSnapshot(req.params.id,locked[0].packSha256,id);
   await conn.execute(`INSERT INTO inv_grn_held_records
    (id,pack_id,decision_id,snapshot_sha256,snapshot_json) VALUES (?,?,?,?,?)`,
    [randomUUID(),req.params.id,id,sha(JSON.stringify(snapshot)),JSON.stringify(snapshot)]);
  }
  await audit(conn,actor,'GRN_PACK',req.params.id,
   input.decision==='HELD_INTERNAL'?'PACK_HELD':'PACK_REJECTED',
   {packSha256:locked[0].packSha256,decisionId:id,
    reviewEvidenceRef:input.reviewEvidenceRef,custodyInspected:input.custodyInspected});
  await conn.commit();
  res.status(201).json({id,packId:req.params.id,status:input.decision,
   heldRecordCreated:input.decision==='HELD_INTERNAL',
   officialGrnCreated:false,realSupplierAcknowledgmentVerified:false,
   stockPostingState:'DISABLED',availableToSell:null,stockPosted:false,
   message:'Reviewed internal reconciliation HELD only; no accepted supplier-issued PO, external GRN, stock issue or inventory availability.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
