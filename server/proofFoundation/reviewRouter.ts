import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {readCandidate,readVerifiedClaim} from './integrity';
import {activeSensitiveReviewerScope} from '../security/sensitiveReviewScope';
import {validateKeyReview,validateClaimReview,proofHoldSnapshot,
 ChainInputError,ChainConflictError} from './validation';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Independent offline proof review rejects altered or unverified source'});return;
 }
 console.error('Offline proof reviewer failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Offline proof reviewer service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'KEY'|'CLAIM',
 id:string,event:'KEY_REVIEWED'|'KEY_REJECTED'|'CLAIM_CRYPTO_REVIEWED'|'CLAIM_REJECTED',
 details:object){
 await c.execute(`INSERT INTO inv_signed_proof_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256) VALUES (?,?,?,?,?,?)`,
  [randomUUID(),actor,type,id,event,sha(JSON.stringify(details))]);
}
router.get('/keys',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT k.id,k.party_kind AS partyKind,
   k.supplier_id AS supplierId,k.site_id AS siteId,
   k.fingerprint_sha256 AS fingerprintSha256,
   k.registered_by AS registeredBy,k.evidence_ref AS evidenceRef,k.status
   FROM inv_proof_key_candidates k
   LEFT JOIN proc_suppliers supplier ON supplier.id=k.supplier_id
   LEFT JOIN inventory_sites site ON site.id=k.site_id
   WHERE k.registered_by<>?
     AND ((k.party_kind='SUPPLIER' AND supplier.created_by=k.registered_by)
       OR (k.party_kind='WAREHOUSE' AND site.created_by=k.registered_by))
     AND EXISTS (SELECT 1 FROM app_reviewer_scope_grants g
      WHERE g.owner_user_id=k.registered_by AND g.reviewer_user_id=?
       AND g.workflow_scope='PROOF' AND g.state='ACTIVE')
   ORDER BY k.created_at DESC,k.id DESC LIMIT 100`,
   [res.locals.auth.userId,res.locals.auth.userId]);
  res.json({items:rows,externalIdentityAuthenticated:false,trustAnchorVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/keys/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid key ID'});return;}
 let data:ReturnType<typeof validateKeyReview>;
 try{data=validateKeyReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const key=await readCandidate(conn,req.params.id,false);
  if(key.registeredBy===actor||
     !await activeSensitiveReviewerScope(conn,key.registeredBy,actor,'PROOF',true)){
   await conn.rollback();res.status(404).json({error:'Key unavailable to reviewer'});return;
  }
  if(key.status!=='PENDING_INTERNAL')throw new ChainConflictError('Key already internally reviewed');
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_proof_key_reviews
   (id,key_id,reviewer_id,decision,reason,evidence_ref,document_inspected)
   VALUES(?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,data.decision,data.reason,data.evidenceRef,data.documentInspected]);
  await conn.execute(`UPDATE inv_proof_key_candidates
   SET status=?,reviewed_at=UTC_TIMESTAMP(3) WHERE id=? AND status='PENDING_INTERNAL'`,
   [data.decision,req.params.id]);
  await audit(conn,actor,'KEY',req.params.id,
   data.decision==='REVIEWED_UNTRUSTED'?'KEY_REVIEWED':'KEY_REJECTED',
   {fingerprint:key.fingerprint,decision:data.decision,evidenceRef:data.evidenceRef});
  await conn.commit();
  res.status(201).json({reviewId:id,keyId:req.params.id,status:data.decision,
   externalKeyOwnershipVerified:false,cryptographicTrustAnchorEstablished:false,
   message:'Independent INTERNAL key-format review only. Supplier/warehouse key ownership unverified.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/claims',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT c.id,c.claim_kind AS kind,
   c.key_id AS keyId,c.created_by AS createdBy,
   c.dispatch_preparation_id AS preparationId,c.held_grn_id AS heldGrnId,
   c.message_sha256 AS messageSha256,c.signature_matched AS signatureMatched,c.status
   FROM inv_signed_proof_claims c
   JOIN inv_proof_key_candidates k ON k.id=c.key_id
   LEFT JOIN proc_dispatch_preparations prep ON prep.id=c.dispatch_preparation_id
   LEFT JOIN inv_grn_held_records grn ON grn.id=c.held_grn_id
   LEFT JOIN inv_grn_reconciliation_packs pack ON pack.id=grn.pack_id
   WHERE c.created_by<>? AND k.registered_by=c.created_by
    AND ((c.claim_kind='WAREHOUSE_GRN_ASSERTION' AND pack.prepared_by=c.created_by)
     OR (c.claim_kind IN ('PO_ISSUANCE_ASSERTION','SUPPLIER_ACK_ASSERTION')
       AND prep.prepared_by=c.created_by))
    AND EXISTS (SELECT 1 FROM app_reviewer_scope_grants g
      WHERE g.owner_user_id=c.created_by AND g.reviewer_user_id=?
       AND g.workflow_scope='PROOF' AND g.state='ACTIVE')
   ORDER BY c.created_at DESC,c.id DESC LIMIT 100`,
   [res.locals.auth.userId,res.locals.auth.userId]);
  res.json({items:rows,validSignaturesAreNotVerifiedIdentity:true});
 }catch(e){fail(res,e);}
});
router.get('/claims/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid signed claim ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const state=await readVerifiedClaim(conn,req.params.id);
  if(state.ownerId===res.locals.auth.userId||
    !await activeSensitiveReviewerScope(conn,state.ownerId,
      String(res.locals.auth.userId),'PROOF')){
   await conn.rollback();res.status(404).json({error:'Claim unavailable to reviewer'});return;
  }
  await conn.commit();
  res.json({claim:{id:state.id,kind:state.kind,status:state.status},
   sourceId:state.sourceId,message:state.message,messageSha256:state.messageSha256,
   candidateKeyFingerprint:state.keyFingerprint,
   cryptographicSignatureMatched:true,externalIdentityAuthenticated:false,
   supplierIssuedPo:false,officialGrnAuthenticated:false,stockPostingEnabled:false});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.post('/claims/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid signed claim ID'});return;}
 let data:ReturnType<typeof validateClaimReview>;
 try{data=validateClaimReview(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const state=await readVerifiedClaim(conn,req.params.id);
  if(state.ownerId===actor||
    !await activeSensitiveReviewerScope(conn,state.ownerId,actor,'PROOF',true)){
   await conn.rollback();res.status(404).json({error:'Claim unavailable to reviewer'});return;
  }
  if(state.status!=='PENDING_INTERNAL')
   throw new ChainConflictError('Signed claim has existing review');
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_signed_proof_reviews
   (id,claim_id,reviewer_id,decision,reason,evidence_ref,signature_inspected)
   VALUES (?,?,?,?,?,?,?)`,
   [id,req.params.id,actor,data.decision,data.reason,data.evidenceRef,data.documentInspected]);
  await conn.execute(`UPDATE inv_signed_proof_claims
   SET status=?,reviewed_at=UTC_TIMESTAMP(3)
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,req.params.id]);
  if(data.decision==='REVIEWED_CRYPTO_ONLY'){
   const frozen=proofHoldSnapshot(req.params.id,state.messageSha256,id);
   await conn.execute(`INSERT INTO inv_signed_proof_holds
    (id,claim_id,review_id,snapshot_sha256,snapshot_json)
    VALUES(?,?,?,?,?)`,[randomUUID(),req.params.id,id,sha(JSON.stringify(frozen)),JSON.stringify(frozen)]);
  }
  await audit(conn,actor,'CLAIM',req.params.id,
   data.decision==='REVIEWED_CRYPTO_ONLY'?'CLAIM_CRYPTO_REVIEWED':'CLAIM_REJECTED',
   {messageSha256:state.messageSha256,reviewId:id,keyFingerprint:state.keyFingerprint});
  await conn.commit();
  res.status(201).json({reviewId:id,claimId:req.params.id,status:data.decision,
   cryptographicSignatureMatched:true,externalKeyTrusted:false,
   supplierAcknowledgmentAuthenticated:false,officialGrnAuthenticated:false,
   stockPostingState:'DISABLED',availableToSell:null,
   message:'Signature mathematically matched an internally registered key. Identity, provenance and stock authority remain UNVERIFIED.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
export default router;
