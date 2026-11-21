import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {inspectIssuer,inspectAuthority} from './integrity';
import {validateReview,ChainInputError,ChainConflictError,digest} from './validation';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||
  (e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Issuer/authority review contradicts signed or independently checked source'});return;
 }
 console.error('External trust independent reviewer error',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'External trust reviewer unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'ISSUER'|'AUTHORITY',id:string,
 event:'ISSUER_REVIEWED'|'ISSUER_REJECTED'|'AUTHORITY_REVIEWED'|'AUTHORITY_REJECTED',
 detail:object){
 await c.execute(`INSERT INTO inv_external_trust_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256)
  VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,event,digest(detail)]);
}
router.get('/issuers',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT i.id,i.party_kind AS partyKind,
   i.party_id AS partyId,i.registered_by AS registeredBy,
   i.fingerprint_sha256 AS fingerprint,
   i.organization_registration AS organizationRegistration,
   i.evidence_ref AS evidenceRef,i.status,
   i.external_root_state AS externalRootState,f.issuer_id AS frozen
   FROM inv_external_issuer_candidates i
   LEFT JOIN inv_external_issuer_freezes f ON f.issuer_id=i.id
   WHERE i.registered_by<>? ORDER BY i.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externallyAuthenticatedIssuerCount:0});
 }catch(e){fail(res,e);}
});
router.post('/issuers/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid issuer ID'});return;}
 let data:ReturnType<typeof validateReview>;
 try{data=validateReview(req.body,'REVIEWED_HELD');}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const issuer=await inspectIssuer(c,req.params.id,false);
  if(issuer.registeredBy===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(issuer.status!=='PENDING_INTERNAL')throw new ChainConflictError('Issuer already reviewed');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_external_issuer_reviews
   (id,issuer_id,reviewer_id,decision,reason,evidence_ref,registry_inspected)
   VALUES(?,?,?,?,?,?,?)`,[id,req.params.id,actor,data.decision,
    data.reason,data.evidenceRef,data.evidenceInspected]);
  await c.execute(`UPDATE inv_external_issuer_candidates SET status=?
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,req.params.id]);
  await audit(c,actor,'ISSUER',req.params.id,
   data.decision==='REVIEWED_HELD'?'ISSUER_REVIEWED':'ISSUER_REJECTED',
   {issuerFingerprint:issuer.fingerprint,decision:data.decision,reviewId:id});
  await c.commit();
  res.status(201).json({id,issuerId:req.params.id,status:data.decision,
   issuerIdentityExternallyVerified:false,organizationAuthorityVerified:false,
   stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/attestations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT a.id,a.issuer_id AS issuerId,
   a.key_id AS keyId,a.prepared_by AS preparedBy,a.purpose,
   a.statement_sha256 AS digest,a.status,
   a.external_authority_state AS externalAuthorityState
   FROM inv_external_authority_attestations a WHERE a.prepared_by<>?
   ORDER BY a.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,legalAuthorityVerified:false,officialGrnAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.get('/attestations/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid attestation ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const a=await inspectAuthority(c,req.params.id);
  if(a.issuer.registeredBy===res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  await c.commit();
  res.json({id:a.id,status:a.status,issuerFingerprint:a.issuer.fingerprint,
   candidateKeyFingerprint:a.key.fingerprint,statement:a.message,digest:a.digest,
   signatureMathematicallyMatched:true,externalIssuerAuthenticated:false,
   organizationAuthorityVerified:false,officialGrnAuthenticated:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/attestations/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid attestation ID'});return;}
 let data:ReturnType<typeof validateReview>;
 try{data=validateReview(req.body,'REVIEWED_CRYPTO_HELD');}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),a=await inspectAuthority(c,req.params.id);
  if(a.issuer.registeredBy===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(a.status!=='PENDING_INTERNAL')
   throw new ChainConflictError('Attestation already independently reviewed');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_external_authority_reviews
   (id,attestation_id,reviewer_id,decision,reason,evidence_ref,signature_inspected)
   VALUES(?,?,?,?,?,?,?)`,[id,req.params.id,actor,data.decision,
    data.reason,data.evidenceRef,data.evidenceInspected]);
  await c.execute(`UPDATE inv_external_authority_attestations SET status=?
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,req.params.id]);
  await audit(c,actor,'AUTHORITY',req.params.id,
   data.decision==='REVIEWED_CRYPTO_HELD'?'AUTHORITY_REVIEWED':'AUTHORITY_REJECTED',
   {digest:a.digest,decision:data.decision,reviewId:id});
  await c.commit();
  res.status(201).json({id,attestationId:req.params.id,status:data.decision,
   internalSignatureInspected:true,externallyVerifiedOrganization:false,
   actualPoIssued:false,officialGrnAuthenticated:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
export default router;
