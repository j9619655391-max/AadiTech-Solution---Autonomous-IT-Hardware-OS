import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {packetReviewBody,artifactReviewBody,mcaReviewBody,ChainInputError,
 ChainConflictError,ensureId} from './validation';
import {readPacket,readArtifact,readMca} from './integrity';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
  ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'Independent missing external authority acknowledgement required'});return;}
 console.error('Phase1AO reviewer verification unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Independent sandbox reviewer unavailable'});
}
async function tx(res:Response,fn:(c:PoolConnection,reviewer:string)=>Promise<{
  reviewId:string;status:string;productionReady:boolean}>){
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const value=await fn(c,String(res.locals.auth.userId));
  await c.commit();res.status(201).json(value);
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
}
router.get('/packets',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT p.id,p.nomination_id AS nominationId,
   p.prepared_by AS owner,p.contract_document_sha256 AS contractDigest,
   p.provider_onboarding_ref AS onboardingRef,p.status,
   (SELECT COUNT(*) FROM inv_provider_ao_packet_reviews r WHERE r.packet_id=p.id) AS reviewCount
   FROM inv_provider_ao_packets p WHERE p.prepared_by<>?
   ORDER BY p.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,providerContractAuthenticated:false,approvedCredentialsPresent:false});
 }catch(e){fail(res,e);}
});
router.post('/packets/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof packetReviewBody>;
 try{id=ensureId(req.params.id);v=packetReviewBody(req.body);}catch(e){fail(res,e);return;}
 await tx(res,async(c,reviewer)=>{
  const packet=await readPacket(c,id);
  if(packet.owner===reviewer)throw new ChainConflictError('Owner cannot self-review');
  if(packet.status!=='PENDING_INTERNAL')throw new ChainConflictError('Already completed or rejected');
  const [existing]=await c.query<RowDataPacket[]>(`SELECT review_role AS role,reviewer_id AS actor
   FROM inv_provider_ao_packet_reviews WHERE packet_id=? FOR UPDATE`,[id]);
  if(existing.some(x=>x.role===v.reviewRole||x.actor===reviewer))
   throw new ChainConflictError('LEGAL and SECURITY reviewers must be distinct and single-use');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_packet_reviews
   (id,packet_id,reviewer_id,review_role,decision,reason,evidence_ref,
    no_external_contract_ack,no_live_credentials_ack)
   VALUES(?,?,?,?,?,?,?,?,?)`,
   [reviewId,id,reviewer,v.reviewRole,v.decision,v.reason,v.evidenceRef,...v.flags]);
  if(v.decision==='REJECTED_INTERNAL')await c.execute(`UPDATE inv_provider_ao_packets
    SET status='REJECTED_INTERNAL' WHERE id=? AND status='PENDING_INTERNAL'`,[id]);
  else if(existing.length===1)await c.execute(`UPDATE inv_provider_ao_packets
    SET status='DUAL_REVIEWED_HELD' WHERE id=? AND status='PENDING_INTERNAL'`,[id]);
  return {reviewId,status:v.decision,productionReady:false};
 });
});
router.get('/revocations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT a.id,a.trial_id AS trialId,
   a.artifact_type AS artifactType,a.artifact_sha256 AS sha256,
   a.imported_by AS owner,v.decision AS reviewDecision
   FROM inv_provider_ao_revocation_trials a
   LEFT JOIN inv_provider_ao_revocation_reviews v ON v.artifact_id=a.id
   WHERE a.imported_by<>? ORDER BY a.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items,actualPublisherAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/revocations/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof artifactReviewBody>;
 try{id=ensureId(req.params.id);v=artifactReviewBody(req.body);}catch(e){fail(res,e);return;}
 await tx(res,async(c,reviewer)=>{
  const artifact=await readArtifact(c,id);
  if(artifact.trial.packet.owner===reviewer)throw new ChainConflictError('Independent reviewer required');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_provider_ao_revocation_reviews
   WHERE artifact_id=? FOR UPDATE`,[id]);
  if(old.length)throw new ChainConflictError('Immutable revocation decision already exists');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_revocation_reviews
   (id,artifact_id,reviewer_id,decision,reason,evidence_ref,issuer_provenance_missing_ack)
   VALUES(?,?,?,?,?,?,?)`,[reviewId,id,reviewer,v.decision,v.reason,v.evidenceRef,v.flags[0]]);
  return {reviewId,status:v.decision,productionReady:false};
 });
});
router.get('/mca-evidence',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT m.id,m.packet_id AS packetId,
   m.dossier_id AS dossierId,m.prepared_by AS owner,
   m.mca_master_data_sha256 AS mcaDigest,m.signatory_mandate_sha256 AS signerDigest,
   m.status,r.decision AS reviewDecision FROM inv_provider_ao_mca_evidence m
   LEFT JOIN inv_provider_ao_mca_reviews r ON r.mca_id=m.id
   WHERE m.prepared_by<>? ORDER BY m.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items,realRegistryOrSignatoryVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/mca-evidence/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof mcaReviewBody>;
 try{id=ensureId(req.params.id);v=mcaReviewBody(req.body);}catch(e){fail(res,e);return;}
 await tx(res,async(c,reviewer)=>{
  const mca=await readMca(c,id);
  if(mca.preparedBy===reviewer)throw new ChainConflictError('Independent reviewer required');
  if(mca.status!=='PENDING_EXTERNAL')throw new ChainConflictError('Already reviewed');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_provider_ao_mca_reviews
   WHERE mca_id=? FOR UPDATE`,[id]);
  if(old.length)throw new ChainConflictError('Immutable MCA review exists');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_mca_reviews
   (id,mca_id,reviewer_id,decision,reason,evidence_ref,
    external_mca_auth_missing_ack,signatory_auth_missing_ack)
   VALUES(?,?,?,?,?,?,?,?)`,[reviewId,id,reviewer,v.decision,v.reason,v.evidenceRef,...v.flags]);
  if(v.decision==='INSPECTED_HELD')
   await c.execute(`UPDATE inv_provider_ao_mca_evidence
    SET status='INTERNALLY_INSPECTED_HELD' WHERE id=? AND status='PENDING_EXTERNAL'`,[id]);
  return {reviewId,status:v.decision,productionReady:false};
 });
});
export default router;
