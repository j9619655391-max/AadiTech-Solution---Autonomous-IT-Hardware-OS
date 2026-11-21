import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ensureId,reviewBody,ChainInputError,ChainConflictError} from './validation';
import {readNomination,readPolicy,readDossier} from './integrity';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
   ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'Independent review remains HELD or conflicting'});return;}
 console.error('Provider selection reviewer error',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Provider selection review unavailable'});
}
router.get('/nominations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT n.id,n.provider_code AS providerCode,
   n.legal_name AS legalName,n.regulatory_source_url AS officialUrl,
   n.opened_by AS openedBy,n.status,n.nomination_ticket AS evidenceRef,
   r.decision AS reviewed FROM inv_provider_named_nominations n
   LEFT JOIN inv_provider_named_reviews r ON r.nomination_id=n.id
   WHERE n.opened_by<>? ORDER BY n.created_at DESC LIMIT 100`,
  [res.locals.auth.userId]);
  res.json({items,authorizedProviderCount:0,productionReady:false});
 }catch(e){fail(res,e);}
});
router.post('/nominations/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof reviewBody>;
 try{id=ensureId(req.params.id);
  v=reviewBody(req.body,'REVIEWED_CANDIDATE_HELD',
   ['officialListingInspected','contractMissingAcknowledged']);
 }catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const reviewer=String(res.locals.auth.userId),nom=await readNomination(c,id,false);
  if(nom.owner===reviewer){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  const [old]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_provider_named_reviews
   WHERE nomination_id=? FOR UPDATE`,[id]);
  if(old.length)throw new ChainConflictError('Nomination already independently decided');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_named_reviews
   (id,nomination_id,reviewer_id,decision,reason,evidence_ref,
   official_listing_inspected,contract_missing_acknowledged)
   VALUES(?,?,?,?,?,?,?,?)`,[reviewId,id,reviewer,v.decision,v.reason,
    v.evidenceRef,...v.flags]);
  if(v.decision==='REJECTED_INTERNAL')await c.execute(`UPDATE inv_provider_named_nominations
    SET status='REJECTED_INTERNAL' WHERE id=? AND status='NOMINATED_HELD'`,[id]);
  await c.commit();res.status(201).json({reviewId,status:v.decision,
   actualProviderAuthorization:false,providerContractApproved:false,
   approvedSandboxCredentials:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/policies',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT p.id,p.nomination_id AS nominationId,
   p.cert_id AS certId,p.prepared_by AS preparedBy,p.policy_oid AS policyOid,
   p.cps_sha256 AS cpsSha256,p.purpose,p.status,r.decision AS reviewed
   FROM inv_provider_policy_proposals p
   LEFT JOIN inv_provider_policy_reviews r ON r.policy_id=p.id
   WHERE p.prepared_by<>? ORDER BY p.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items,fullPkiPolicyVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/policies/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof reviewBody>;
 try{id=ensureId(req.params.id);
  v=reviewBody(req.body,'REVIEWED_POLICY_HELD',
   ['policyOidInspected','missingCrlOcspAcknowledged']);
 }catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const reviewer=String(res.locals.auth.userId),policy=await readPolicy(c,id);
  if(policy.preparedBy===reviewer){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  const [old]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_provider_policy_reviews
   WHERE policy_id=? FOR UPDATE`,[id]);
  if(old.length)throw new ChainConflictError('Policy already independently decided');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_policy_reviews
   (id,policy_id,reviewer_id,decision,reason,evidence_ref,
   policy_oid_inspected,missing_crl_ocsp_acknowledged)
   VALUES(?,?,?,?,?,?,?,?)`,[reviewId,id,reviewer,v.decision,v.reason,
    v.evidenceRef,...v.flags]);
  await c.commit();res.status(201).json({reviewId,status:v.decision,
   localOpenSslPolicyMathMatched:policy.trial.oneHopOpenSslPolicyTrialMatched,
   fullProductionPkixValidated:false,certificateRevocationTrusted:false,
   independentProviderApproved:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/dossiers',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT d.id,d.nomination_id AS nominationId,
   d.sandbox_case_id AS sandboxCaseId,d.prepared_by AS preparedBy,
   d.registry_reference AS registryReference,d.registry_source_url AS sourceUrl,
   d.company_master_data_sha256 AS masterSha,d.signatory_delegation_sha256 AS delegationSha,
   d.status,r.decision AS reviewed
   FROM inv_provider_registry_dossiers d
   LEFT JOIN inv_provider_registry_reviews r ON r.dossier_id=d.id
   WHERE d.prepared_by<>? ORDER BY d.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items,independentlyVerifiedRegistryCount:0});
 }catch(e){fail(res,e);}
});
router.post('/dossiers/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,v:ReturnType<typeof reviewBody>;
 try{id=ensureId(req.params.id);
  v=reviewBody(req.body,'REVIEWED_CLAIM_HELD',
   ['registrySourceInspected','delegationSourceInspected']);
 }catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const reviewer=String(res.locals.auth.userId),dossier=await readDossier(c,id);
  if(dossier.preparedBy===reviewer){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  const [old]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_provider_registry_reviews
   WHERE dossier_id=? FOR UPDATE`,[id]);
  if(old.length)throw new ChainConflictError('Registry dossier already reviewed');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_registry_reviews
   (id,dossier_id,reviewer_id,decision,reason,evidence_ref,
   registry_source_inspected,delegation_source_inspected)
   VALUES(?,?,?,?,?,?,?,?)`,[reviewId,id,reviewer,v.decision,v.reason,
    v.evidenceRef,...v.flags]);
  if(v.decision==='REVIEWED_CLAIM_HELD')
   await c.execute(`UPDATE inv_provider_registry_dossiers
    SET status='INTERNALLY_INSPECTED_HELD'
    WHERE id=? AND status='EVIDENCE_PENDING_EXTERNAL'`,[id]);
  await c.commit();res.status(201).json({reviewId,status:v.decision,
   officialMcaIdentityAuthenticated:false,legallyApprovedSignatory:false,
   productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
export default router;
