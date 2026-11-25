import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {readCert,readCase} from '../providerSandbox/integrity';
import {readNomination,readiness} from './integrity';
import {PROVIDER,RELEASE_BLOCKERS,nominationBody,policyBody,dossierBody,accessBody,
 inspectLocalPolicyDryRun,sha,ChainInputError,ChainConflictError,ensureId} from './validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
  ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'Named provider nomination, policy or registry claim remains unapproved/HELD'});return;}
 console.error('Named provider due diligence owner error',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Provider due diligence unavailable'});
}
async function audit(c:PoolConnection,actor:string,code:string,entity:string,detail:object){
 // Reuse the existing actor/SHA-only evidence audit to avoid a parallel
 // trusted audit authority; all events remain internal, not public notarization.
 await c.execute(`INSERT INTO inv_provider_audit
 (id,actor_id,entity_type,entity_id,action,event_sha256)
 VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,'PIN',entity,'PIN_CANDIDATE_RECORDED',
  sha(JSON.stringify({phase:'1AN',code,...detail}))]);
}
router.get('/candidate',(_req,res)=>res.json({
 provider:PROVIDER,nominationOnly:true,sandboxCredentialState:'NOT_PROVIDED',
 providerContractApproved:false,rootExternallyAuthenticated:false,
 officialSourceNeedsIndependentVerification:true,productionReady:false,
 blockers:RELEASE_BLOCKERS}));
router.get('/nominations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT n.id,n.provider_code AS providerCode,
   n.legal_name AS legalName,n.status,n.provider_contract AS contractState,
   n.sandbox_credentials AS credentialsState,n.production_release AS releaseState,
   r.decision AS reviewDecision FROM inv_provider_named_nominations n
   LEFT JOIN inv_provider_named_reviews r ON r.nomination_id=n.id
   WHERE n.opened_by=? ORDER BY n.created_at DESC LIMIT 50`,[res.locals.auth.userId]);
  res.json({items,approvedForUse:false,realSandboxCredentials:false});
 }catch(e){fail(res,e);}
});
router.post('/nominations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof nominationBody>;
 try{v=nominationBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id,opened_by AS owner,
   nomination_ticket AS ticket,status FROM inv_provider_named_nominations
   WHERE provider_code=? FOR UPDATE`,[v.providerCode]);
  if(prior.length){
   if(prior[0].owner!==actor||prior[0].ticket!==v.nominationTicket)
    throw new ChainConflictError('Named candidate already nominated with different immutable source');
   await c.commit();res.status(200).json({id:prior[0].id,status:prior[0].status,
    replayed:true,externallyApproved:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_named_nominations
   (id,provider_code,legal_name,regulatory_source_url,opened_by,nomination_ticket)
   VALUES(?,?,?,?,?,?)`,[id,PROVIDER.code,PROVIDER.legalName,
    PROVIDER.authorityUrl,actor,v.nominationTicket]);
  await c.commit();res.status(201).json({id,status:'NOMINATED_HELD',
   approvedContract:false,credentialsConfigured:false,
   regulatoryListingIsNotBusinessUseAuthorization:true});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.post('/access-requests',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof accessBody>;
 try{v=accessBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),nom=await readNomination(c,v.nominationId);
  if(nom.owner!==actor)throw new ChainConflictError('Owner does not control nomination');
  const [old]=await c.query<RowDataPacket[]>(`SELECT access_request_ticket AS ticket
   FROM inv_provider_sandbox_access_gates WHERE nomination_id=? FOR UPDATE`,[nom.id]);
  if(old.length){
   if(old[0].ticket!==v.requestTicket)throw new ChainConflictError('Access request already frozen');
   await c.commit();res.status(200).json({nominationId:nom.id,
    status:'WAITING_EXTERNAL',replayed:true,liveSandboxAccess:false});return;
  }
  await c.execute(`INSERT INTO inv_provider_sandbox_access_gates
   (nomination_id,requested_by,access_request_ticket) VALUES(?,?,?)`,
   [nom.id,actor,v.requestTicket]);
  await c.commit();res.status(201).json({nominationId:nom.id,
   status:'WAITING_EXTERNAL',credentialSecretStored:false,
   actualProviderAuthorization:false,liveSandboxAccess:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/policies',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT id,nomination_id AS nominationId,
   cert_id AS certId,policy_oid AS policyOid,cps_sha256 AS cpsSha256,purpose,
   status,provider_policy_approved AS approved FROM inv_provider_policy_proposals
   WHERE prepared_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,providerPolicyActuallyApproved:false,fullPkiPathValidated:false});
 }catch(e){fail(res,e);}
});
router.post('/policies',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof policyBody>;
 try{v=policyBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),nom=await readNomination(c,v.nominationId),
   cert=await readCert(c,v.certId,true);
  if(nom.owner!==actor||cert.importedBy!==actor||cert.caseData.purpose!==v.purpose)
   throw new ChainConflictError('Original certificate and provider nomination mismatch');
  const [raw]=await c.query<RowDataPacket[]>(`SELECT ca_certificate_pem AS caPem,
   leaf_certificate_pem AS leafPem FROM inv_sandbox_cert_packages
   WHERE id=? FOR UPDATE`,[v.certId]);
  if(raw.length!==1)throw new ChainConflictError('Source certificate missing');
  inspectLocalPolicyDryRun(String(raw[0].caPem),String(raw[0].leafPem),v.policyOid);
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,policy_oid AS oid,cps_sha256 AS cps,
   purpose FROM inv_provider_policy_proposals
   WHERE nomination_id=? AND cert_id=? FOR UPDATE`,[nom.id,cert.id]);
  if(old.length){
   if(old[0].oid!==v.policyOid||old[0].cps!==v.cpsSha256||old[0].purpose!==v.purpose)
    throw new ChainConflictError('Immutable policy proposal conflicts with existing');
   await c.commit();res.status(200).json({id:old[0].id,replayed:true,status:'PROFILE_HELD',
    productionApproved:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_policy_proposals
  (id,nomination_id,cert_id,prepared_by,policy_oid,cps_sha256,cps_source_url,purpose)
  VALUES(?,?,?,?,?,?,?,?)`,[id,nom.id,cert.id,actor,
   v.policyOid,v.cpsSha256,PROVIDER.cpsUrl,v.purpose]);
  await c.commit();res.status(201).json({id,status:'PROFILE_HELD',
   opensslOneHopPolicyMathMatched:true,trustedCrlOcspVerified:false,
   fullPathProviderApproved:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/dossiers',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT id,nomination_id AS nominationId,
   sandbox_case_id AS sandboxCaseId,registry_reference AS registryReference,
   company_master_data_sha256 AS companyMasterDataSha256,
   signatory_delegation_sha256 AS signatoryDelegationSha256,status,
   registry_authentication AS registryState,
   legal_signatory_authentication AS signatoryState FROM inv_provider_registry_dossiers
   WHERE prepared_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,legalKycVerified:false,signatoryVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/dossiers',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof dossierBody>;
 try{v=dossierBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),nom=await readNomination(c,v.nominationId),
   record=await readCase(c,v.sandboxCaseId,true);
  if(nom.owner!==actor||record.openedBy!==actor||
   record.registryReference!==v.registryReference)
   throw new ChainConflictError('Company registry evidence does not match original held case');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,company_master_data_sha256 AS masterSha,
   signatory_delegation_sha256 AS delegationSha,source_evidence_ref AS evidence
   FROM inv_provider_registry_dossiers
   WHERE nomination_id=? AND sandbox_case_id=? FOR UPDATE`,[nom.id,record.id]);
  if(old.length){
   if(old[0].masterSha!==v.companyMasterDataSha256||
    old[0].delegationSha!==v.signatoryDelegationSha256||
    old[0].evidence!==v.sourceEvidenceRef)
    throw new ChainConflictError('Immutable legal-identity dossier cannot be silently replaced');
   await c.commit();res.status(200).json({id:old[0].id,replayed:true,
    legalRegistryVerified:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_registry_dossiers
  (id,nomination_id,sandbox_case_id,prepared_by,registry_source_url,
  company_master_data_sha256,signatory_delegation_sha256,registry_reference,source_evidence_ref)
  VALUES(?,?,?,?,?,?,?,?,?)`,[id,nom.id,record.id,actor,PROVIDER.registryUrl,
   v.companyMasterDataSha256,v.signatoryDelegationSha256,
   v.registryReference,v.sourceEvidenceRef]);
  await c.commit();res.status(201).json({id,status:'EVIDENCE_PENDING_EXTERNAL',
   mcaRegistryAuthenticated:false,legalSignatoryVerified:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/readiness',async(req,res)=>{
 let policyId:string,dossierId:string;
 try{policyId=ensureId(req.query.policyId);dossierId=ensureId(req.query.dossierId);}
 catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const [mine]=await c.query<RowDataPacket[]>(`SELECT prepared_by AS owner
   FROM inv_provider_policy_proposals WHERE id=?`,[policyId]);
  if(mine.length!==1||mine[0].owner!==res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Policy not available'});return;
  }
  const data=await readiness(c,policyId,dossierId);
  await c.commit();res.json(data);
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/authority',(_req,res)=>res.json({provider:PROVIDER.legalName,
 namedEvaluationCandidate:true,providerContractApproved:false,
 approvedSandboxCredentialsPresent:false,independentlyVerifiedCompany:false,
 authorizedSignatoryAuthenticated:false,fullCertificateChainAndRevocationVerified:false,
 realSupplierPoAck:false,officialGrnVerified:false,stockPostingEnabled:false,
 productionReady:false,blockers:RELEASE_BLOCKERS}));
export default router;
