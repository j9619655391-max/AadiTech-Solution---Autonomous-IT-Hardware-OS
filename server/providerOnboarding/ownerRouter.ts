import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {readNomination,readPolicy,readDossier} from '../providerSelection/integrity';
import {sandboxReadiness} from '../providerSandbox/integrity';
import {readPacket,readTrial,readMca,readiness} from './integrity';
import {packetBody,trialBody,revocationBody,mcaBody,offlineSignedRevocationCheck,
 AO_BLOCKERS,CCA_CURRENT_CPS_REFERENCE,
 ChainInputError,ChainConflictError,ensureId} from './validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
  ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'External provider identity, credential or evidence remains HELD/unverified'});return;}
 console.error('Phase1AO owner proof unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Sandbox provider prerequisite service unavailable'});
}
async function transactional(res:Response,op:(c:PoolConnection,owner:string)=>Promise<void>){
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  await op(c,String(res.locals.auth.userId));
  await c.commit();
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
}
router.get('/requirements',(_req,res)=>res.json({
 provider:'eMudhra Limited',ccaCpsReference:CCA_CURRENT_CPS_REFERENCE,
 providerAgreementApproved:false,approvedSandboxCredentialsPresent:false,
 externalMcaRegistryVerified:false,authorizedSignatoryVerified:false,
 authenticatedProductionCrlOcsp:false,officialGrnVerified:false,
 productionReady:false,blockers:AO_BLOCKERS}));
router.get('/packets',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT id,nomination_id AS nominationId,
   contract_document_sha256 AS contractDigest,provider_onboarding_ref AS onboardingRef,
   sandbox_scope_ref AS scopeRef,status,contract_authentication AS contractState,
   sandbox_secret_state AS credentialState FROM inv_provider_ao_packets
   WHERE prepared_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,providerActuallyApproved:false});
 }catch(e){fail(res,e);}
});
router.post('/packets',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof packetBody>;try{v=packetBody(req.body);}catch(e){fail(res,e);return;}
 await transactional(res,async(c,owner)=>{
  const nom=await readNomination(c,v.nominationId,true);
  if(nom.owner!==owner)throw new ChainConflictError('Nomination owner mismatch');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,contract_document_sha256 AS hash,
   provider_onboarding_ref AS ref,sandbox_scope_ref AS scope,status
   FROM inv_provider_ao_packets WHERE nomination_id=? FOR UPDATE`,[nom.id]);
  if(old.length){
   if(old[0].hash!==v.contractDocumentSha256||old[0].ref!==v.providerOnboardingRef||
    old[0].scope!==v.sandboxScopeRef)throw new ChainConflictError('Changed immutable packet');
   res.status(200).json({id:old[0].id,status:old[0].status,replayed:true,
    agreementAuthenticated:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_packets
   (id,nomination_id,prepared_by,contract_document_sha256,provider_onboarding_ref,sandbox_scope_ref)
   VALUES(?,?,?,?,?,?)`,[id,nom.id,owner,v.contractDocumentSha256,
    v.providerOnboardingRef,v.sandboxScopeRef]);
  res.status(201).json({id,status:'PENDING_INTERNAL',agreementAuthenticated:false,
   sandboxCredentialsConfigured:false,productionReady:false});
 });
});
router.get('/trials',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT id,packet_id AS packetId,
   policy_id AS policyId,requested_policy_oid AS policyOid,status,
   provider_chain_authenticated AS chainAuthenticated FROM inv_provider_ao_pkix_trials
   WHERE prepared_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,trustedProviderChainCount:0});
 }catch(e){fail(res,e);}
});
router.post('/trials',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof trialBody>;try{v=trialBody(req.body);}catch(e){fail(res,e);return;}
 await transactional(res,async(c,owner)=>{
  const packet=await readPacket(c,v.packetId,true);
  const policy=await readPolicy(c,v.policyId,true);
  if(packet.owner!==owner||packet.nom.id!==policy.nom.id||
   policy.preparedBy!==owner)throw new ChainConflictError('Provider policy scope mismatch');
  await sandboxReadiness(c,policy.cert.id); // current signed candidate feed
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,status
   FROM inv_provider_ao_pkix_trials WHERE packet_id=? AND policy_id=? FOR UPDATE`,
   [packet.id,policy.id]);
  if(old.length){res.status(200).json({id:old[0].id,status:old[0].status,
   replayed:true,realProviderChainAuthenticated:false});return;}
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_pkix_trials
   (id,packet_id,policy_id,prepared_by,requested_policy_oid,
    root_certificate_sha256,leaf_certificate_sha256) VALUES(?,?,?,?,?,?,?)`,
   [id,packet.id,policy.id,owner,policy.policyOid,
    policy.cert.crypto.rootCertSha256,policy.cert.crypto.leafCertSha256]);
  res.status(201).json({id,status:'OFFLINE_CRYPTO_HELD',
   actualTrustedIssuerAuthenticated:false,productionReady:false});
 });
});
router.get('/revocations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT r.id,r.trial_id AS trialId,
   r.artifact_type AS artifactType,r.artifact_sha256 AS sha256,r.status,
   r.external_publisher_authenticated AS publisherAuthenticated,
   v.decision AS reviewDecision FROM inv_provider_ao_revocation_trials r
   LEFT JOIN inv_provider_ao_revocation_reviews v ON v.artifact_id=r.id
   WHERE r.imported_by=? ORDER BY r.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,realCrlOcspPublisherAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/revocations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof revocationBody>;
 try{v=revocationBody(req.body);}catch(e){fail(res,e);return;}
 await transactional(res,async(c,owner)=>{
  const trial=await readTrial(c,v.trialId);
  if(trial.packet.owner!==owner)throw new ChainConflictError('Owner mismatch');
  const proof=offlineSignedRevocationCheck(v.artifactType,v.artifactDerB64,trial.root,trial.leaf);
  if(proof.artifactSha256!==v.digest)throw new ChainConflictError('DER hash mismatch');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,artifact_sha256 AS digest,status
   FROM inv_provider_ao_revocation_trials WHERE trial_id=? AND artifact_type=?
   FOR UPDATE`,[trial.id,v.artifactType]);
  if(old.length){
   if(old[0].digest!==v.digest)throw new ChainConflictError('Immutable signed artifact differs');
   res.status(200).json({id:old[0].id,status:old[0].status,replayed:true,
    externalPublisherAuthenticated:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_revocation_trials
   (id,trial_id,imported_by,artifact_type,artifact_der_b64,artifact_sha256)
   VALUES(?,?,?,?,?,?)`,[id,trial.id,owner,v.artifactType,
    v.artifactDerB64,v.digest]);
  res.status(201).json({id,status:'SIGNED_OFFLINE_HELD',artifactType:v.artifactType,
   cryptographicArtifactVerified:true,externalPublisherAuthenticated:false,
   trustedRealCertificateStatus:false,productionReady:false});
 });
});
router.get('/mca-evidence',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [items]=await db.query<RowDataPacket[]>(`SELECT id,packet_id AS packetId,
   dossier_id AS dossierId,status,registry_authenticated AS registryAuthenticated,
   signatory_authorized AS signatoryAuthenticated FROM inv_provider_ao_mca_evidence
   WHERE prepared_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items,realMcaAndSignatoryAuthority:false});
 }catch(e){fail(res,e);}
});
router.post('/mca-evidence',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let v:ReturnType<typeof mcaBody>;try{v=mcaBody(req.body);}catch(e){fail(res,e);return;}
 await transactional(res,async(c,owner)=>{
  const packet=await readPacket(c,v.packetId,true);
  const dossier=await readDossier(c,v.dossierId,true);
  if(packet.owner!==owner||dossier.preparedBy!==owner||
   packet.nom.id!==dossier.nom.id)throw new ChainConflictError('Original MCA dossier scope mismatch');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,
   mca_master_data_sha256 AS master,signatory_mandate_sha256 AS mandate,
   verification_ticket AS ticket,status FROM inv_provider_ao_mca_evidence
   WHERE packet_id=? AND dossier_id=? FOR UPDATE`,[packet.id,dossier.id]);
  if(old.length){
   if(old[0].master!==v.mcaMasterDataSha256||old[0].mandate!==v.signatoryMandateSha256||
    old[0].ticket!==v.verificationTicket)throw new ChainConflictError('Immutable MCA evidence differs');
   res.status(200).json({id:old[0].id,status:old[0].status,replayed:true,
    mcaExternallyAuthenticated:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_ao_mca_evidence
   (id,packet_id,dossier_id,prepared_by,mca_master_data_sha256,
   signatory_mandate_sha256,verification_ticket) VALUES(?,?,?,?,?,?,?)`,
   [id,packet.id,dossier.id,owner,v.mcaMasterDataSha256,
    v.signatoryMandateSha256,v.verificationTicket]);
  res.status(201).json({id,status:'PENDING_EXTERNAL',
   actualMcaRegistryAuthenticated:false,actualLegalSignatoryAuthenticated:false});
 });
});
router.get('/readiness',async(req,res)=>{
 let trialId:string,mcaId:string;
 try{trialId=ensureId(req.query.trialId);mcaId=ensureId(req.query.mcaId);}
 catch(e){fail(res,e);return;}
 await transactional(res,async(c,owner)=>{
  const proof=await readTrial(c,trialId);
  if(proof.packet.owner!==owner)throw new ChainConflictError('Not original owner');
  const v=await readiness(c,trialId,mcaId);
  res.json(v);
 });
});
router.get('/authority',(_req,res)=>res.json({provider:'eMudhra Limited',
 approvedProviderContract:false,approvedSandboxApiCredentials:false,
 authenticMcaVerification:false,realSignatoryAuthority:false,
 productionCrlOcspTrusted:false,productionCertPathAccepted:false,
 officialGrnVerified:false,stockPostingEnabled:false,
 productionReady:false,blockers:AO_BLOCKERS}));
export default router;
