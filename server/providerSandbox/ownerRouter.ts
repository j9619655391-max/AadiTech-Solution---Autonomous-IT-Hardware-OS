import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ensureId} from '../providerBridge/validation';
import {inspectIssuer} from '../externalTrust/integrity';
import {readPin} from '../providerBridge/integrity';
import {readCase,sandboxReadiness} from './integrity';
import {caseBody,certificateBody,inspectOneHopCertificateChain,
 ChainInputError,ChainConflictError,exact,checkDigest} from './validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
  ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'Only immutable, independently reviewed sandbox identity/certificate evidence can be recorded'});return;
 }
 console.error('Sandbox onboarding owner evidence unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Provider sandbox evidence service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'CASE'|'CERT'|'CHECK',id:string,
 event:'CASE_OPENED'|'CERT_EVIDENCE_IMPORTED'|'REVOCATION_RECHECKED',data:object){
 await c.execute(`INSERT INTO inv_sandbox_audit
 (id,actor_id,entity_type,entity_id,event_type,digest_sha256)
 VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,event,checkDigest(data)]);
}
router.get('/cases',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,
    issuer_id AS issuerId,purpose,registry_reference AS registryReference,
    signatory_reference AS signatoryReference,status,
    corporate_identity_state AS corporateState,signatory_authority_state AS signatoryState
    FROM inv_sandbox_onboarding_cases WHERE opened_by=?
    ORDER BY created_at DESC,id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,corporateVerified:false,authorizedSignatoryVerified:false});
 }catch(e){fail(res,e);}
});
router.post('/cases',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof caseBody>;
 try{input=caseBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),pin=await readPin(c,input.pinId),
   issuer=await inspectIssuer(c,input.issuerId);
  if(pin.provisionedBy!==actor||issuer.registeredBy!==actor||
    issuer.organizationRegistration!==input.registryReference||
    (input.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
    (input.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE'))
   throw new ChainConflictError('Provider, issuer or registry claim mismatch');
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id,opened_by AS owner,status,
   registry_reference AS registryReference,
   identity_document_sha256 AS identityDoc,
   signatory_reference AS signatoryReference,
   signatory_document_sha256 AS signatoryDoc,evidence_ref AS evidenceRef
   FROM inv_sandbox_onboarding_cases
   WHERE pin_id=? AND issuer_id=? AND purpose=? FOR UPDATE`,
   [input.pinId,input.issuerId,input.purpose]);
  if(prior.length){
   const p=prior[0];
   if(p.owner!==actor||p.registryReference!==input.registryReference||
    p.identityDoc!==input.identityDocumentSha256||
    p.signatoryReference!==input.signatoryReference||
    p.signatoryDoc!==input.signatoryDocumentSha256||p.evidenceRef!==input.evidenceRef)
    throw new ChainConflictError('Onboarding case conflict with immutable source');
   await c.commit();res.status(200).json({id:p.id,status:p.status,replayed:true,
    corporateIdentityVerified:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_sandbox_onboarding_cases
   (id,pin_id,issuer_id,opened_by,purpose,registry_reference,
    identity_document_sha256,signatory_reference,
    signatory_document_sha256,evidence_ref) VALUES(?,?,?,?,?,?,?,?,?,?)`,
   [id,input.pinId,input.issuerId,actor,input.purpose,input.registryReference,
    input.identityDocumentSha256,input.signatoryReference,
    input.signatoryDocumentSha256,input.evidenceRef]);
  await audit(c,actor,'CASE',id,'CASE_OPENED',{pinId:input.pinId,issuerId:input.issuerId,
   purpose:input.purpose,identityDocumentSha256:input.identityDocumentSha256,
   signatoryDocumentSha256:input.signatoryDocumentSha256});
  await c.commit();res.status(201).json({id,status:'PENDING_INTERNAL',replayed:false,
   corporateIdentityVerified:false,authorizedSignatoryVerified:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/certificates',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.case_id AS caseId,
   p.ca_certificate_sha256 AS caFingerprint,
   p.leaf_certificate_sha256 AS leafFingerprint,
   p.leaf_spki_sha256 AS leafKeyFingerprint,
   p.leaf_serial AS serial,p.status,
   p.provider_issued_authenticated AS providerAuthenticated
   FROM inv_sandbox_cert_packages p
   WHERE p.imported_by=? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,fullRfc5280Validation:false,providerIssuanceAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/certificates',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof certificateBody>;
 try{input=certificateBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),
   caseData=await readCase(c,input.caseId,true);
  if(caseData.openedBy!==actor)throw new ChainConflictError('Owner scope mismatch');
  const cert=inspectOneHopCertificateChain(input.rootCertificatePem,input.leafCertificatePem,
   caseData.pin.rootFingerprint,caseData.issuer.fingerprint);
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id,ca_certificate_sha256 AS caDigest,
   leaf_certificate_sha256 AS leafDigest,leaf_spki_sha256 AS keyDigest,status
   FROM inv_sandbox_cert_packages WHERE case_id=? FOR UPDATE`,[input.caseId]);
  if(prior.length){
   if(prior[0].caDigest!==cert.rootCertSha256||
    prior[0].leafDigest!==cert.leafCertSha256||
    prior[0].keyDigest!==cert.leafSpkiSha256)
    throw new ChainConflictError('Immutable sandbox certificate is different');
   await c.commit();
   res.status(200).json({id:prior[0].id,status:prior[0].status,replayed:true,
    fullPathValidated:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_sandbox_cert_packages
   (id,case_id,imported_by,ca_certificate_pem,leaf_certificate_pem,
    ca_certificate_sha256,leaf_certificate_sha256,leaf_spki_sha256,
    leaf_serial,leaf_not_before,leaf_not_after)
   VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
   [id,input.caseId,actor,input.rootCertificatePem,input.leafCertificatePem,
    cert.rootCertSha256,cert.leafCertSha256,cert.leafSpkiSha256,
    cert.leafSerial,cert.notBefore.slice(0,19).replace('T',' '),
    cert.notAfter.slice(0,19).replace('T',' ')]);
  await audit(c,actor,'CERT',id,'CERT_EVIDENCE_IMPORTED',
   {caseId:input.caseId,caDigest:cert.rootCertSha256,leafDigest:cert.leafCertSha256});
  await c.commit();res.status(201).json({id,status:'CERT_SIGNATURE_MATCHED_HELD',
   oneHopSignatureMatched:true,fullRfc5280PathValidated:false,
   providerIssuedAuthenticated:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/readiness/:id',async(req,res)=>{
 let id:string;
 try{id=ensureId(req.params.id);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const [mine]=await c.query<RowDataPacket[]>(`SELECT imported_by AS owner
   FROM inv_sandbox_cert_packages WHERE id=?`,[id]);
  if(mine.length!==1||mine[0].owner!==res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Certificate evidence unavailable'});return;
  }
  const check=await sandboxReadiness(c,id);await c.commit();
  res.json({certificateId:id,revocationSequence:check.feed.sequenceNumber,
   revocationValidUntil:check.feed.validUntil,
   oneHopCertificateSignatureMatched:true,fullRfc5280PathValidated:false,
   corporateIdentityVerified:false,authorizedSignatoryVerified:false,
   providerIssuedAuthenticated:false,revocationPublisherVerified:false,
   officialGrnVerified:false,stockPostingEnabled:false,
   productionReady:false,availableToSell:null,
   blockers:['No independently authenticated real corporate identity/KYC',
    'No independently authorized legal company signatory',
    'No provider-specific full RFC5280 path/certificate policy validation',
    'No authenticated production revocation publisher/official GRN']});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.post('/revocation-checks',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let certId:string;
 try{certId=ensureId(exact(req.body,['certId']).certId);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),check=await sandboxReadiness(c,certId);
  if(check.cert.importedBy!==actor)throw new ChainConflictError('Owner source mismatch');
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id,checked_digest_sha256 AS digest
   FROM inv_sandbox_revocation_checks
   WHERE cert_id=? AND feed_id=? FOR UPDATE`,[certId,check.feed.id]);
  if(prior.length){
   if(prior[0].digest!==check.digest)throw new ChainConflictError('Historical check digest mismatch');
   await c.commit();res.status(200).json({id:prior[0].id,replayed:true,
    status:'CHECKED_HELD',productionReady:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_sandbox_revocation_checks
   (id,cert_id,feed_id,checked_by,checked_digest_sha256) VALUES(?,?,?,?,?)`,
   [id,certId,check.feed.id,actor,check.digest]);
  await audit(c,actor,'CHECK',id,'REVOCATION_RECHECKED',{digest:check.digest});
  await c.commit();res.status(201).json({id,status:'CHECKED_HELD',
   rootSignedRevocationMathematicallyMatched:true,actualPublisherAuthenticated:false,
   officialGrnVerified:false,stockPostingEnabled:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/authority',(_req,res)=>res.json({onboardingVerified:false,
 independentlyVerifiedCorporateIdentity:false,authorizedSignatory:false,
 externallyValidatedProviderIssuedCertificate:false,
 fullRfc5280CertificationPathValidated:false,
 externallyAuthenticatedRevocationPublisher:false,
 officialGrnVerified:false,stockPostingEnabled:false,
 productionReady:false,availableToSell:null}));
export default router;
