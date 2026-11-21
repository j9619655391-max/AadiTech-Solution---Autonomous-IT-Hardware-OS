import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ensureId} from '../providerBridge/validation';
import {readCase,readCert} from './integrity';
import {reviewCaseBody,reviewCertBody,ChainInputError,ChainConflictError,checkDigest} from './validation';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&
  ['ER_DUP_ENTRY','ER_CHECK_CONSTRAINT_VIOLATED'].includes(String(e.code)))){
  res.status(409).json({error:'Internal review cannot establish true provider/corporate authority'});return;
 }
 console.error('Sandbox reviewer evidence denied',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Sandbox reviewer service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'CASE'|'CERT',id:string,
 event:'CASE_REVIEWED'|'CASE_REJECTED'|'CERT_REVIEWED'|'CERT_REJECTED',v:object){
 await c.execute(`INSERT INTO inv_sandbox_audit
 (id,actor_id,entity_type,entity_id,event_type,digest_sha256)
 VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,event,checkDigest(v)]);
}
router.get('/cases',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,
   issuer_id AS issuerId,opened_by AS openedBy,purpose,
   registry_reference AS registryReference,identity_document_sha256 AS identityDocumentSha256,
   signatory_reference AS signatoryReference,signatory_document_sha256 AS signatoryDocumentSha256,
   status,corporate_identity_state AS corporateState,signatory_authority_state AS signatoryState
   FROM inv_sandbox_onboarding_cases WHERE opened_by<>?
   ORDER BY created_at DESC,id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,genuinelyCorporateAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/cases/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let caseId:string,data:ReturnType<typeof reviewCaseBody>;
 try{caseId=ensureId(req.params.id);data=reviewCaseBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),record=await readCase(c,caseId);
  if(actor===record.openedBy){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(record.status!=='PENDING_INTERNAL')throw new ChainConflictError('Case decision already final');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_sandbox_case_reviews
   (id,case_id,reviewer_id,decision,reason,evidence_ref,
    registry_document_inspected,signatory_document_inspected)
   VALUES(?,?,?,?,?,?,?,?)`,[id,caseId,actor,data.decision,data.reason,
    data.evidenceRef,data.registryInspected,data.signatoryInspected]);
  await c.execute(`UPDATE inv_sandbox_onboarding_cases SET status=?
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,caseId]);
  await audit(c,actor,'CASE',caseId,data.decision==='REVIEWED_EVIDENCE_HELD'?
   'CASE_REVIEWED':'CASE_REJECTED',{caseId,decision:data.decision,reviewId:id});
  await c.commit();res.status(201).json({reviewId:id,status:data.decision,
   corporateIdentityAuthenticated:false,signatoryAuthorityVerified:false,
   productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.get('/certificates',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.case_id AS caseId,
   p.imported_by AS importedBy,p.leaf_certificate_sha256 AS leafFingerprint,
   p.leaf_spki_sha256 AS leafKeyFingerprint,p.leaf_serial AS leafSerial,p.status,
   r.decision AS reviewState FROM inv_sandbox_cert_packages p
   LEFT JOIN inv_sandbox_cert_reviews r ON r.cert_id=p.id
   WHERE p.imported_by<>? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,providerIssuedAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.get('/certificates/:id',async(req,res)=>{
 let id:string;try{id=ensureId(req.params.id);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const record=await readCert(c,id);
  if(record.importedBy===res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  await c.commit();
  res.json({certificateId:id,caseId:record.caseData.id,
   rootCertificateSha256:record.crypto.rootCertSha256,
   leafCertificateSha256:record.crypto.leafCertSha256,
   leafSpkiSha256:record.crypto.leafSpkiSha256,serial:record.crypto.leafSerial,
   validFrom:record.crypto.notBefore,validUntil:record.crypto.notAfter,
   oneHopSignatureMatched:true,fullRfc5280PathValidated:false,
   legalCorporateIdentityVerified:false,sourceIssuerAuthenticated:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
router.post('/certificates/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let id:string,data:ReturnType<typeof reviewCertBody>;
 try{id=ensureId(req.params.id);data=reviewCertBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),record=await readCert(c,id);
  if(actor===record.importedBy){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id FROM inv_sandbox_cert_reviews WHERE cert_id=? FOR UPDATE`,[id]);
  if(prior.length)throw new ChainConflictError('Certificate evidence already reviewed');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_sandbox_cert_reviews
   (id,cert_id,reviewer_id,decision,reason,evidence_ref,
    certificate_inspected,policy_gaps_acknowledged) VALUES(?,?,?,?,?,?,?,?)`,
   [reviewId,id,actor,data.decision,data.reason,data.evidenceRef,
    data.certificateInspected,data.policyGapsAcknowledged]);
  await audit(c,actor,'CERT',id,data.decision==='REVIEWED_CRYPTO_HELD'?
   'CERT_REVIEWED':'CERT_REJECTED',{certId:id,decision:data.decision,reviewId});
  await c.commit();res.status(201).json({reviewId,status:data.decision,
   fullRfc5280PathValidated:false,externallyIssuedCertificateAuthenticated:false,
   actualCorporateIdentityVerified:false,officialGrnVerified:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}finally{c?.release();}
});
export default router;
