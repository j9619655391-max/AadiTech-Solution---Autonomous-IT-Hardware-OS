import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {independentlyReviewedPossession} from '../keyLifecycle/integrity';
import {inspectIssuer,inspectLatestRevocations,inspectReadiness} from './integrity';
import {validateIssuer,validateAuthority,validateAuthorityTemplate,validateRevocation,
 revocationTemplate,authorityMessage,revocationMessage,verifySigned,
 digest,exact,ChainInputError,ChainConflictError} from './validation';
import {chainEvidence} from '../evidenceChain/validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||
   (e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Untrusted issuer, organizational claim, revocation or evidence chain conflict'});return;
 }
 console.error('External trust prerequisite owner error',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'External trust prerequisites unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'ISSUER'|'AUTHORITY'|'REVOCATION',
 id:string,event:'ISSUER_REGISTERED'|'AUTHORITY_SIGNED'|'REVOCATION_IMPORTED'|'ISSUER_FROZEN',
 detail:object){
 await c.execute(`INSERT INTO inv_external_trust_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256)
  VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,event,digest(detail)]);
}
router.get('/issuers',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT i.id,i.party_kind AS partyKind,
   i.party_id AS partyId,i.fingerprint_sha256 AS fingerprint,
   i.organization_registration AS organizationRegistration,i.status,
   i.external_root_state AS externalRootState,f.issuer_id AS frozen
   FROM inv_external_issuer_candidates i
   LEFT JOIN inv_external_issuer_freezes f ON f.issuer_id=i.id
   WHERE i.registered_by=? ORDER BY i.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,verifiedExternalRootCount:0,externallyAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/issuers',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateIssuer>;
 try{input=validateIssuer(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [party]=input.partyKind==='SUPPLIER'?
   await c.query<RowDataPacket[]>(`SELECT id FROM proc_suppliers
    WHERE id=? AND created_by=? AND status='REVIEWED_INTERNAL' FOR UPDATE`,
    [input.partyId,actor]):
   await c.query<RowDataPacket[]>(`SELECT id FROM inventory_sites
    WHERE id=? AND created_by=? FOR UPDATE`,[input.partyId,actor]);
  if(party.length!==1){await c.rollback();res.status(404).json({error:'Owner internal party not found'});return;}
  const [prior]=await c.query<RowDataPacket[]>(`SELECT id,party_kind AS partyKind,
   party_id AS partyId,registered_by AS registeredBy,
   organization_registration AS registration,evidence_ref AS evidenceRef,status
   FROM inv_external_issuer_candidates WHERE fingerprint_sha256=? FOR UPDATE`,
   [input.issuerFingerprint]);
  if(prior.length){
   if(prior[0].partyKind!==input.partyKind||prior[0].partyId!==input.partyId||
    prior[0].registeredBy!==actor||prior[0].registration!==input.organizationRegistration||
    prior[0].evidenceRef!==input.evidenceRef)
    throw new ChainConflictError('Issuer fingerprint is already bound to different metadata');
   await c.commit();
   res.status(200).json({id:prior[0].id,status:prior[0].status,replayed:true,
    externalTrustVerified:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_external_issuer_candidates
   (id,party_kind,party_id,registered_by,issuer_spki_b64,fingerprint_sha256,
    organization_registration,evidence_ref)
   VALUES(?,?,?,?,?,?,?,?)`,
   [id,input.partyKind,input.partyId,actor,input.issuerSpkiB64,input.issuerFingerprint,
    input.organizationRegistration,input.evidenceRef]);
  await audit(c,actor,'ISSUER',id,'ISSUER_REGISTERED',
   {fingerprint:input.issuerFingerprint,partyId:input.partyId});
  await c.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',replayed:false,
   cryptographicRootCandidate:true,externallyAuthenticated:false,
   message:'Owner-supplied issuer key is NOT a trusted external certificate authority.'});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/issuers/:id/freeze',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid issuer ID'});return;}
 let reason:string,evidenceRef:string;
 try{
  const v=exact(req.body,['reason','evidenceRef']);
  if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
   throw new ChainInputError('Detailed issuer compromise reason required');
  reason=v.reason.trim();evidenceRef=chainEvidence(v.evidenceRef);
 }catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [candidate]=await c.query<RowDataPacket[]>(`SELECT registered_by AS owner
    FROM inv_external_issuer_candidates WHERE id=? FOR UPDATE`,[req.params.id]);
  if(candidate.length!==1||candidate[0].owner!==actor){
   await c.rollback();res.status(404).json({error:'Issuer unavailable'});return;
  }
  const [old]=await c.query<RowDataPacket[]>(`SELECT issuer_id
   FROM inv_external_issuer_freezes WHERE issuer_id=? FOR UPDATE`,[req.params.id]);
  if(old.length)throw new ChainConflictError('Issuer already permanently frozen');
  await c.execute(`INSERT INTO inv_external_issuer_freezes
   (issuer_id,initiated_by,reason,evidence_ref) VALUES(?,?,?,?)`,
   [req.params.id,actor,reason,evidenceRef]);
  await audit(c,actor,'ISSUER',req.params.id,'ISSUER_FROZEN',{reason,evidenceRef});
  await c.commit();
  res.status(201).json({issuerId:req.params.id,irreversiblyFrozen:true,
   externalTrustVerified:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
async function resolvedAuthority(c:PoolConnection,actor:string,input:ReturnType<typeof validateAuthorityTemplate>){
 const issuer=await inspectIssuer(c,input.issuerId);
 const key=await independentlyReviewedPossession(c,input.keyId);
 if(issuer.registeredBy!==actor||key.key.registeredBy!==actor||
  issuer.partyKind!==key.key.partyKind||issuer.partyId!==key.key.partyId||
  (input.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
  (input.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE'))
  throw new ChainConflictError('No matching reviewed internal issuer/key possession/party');
 const message=authorityMessage({...input,issuerFingerprint:issuer.fingerprint,
  keyFingerprint:key.key.fingerprint,partyKind:issuer.partyKind,partyId:issuer.partyId,
  organizationRegistration:issuer.organizationRegistration});
 return {issuer,key,message,hash:digest(message)};
}
router.post('/authority-template',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateAuthorityTemplate>;
 try{input=validateAuthorityTemplate(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const v=await resolvedAuthority(c,String(res.locals.auth.userId),input);
  await c.commit();
  res.json({canonicalUtf8:JSON.stringify(v.message),statementSha256:v.hash,
   message:v.message,issuerExternallyAuthenticated:false,
   warning:'Sign EXACT bytes offline. A self-registered issuer signature never establishes a legal organization.'});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/attestations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateAuthority>;
 try{input=validateAuthority(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),{signatureB64,...base}=input;
  const data=await resolvedAuthority(c,actor,base);
  if(Date.parse(base.validFrom)>Date.now()+5*60_000||
   Date.parse(base.validUntil)<=Date.now()||
   !verifySigned(data.message,data.issuer.key,signatureB64))
   throw new ChainConflictError('Issuer signature invalid, out-of-window or source compromised');
  const [existing]=await c.query<RowDataPacket[]>(`SELECT id,statement_sha256 AS digest,
   signature_b64 AS signature,status
   FROM inv_external_authority_attestations
   WHERE issuer_id=? AND key_id=? AND purpose=? FOR UPDATE`,
   [input.issuerId,input.keyId,input.purpose]);
  if(existing.length){
   if(existing[0].digest!==data.hash||existing[0].signature!==signatureB64)
    throw new ChainConflictError('Different immutable authority assertion already recorded');
   await c.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,replayed:true,
    organizationalAuthorityVerified:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_external_authority_attestations
   (id,issuer_id,key_id,prepared_by,purpose,valid_from,valid_until,
    statement_sha256,statement_json,signature_b64)
   VALUES(?,?,?,?,?,?,?,?,?,?)`,[id,input.issuerId,input.keyId,actor,input.purpose,
    input.validFrom.replace('T',' ').replace('.000Z',''),
    input.validUntil.replace('T',' ').replace('.000Z',''),
    data.hash,JSON.stringify(data.message),signatureB64]);
  await audit(c,actor,'AUTHORITY',id,'AUTHORITY_SIGNED',
   {issuerFingerprint:data.issuer.fingerprint,keyFingerprint:data.key.key.fingerprint,
    statementSha256:data.hash});
  await c.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',replayed:false,
   issuerSignatureMatched:true,organizationAuthorityVerified:false,
   externalIdentityAuthenticated:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/attestations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,issuer_id AS issuerId,
   key_id AS keyId,purpose,statement_sha256 AS digest,status,
   external_authority_state AS externalAuthorityState
   FROM inv_external_authority_attestations WHERE prepared_by=?
   ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalAuthorityAuthenticated:false,realGrn:false});
 }catch(e){fail(res,e);}
});
async function resolvedRevocations(c:PoolConnection,actor:string,input:ReturnType<typeof revocationTemplate>){
 const issuer=await inspectIssuer(c,input.issuerId);
 if(issuer.registeredBy!==actor)throw new ChainConflictError('Issuer not available to owner');
 const message=revocationMessage({...input,issuerFingerprint:issuer.fingerprint,
  partyKind:issuer.partyKind,partyId:issuer.partyId});
 return {issuer,message,hash:digest(message)};
}
router.post('/revocation-template',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof revocationTemplate>;
 try{input=revocationTemplate(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const v=await resolvedRevocations(c,String(res.locals.auth.userId),input);
  await c.commit();
  res.json({message:v.message,canonicalUtf8:JSON.stringify(v.message),
   digest:v.hash,externalPublisherAuthenticated:false,trustAnchorVerified:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/revocations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateRevocation>;
 try{input=validateRevocation(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),{signatureB64,...base}=input;
  const data=await resolvedRevocations(c,actor,base);
  if(Date.parse(base.issuedAt)>Date.now()+5*60_000||
   Date.parse(base.expiresAt)<=Date.now()||
   !verifySigned(data.message,data.issuer.key,signatureB64))
   throw new ChainConflictError('Invalid, expired or mis-signed revocation bundle');
  const [latest]=await c.query<RowDataPacket[]>(`SELECT id,sequence_number AS seq,
   manifest_sha256 AS digest,signature_b64 AS signature
   FROM inv_external_revocation_bundles WHERE issuer_id=?
   ORDER BY sequence_number DESC LIMIT 1 FOR UPDATE`,[input.issuerId]);
  const current=latest.length?Number(latest[0].seq):0;
  if(input.sequenceNumber===current&&latest.length){
   if(latest[0].digest!==data.hash||latest[0].signature!==signatureB64)
    throw new ChainConflictError('Revocation feed sequence digest conflict');
   await inspectLatestRevocations(c,input.issuerId);
   await c.commit();
   res.status(200).json({id:latest[0].id,sequenceNumber:current,
    replayed:true,externalPublisherAuthenticated:false});return;
  }
  if(input.sequenceNumber!==current+1)
   throw new ChainConflictError('Revocation feed sequence must be strictly contiguous');
  if(latest.length){
   const [prior]=await c.query<RowDataPacket[]>(`SELECT key_fingerprint_sha256 AS fingerprint
    FROM inv_external_revocation_entries WHERE bundle_id=?`,[latest[0].id]);
   if(prior.some(x=>!base.revokedFingerprints.includes(String(x.fingerprint))))
    throw new ChainConflictError('Revocation distribution cannot un-revoke previous fingerprints');
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_external_revocation_bundles
   (id,issuer_id,submitted_by,sequence_number,issued_at,expires_at,
    manifest_sha256,manifest_json,signature_b64)
   VALUES(?,?,?,?,?,?,?,?,?)`,[id,input.issuerId,actor,input.sequenceNumber,
    input.issuedAt.replace('T',' ').replace('.000Z',''),
    input.expiresAt.replace('T',' ').replace('.000Z',''),
    data.hash,JSON.stringify(data.message),signatureB64]);
  for(const fp of base.revokedFingerprints)
   await c.execute(`INSERT INTO inv_external_revocation_entries
    (bundle_id,key_fingerprint_sha256) VALUES(?,?)`,[id,fp]);
  await audit(c,actor,'REVOCATION',id,'REVOCATION_IMPORTED',
   {issuerId:input.issuerId,sequenceNumber:input.sequenceNumber,
    manifestSha256:data.hash,count:base.revokedFingerprints.length});
  await c.commit();
  res.status(201).json({id,sequenceNumber:input.sequenceNumber,
   cryptographicSignatureMatched:true,externalPublisherAuthenticated:false,
   revocationEntryCount:base.revokedFingerprints.length,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/revocations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT b.id,b.issuer_id AS issuerId,
   b.sequence_number AS sequenceNumber,b.expires_at AS expiresAt,
   b.status,b.external_publisher_authenticated AS publisherAuthenticated
   FROM inv_external_revocation_bundles b
   JOIN inv_external_issuer_candidates i ON i.id=b.issuer_id
   WHERE i.registered_by=? ORDER BY b.created_at DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,externalPublisherAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.get('/readiness/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid authority ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const [own]=await c.query<RowDataPacket[]>(`SELECT prepared_by AS owner FROM
   inv_external_authority_attestations WHERE id=?`,[req.params.id]);
  if(own.length!==1||own[0].owner!==res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Authority record unavailable'});return;
  }
  const check=await inspectReadiness(c,req.params.id);
  await c.commit();
  res.json({...check,externalIdentityVerified:false,actualPoIssued:false,
   supplierAckAuthenticated:false,officialGrnAuthenticated:false,availableToSell:null,
   blockers:['No independently established external issuer trust root',
    'No authenticated supplier/warehouse organizational authority',
    'No official physical GRN or authorized stock ledger posting']});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/authority',(_req,res)=>res.json({externalRootAuthenticated:false,
 organizationAuthorityVerified:false,revocationPublisherAuthenticated:false,
 officialGrnAuthenticated:false,supplierIssuedPo:false,operationalStockEnabled:false,
 availableToSell:null,productionReady:false}));
export default router;
