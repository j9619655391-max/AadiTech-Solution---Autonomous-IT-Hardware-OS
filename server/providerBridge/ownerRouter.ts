import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {chainEvidence} from '../evidenceChain/validation';
import {inspectIssuer} from '../externalTrust/integrity';
import {inventoryId} from '../inventory/validation';
import {readPin,latestFeed,internalReadiness} from './integrity';
import {fetchPinnedRevocationEnvelope} from './transport';
import {pinConfig,validateCredential,validateCredentialTemplate,
 validateFeed,validateFeedTemplate,credentialMessage,feedMessage,validateFreeze,
 exact,ChainInputError,ChainConflictError,digest,verify} from './validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function error(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Preprovisioned pin, issuer credential, source or revocation evidence is blocked'});return;
 }
 console.error('Provider evidence owner denied',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Provider proof service unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'PIN'|'CREDENTIAL'|'FEED',
 id:string,action:'PIN_CANDIDATE_RECORDED'|'CREDENTIAL_IMPORTED'|'FEED_IMPORTED'|'PIN_FROZEN',details:object){
 await c.execute(`INSERT INTO inv_provider_audit
  (id,actor_id,entity_type,entity_id,action,event_sha256)
  VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,action,digest(details)]);
}
router.get('/pins',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.provider_code AS providerCode,
   p.provider_origin AS providerOrigin,p.root_fingerprint_sha256 AS rootFingerprint,
   p.tls_spki_sha256 AS tlsFingerprint,p.status,
   p.external_root_state AS externalRootState,f.pin_id AS frozen
   FROM inv_provider_pin_candidates p
   LEFT JOIN inv_provider_pin_freezes f ON f.pin_id=p.id
   WHERE p.provisioned_by=? ORDER BY p.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externallyVerifiedTrustRoots:0,serverConfiguredPinIsNotAuthentication:true});
 }catch(e){error(res,e);}
});
router.post('/pins',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let evidenceRef:string;
 try{evidenceRef=chainEvidence(exact(req.body,['evidenceRef']).evidenceRef);}
 catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  const pinned=pinConfig(process.env);
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [existing]=await c.query<RowDataPacket[]>(`SELECT id,provider_code AS providerCode,
   provider_origin AS origin,root_spki_b64 AS spki,
   tls_spki_sha256 AS tls,provisioned_by AS owner,evidence_ref AS evidenceRef,status
   FROM inv_provider_pin_candidates WHERE root_fingerprint_sha256=? FOR UPDATE`,
   [pinned.rootFingerprint]);
  if(existing.length){
   if(existing[0].providerCode!==pinned.providerCode||
    existing[0].origin!==pinned.origin||existing[0].spki!==pinned.spkiB64||
    existing[0].tls!==pinned.tlsFingerprint||existing[0].owner!==actor||
    existing[0].evidenceRef!==evidenceRef)
    throw new ChainConflictError('Root fingerprint already bound to different configuration');
   await c.commit();
   res.status(200).json({id:existing[0].id,status:existing[0].status,replayed:true,
    externallyAuthenticated:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_pin_candidates
   (id,provider_code,provider_origin,root_spki_b64,root_fingerprint_sha256,
    tls_spki_sha256,provisioned_by,evidence_ref)
   VALUES(?,?,?,?,?,?,?,?)`,
   [id,pinned.providerCode,pinned.origin,pinned.spkiB64,pinned.rootFingerprint,
    pinned.tlsFingerprint,actor,evidenceRef]);
  await audit(c,actor,'PIN',id,'PIN_CANDIDATE_RECORDED',
   {rootFingerprint:pinned.rootFingerprint,tlsFingerprint:pinned.tlsFingerprint});
  await c.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',externallyAuthenticated:false,
   rootSource:'SERVER_ENVIRONMENT_ONLY',productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.get('/credentials',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,
   issuer_id AS issuerId,purpose,status,corporate_identity_state AS corporateState,
   stock_posting AS stockPosting FROM inv_provider_org_credentials
   WHERE submitted_by=? ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalCorporateIdentityVerified:false});
 }catch(e){error(res,e);}
});
async function credentialSource(c:PoolConnection,input:ReturnType<typeof validateCredentialTemplate>,
 actor:string){
 const pin=await readPin(c,input.pinId);
 const issuer=await inspectIssuer(c,input.issuerId);
 if(pin.provisionedBy!==actor||issuer.registeredBy!==actor||
  (input.purpose==='SUPPLIER_ACK'&&issuer.partyKind!=='SUPPLIER')||
  (input.purpose==='WAREHOUSE_GRN'&&issuer.partyKind!=='WAREHOUSE'))
  throw new ChainConflictError('Provider and issuer party scope mismatch');
 const message=credentialMessage({pinId:pin.id,providerCode:pin.providerCode,
  providerOrigin:pin.origin,rootFingerprint:pin.rootFingerprint,
  issuerId:issuer.id,issuerFingerprint:issuer.fingerprint,
  partyKind:issuer.partyKind,partyId:issuer.partyId,
  organizationRegistration:issuer.organizationRegistration,
  purpose:input.purpose,validFrom:input.validFrom,validUntil:input.validUntil});
 return {pin,issuer,message,sha:digest(message)};
}
router.post('/credential-template',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateCredentialTemplate>;
 try{input=validateCredentialTemplate(req.body);}catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const v=await credentialSource(c,input,String(res.locals.auth.userId));
  await c.commit();
  res.json({message:v.message,canonicalUtf8:JSON.stringify(v.message),
   messageSha256:v.sha,externallyAuthenticated:false,
   warning:'An offline root signature is not independent supplier identity authentication.'});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.post('/credentials',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateCredential>;
 try{input=validateCredential(req.body);}catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),{signatureB64,...base}=input;
  const v=await credentialSource(c,base,actor);
  if(Date.parse(input.validFrom)>Date.now()+300_000||
   Date.parse(input.validUntil)<=Date.now()||
   !verify(v.message,v.pin.publicKey,signatureB64))
   throw new ChainConflictError('Credential is invalid, expired or not signed by pinned root');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,message_sha256 AS digest,
   signature_b64 AS signature,status FROM inv_provider_org_credentials
   WHERE pin_id=? AND issuer_id=? AND purpose=? FOR UPDATE`,
   [base.pinId,base.issuerId,base.purpose]);
  if(old.length){
   if(old[0].digest!==v.sha||old[0].signature!==signatureB64)
    throw new ChainConflictError('Immutable root credential already differs');
   await c.commit();
   res.status(200).json({id:old[0].id,status:old[0].status,replayed:true,
    corporateIdentityVerified:false});return;
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_org_credentials
   (id,pin_id,issuer_id,submitted_by,purpose,valid_from,valid_until,
    message_sha256,message_json,signature_b64)
   VALUES(?,?,?,?,?,?,?,?,?,?)`,
   [id,base.pinId,base.issuerId,actor,base.purpose,
    base.validFrom.replace('T',' ').replace('.000Z',''),
    base.validUntil.replace('T',' ').replace('.000Z',''),
    v.sha,JSON.stringify(v.message),signatureB64]);
  await audit(c,actor,'CREDENTIAL',id,'CREDENTIAL_IMPORTED',
   {pinFingerprint:v.pin.rootFingerprint,issuerFingerprint:v.issuer.fingerprint,digest:v.sha});
  await c.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',
   pinnedRootSignatureMatched:true,corporateIdentityVerified:false,
   credentialIssuanceExternallyAuthenticated:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
async function feedSource(c:PoolConnection,actor:string,input:ReturnType<typeof validateFeedTemplate>){
 const pin=await readPin(c,input.pinId);
 if(pin.provisionedBy!==actor)throw new ChainConflictError('Pin not controlled by owner');
 const message=feedMessage({...input,providerCode:pin.providerCode,
  providerOrigin:pin.origin,rootFingerprint:pin.rootFingerprint});
 return {pin,message,sha:digest(message)};
}
router.post('/feed-template',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateFeedTemplate>;
 try{input=validateFeedTemplate(req.body);}catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const v=await feedSource(c,String(res.locals.auth.userId),input);
  await c.commit();
  res.json({message:v.message,canonicalUtf8:JSON.stringify(v.message),messageSha256:v.sha,
   publisherExternallyVerified:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.post('/feeds',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateFeed>;
 try{input=validateFeed(req.body);}catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),{signatureB64,...base}=input;
  const v=await feedSource(c,actor,base);
  if(Date.parse(base.publishedAt)>Date.now()+300_000||
   Date.parse(base.validUntil)<=Date.now()||
   !verify(v.message,v.pin.publicKey,signatureB64))
   throw new ChainConflictError('Invalid pinned root signature or stale feed');
  const [old]=await c.query<RowDataPacket[]>(`SELECT id,sequence_number AS seq,
   message_sha256 AS digest,signature_b64 AS signature FROM inv_provider_revocation_feeds
   WHERE pin_id=? ORDER BY sequence_number DESC LIMIT 1 FOR UPDATE`,[base.pinId]);
  const sequence=old.length?Number(old[0].seq):0;
  if(input.sequenceNumber===sequence&&old.length){
   if(old[0].digest!==v.sha||old[0].signature!==signatureB64)
    throw new ChainConflictError('Root revocation feed sequence equivocation');
   await latestFeed(c,input.pinId);
   await c.commit();
   res.status(200).json({id:old[0].id,sequenceNumber:sequence,replayed:true,
    publisherExternallyVerified:false});return;
  }
  if(input.sequenceNumber!==sequence+1)
   throw new ChainConflictError('Revocation feed sequence gap or rollback');
  if(old.length){
   const [entries]=await c.query<RowDataPacket[]>(`SELECT revoked_fingerprint_sha256 AS fp
    FROM inv_provider_revocation_entries WHERE feed_id=?`,[old[0].id]);
   if(entries.some(e=>!base.revokedFingerprints.includes(String(e.fp))))
    throw new ChainConflictError('Revocation list cannot silently un-revoke');
  }
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_revocation_feeds
   (id,pin_id,sequence_number,published_at,valid_until,imported_by,
    message_sha256,message_json,signature_b64) VALUES(?,?,?,?,?,?,?,?,?)`,
   [id,base.pinId,base.sequenceNumber,
    base.publishedAt.replace('T',' ').replace('.000Z',''),
    base.validUntil.replace('T',' ').replace('.000Z',''),actor,
    v.sha,JSON.stringify(v.message),signatureB64]);
  for(const fp of base.revokedFingerprints)
   await c.execute(`INSERT INTO inv_provider_revocation_entries
    (feed_id,revoked_fingerprint_sha256) VALUES(?,?)`,[id,fp]);
  await audit(c,actor,'FEED',id,'FEED_IMPORTED',
   {pinId:base.pinId,sequence:base.sequenceNumber,digest:v.sha});
  await c.commit();
  res.status(201).json({id,sequenceNumber:base.sequenceNumber,
   rootSignatureMatched:true,publisherExternallyVerified:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.get('/feeds',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT f.id,f.pin_id AS pinId,
   f.sequence_number AS sequenceNumber,f.valid_until AS validUntil,
   f.status FROM inv_provider_revocation_feeds f
   JOIN inv_provider_pin_candidates p ON p.id=f.pin_id
   WHERE p.provisioned_by=? ORDER BY f.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalPublisherVerified:false});
 }catch(e){error(res,e);}
});
router.get('/readiness/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid credential ID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const [mine]=await c.query<RowDataPacket[]>(`SELECT submitted_by AS owner
   FROM inv_provider_org_credentials WHERE id=?`,[req.params.id]);
  if(mine.length!==1||mine[0].owner!==res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Credential unavailable'});return;
  }
  const v=await internalReadiness(c,req.params.id);await c.commit();
  res.json({...v,blockers:['Pinned environment key not externally validated with provider',
   'Corporate identity and authorized signatory not independently authenticated',
   'Revocation publication transport origin not independently authenticated',
   'No real supplier PO, official GRN, or operational stock authorization']});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.post('/pins/:id/freeze',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid pin ID'});return;}
 let data:ReturnType<typeof validateFreeze>;
 try{data=validateFreeze(req.body);}catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [rows]=await c.query<RowDataPacket[]>(`SELECT provisioned_by AS owner
   FROM inv_provider_pin_candidates WHERE id=? FOR UPDATE`,[req.params.id]);
  if(rows.length!==1||rows[0].owner!==actor){
   await c.rollback();res.status(404).json({error:'Pin unavailable'});return;
  }
  const [freeze]=await c.query<RowDataPacket[]>(`SELECT pin_id FROM inv_provider_pin_freezes
   WHERE pin_id=? FOR UPDATE`,[req.params.id]);
  if(freeze.length)throw new ChainConflictError('Already permanently frozen');
  await c.execute(`INSERT INTO inv_provider_pin_freezes
   (pin_id,initiated_by,reason,evidence_ref) VALUES(?,?,?,?)`,
   [req.params.id,actor,data.reason,data.evidenceRef]);
  await audit(c,actor,'PIN',req.params.id,'PIN_FROZEN',data);
  await c.commit();
  res.status(201).json({pinId:req.params.id,permanentlyFrozen:true,
   externallyAuthenticated:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
// Preview only: a separately configured TLS peer may return a signed feed,
// but we cannot convert this into legal external identity or silently insert DB rows.
router.post('/feeds/pull-pinned-preview',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let pinId:string;
 try{
  const input=exact(req.body,['pinId']);
  if(!inventoryId(input.pinId))throw new ChainInputError('Valid pin ID required');
  pinId=input.pinId as string;
 }catch(e){error(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const pin=await readPin(c,pinId);
  if(pin.provisionedBy!==res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Pin unavailable'});return;
  }
  await c.commit();
  const payload=await fetchPinnedRevocationEnvelope(process.env);
  const signed=validateFeed(payload);
  if(signed.pinId!==pinId)throw new ChainConflictError('Pinned publisher returned unrelated scope');
  const message=feedMessage({...signed,providerCode:pin.providerCode,
   providerOrigin:pin.origin,rootFingerprint:pin.rootFingerprint});
  if(!verify(message,pin.publicKey,signed.signatureB64)||
   Date.parse(signed.publishedAt)>Date.now()+300_000||
   Date.parse(signed.validUntil)<=Date.now())
   throw new ChainConflictError('Pinned TLS source returned invalid signed revocations');
  res.json({validatedTlsPeerSpki:true,validatedRootDetachedSignature:true,
   previewOnly:true,notImported:true,externalOrganizationIdentityVerified:false,
   issuerExternallyAuthenticated:false,productionReady:false,
   feed:signed,canonicalMessage:message});
 }catch(e){if(c)await c.rollback().catch(()=>{});error(res,e);}
 finally{c?.release();}
});
router.get('/authority',(_req,res)=>res.json({externalTrustProviderAuthenticated:false,
 rootCertificateChainExternallyValidated:false,corporateIdentityVerified:false,
 signedCredentialsExternallyIssued:false,trustedRevocationPublisherVerified:false,
 productionReady:false,officialGrnVerified:false,stockPostingEnabled:false,
 availableToSell:null}));
export default router;
