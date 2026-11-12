import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireReviewer,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {readPin,signedOrg} from './integrity';
import {validateReviewHeld,ChainInputError,ChainConflictError,digest} from './validation';
const router=Router();router.use(requireReviewer);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Pinned provider review or frozen signed evidence conflict'});return;
 }
 console.error('Provider bridge independent review unavailable',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Independent provider evidence review unavailable'});
}
async function audit(c:PoolConnection,actor:string,type:'PIN'|'CREDENTIAL',id:string,
 action:'PIN_REVIEWED'|'PIN_REJECTED'|'CREDENTIAL_REVIEWED'|'CREDENTIAL_REJECTED',details:object){
 await c.execute(`INSERT INTO inv_provider_audit
  (id,actor_id,entity_type,entity_id,action,event_sha256)
  VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,type,id,action,digest(details)]);
}
router.get('/pins',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id,p.provider_code AS providerCode,
   p.provider_origin AS providerOrigin,p.root_fingerprint_sha256 AS rootFingerprint,
   p.tls_spki_sha256 AS tlsFingerprint,p.provisioned_by AS provisionedBy,
   p.evidence_ref AS evidenceRef,p.status,f.pin_id AS frozen
   FROM inv_provider_pin_candidates p
   LEFT JOIN inv_provider_pin_freezes f ON f.pin_id=p.id
   WHERE p.provisioned_by<>? ORDER BY p.created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalCertificateAuthoritiesVerified:0});
 }catch(e){fail(res,e);}
});
router.post('/pins/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid pin UUID'});return;}
 let data:ReturnType<typeof validateReviewHeld>;
 try{data=validateReviewHeld(req.body,'REVIEWED_HELD');}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),pin=await readPin(c,req.params.id,false);
  if(pin.provisionedBy===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(pin.status!=='PENDING_INTERNAL')throw new ChainConflictError('Pin previously reviewed');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_provider_pin_reviews
   (id,pin_id,reviewer_id,decision,reason,evidence_ref,pin_inspected)
   VALUES(?,?,?,?,?,?,?)`,[id,pin.id,actor,data.decision,data.reason,
    data.evidenceRef,data.evidenceInspected]);
  await c.execute(`UPDATE inv_provider_pin_candidates SET status=?
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,pin.id]);
  await audit(c,actor,'PIN',pin.id,
   data.decision==='REVIEWED_HELD'?'PIN_REVIEWED':'PIN_REJECTED',
   {decision:data.decision,fingerprint:pin.rootFingerprint});
  await c.commit();
  res.status(201).json({reviewId:id,status:data.decision,
   externallyAuthenticated:false,productionReady:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/credentials',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,pin_id AS pinId,
   issuer_id AS issuerId,submitted_by AS submittedBy,purpose,
   message_sha256 AS messageSha256,status
   FROM inv_provider_org_credentials WHERE submitted_by<>?
   ORDER BY created_at DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externallyAuthenticatedCredentials:0});
 }catch(e){fail(res,e);}
});
router.get('/credentials/:id',async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid credential UUID'});return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const data=await signedOrg(c,req.params.id);
  if(data.submitter===res.locals.auth.userId){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  await c.commit();
  res.json({id:data.id,status:data.status,message:data.message,
   rootFingerprint:data.pin.rootFingerprint,
   organizationFingerprint:data.issuer.fingerprint,rootSignatureMathMatched:true,
   externallyAuthenticated:false,corporateIdentityVerified:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/credentials/:id/decide',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid credential UUID'});return;}
 let data:ReturnType<typeof validateReviewHeld>;
 try{data=validateReviewHeld(req.body,'REVIEWED_CRYPTO_HELD');}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),v=await signedOrg(c,req.params.id);
  if(v.submitter===actor){
   await c.rollback();res.status(404).json({error:'Independent reviewer required'});return;
  }
  if(v.status!=='PENDING_INTERNAL')throw new ChainConflictError('Credential already reviewed');
  const reviewId=randomUUID();
  await c.execute(`INSERT INTO inv_provider_org_reviews
   (id,credential_id,reviewer_id,decision,reason,evidence_ref,source_inspected)
   VALUES(?,?,?,?,?,?,?)`,[reviewId,v.id,actor,data.decision,
    data.reason,data.evidenceRef,data.evidenceInspected]);
  await c.execute(`UPDATE inv_provider_org_credentials SET status=?
   WHERE id=? AND status='PENDING_INTERNAL'`,[data.decision,v.id]);
  await audit(c,actor,'CREDENTIAL',v.id,
   data.decision==='REVIEWED_CRYPTO_HELD'?'CREDENTIAL_REVIEWED':'CREDENTIAL_REJECTED',
   {decision:data.decision,credentialDigest:v.digest});
  await c.commit();
  res.status(201).json({reviewId,status:data.decision,
   corporateIdentityVerified:false,externalRootAuthenticated:false,
   officialGrnVerified:false,stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
export default router;
