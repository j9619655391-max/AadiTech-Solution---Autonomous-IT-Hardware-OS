import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inventoryId} from '../inventory/validation';
import {readCandidate} from '../proofFoundation/integrity';
import {independentlyReviewedPossession} from './integrity';
import {ChainInputError,ChainConflictError,nonce,possessionMessage,sha256,
 keyIdBody,challengeResponse,reasonEvidence,rotationBody,verifyPossession} from './validation';
const router=Router();router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Key possession, one-time challenge, rotation or retirement is not independently authorized'});return;
 }
 console.error('Key lifecycle owner request denied',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Key lifecycle service unavailable'});
}
async function audit(c:PoolConnection,actor:string,entityType:string,id:string,
 event:string,details:object){
 await c.execute(`INSERT INTO inv_key_lifecycle_audit
 (id,actor_id,entity_type,entity_id,event_type,event_sha256)
 VALUES(?,?,?,?,?,?)`,[randomUUID(),actor,entityType,id,event,sha256(JSON.stringify(details))]);
}
router.get('/keys',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT k.id,k.party_kind AS partyKind,
   k.fingerprint_sha256 AS fingerprint,k.status,
   t.event_type AS retirement,
   x.id AS rotationId,x.status AS rotationState,
   (SELECT COUNT(*) FROM inv_key_possession_receipts p
    JOIN inv_key_possession_reviews v ON v.receipt_id=p.id
    WHERE p.key_id=k.id AND v.decision='REVIEWED_UNTRUSTED') AS reviewedPossessions
   FROM inv_proof_key_candidates k
   LEFT JOIN inv_key_retirements t ON t.key_id=k.id
   LEFT JOIN inv_key_rotation_proposals x ON x.old_key_id=k.id
   WHERE k.registered_by=? ORDER BY k.created_at DESC,k.id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalIdentityAuthenticated:false,
   cryptographicPossessionIsOnlyInternal:true});
 }catch(e){fail(res,e);}
});
router.post('/challenges',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof keyIdBody>;
 try{input=keyIdBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId),key=await readCandidate(c,input.keyId,true);
  if(key.registeredBy!==actor){await c.rollback();res.status(404).json({error:'No eligible candidate for owner'});return;}
  const challengeId=randomUUID(),nonceB64=nonce();
  const message=possessionMessage({challengeId,keyId:key.id,keyFingerprint:key.fingerprint,
   partyKind:key.partyKind,partyId:key.partyId,nonceB64});
  const digest=sha256(JSON.stringify(message));
  const expiry=new Date(Math.floor(Date.now()/1000)*1000+10*60_000);
  await c.execute(`INSERT INTO inv_key_possession_challenges
    (id,key_id,prepared_by,message_sha256,expires_at) VALUES(?,?,?,?,?)`,
    [challengeId,key.id,actor,digest,expiry.toISOString().slice(0,19).replace('T',' ')]);
  await audit(c,actor,'CHALLENGE',challengeId,'CHALLENGE_ISSUED',{keyId:key.id,digest});
  await c.commit();
  res.status(201).json({challengeId,message,canonicalUtf8:JSON.stringify(message),
   messageSha256:digest,expiresAt:expiry.toISOString(),algorithm:'Ed25519',
   trustState:'UNVERIFIED',identityAuthenticated:false,
   note:'Challenge nonce disclosed once. Sign exact bytes OFFLINE; do not upload private keys.'});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.post('/responses',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof challengeResponse>;
 try{input=challengeResponse(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  // First locate key, then lock candidate before challenge to maintain lock order with revocations.
  const [refs]=await c.query<RowDataPacket[]>(`SELECT key_id AS keyId FROM inv_key_possession_challenges
   WHERE id=?`,[input.challengeId]);
  if(refs.length!==1)throw new ChainConflictError('Missing challenge');
  const key=await readCandidate(c,String(refs[0].keyId),true);
  if(key.registeredBy!==actor){await c.rollback();res.status(404).json({error:'No eligible challenge for owner'});return;}
  const [rows]=await c.query<RowDataPacket[]>(`SELECT id,key_id AS keyId,prepared_by AS preparedBy,
   message_sha256 AS messageSha256,status,
   (expires_at>UTC_TIMESTAMP(3)) AS unexpired
   FROM inv_key_possession_challenges WHERE id=? FOR UPDATE`,[input.challengeId]);
  if(rows.length!==1||rows[0].keyId!==key.id||rows[0].preparedBy!==actor||
   rows[0].status!=='ISSUED'||Number(rows[0].unexpired)!==1)
   throw new ChainConflictError('Expired, consumed or invalid one-time challenge');
  const message=possessionMessage({challengeId:input.challengeId,keyId:key.id,
   keyFingerprint:key.fingerprint,partyKind:key.partyKind,partyId:key.partyId,
   nonceB64:input.nonceB64});
  if(sha256(JSON.stringify(message))!==rows[0].messageSha256||
   !verifyPossession(key.publicKey,message,input.signatureB64))
   throw new ChainConflictError('Challenge or detached signature does not match');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_key_possession_receipts
   (id,challenge_id,key_id,nonce_b64,signature_b64,signature_sha256)
   VALUES(?,?,?,?,?,?)`,[id,input.challengeId,key.id,input.nonceB64,
    input.signatureB64,sha256(Buffer.from(input.signatureB64,'base64').toString('hex'))]);
  await c.execute(`UPDATE inv_key_possession_challenges
    SET status='MATCHED_INTERNAL',consumed_at=UTC_TIMESTAMP(3)
    WHERE id=? AND status='ISSUED'`,[input.challengeId]);
  await audit(c,actor,'POSSESSION',id,'POSSESSION_MATCHED',{
   keyId:key.id,challengeId:input.challengeId,digest:rows[0].messageSha256});
  await c.commit();
  res.status(201).json({receiptId:id,status:'MATCHED_INTERNAL',
   internalSignatureMatched:true,externallyVerifiedKeyOwner:false,
   supplierIdentityAuthenticated:false,officialGrnVerified:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/receipts',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT p.id AS receiptId,p.key_id AS keyId,
   p.status,v.decision AS reviewState,p.created_at AS createdAt
   FROM inv_key_possession_receipts p
   JOIN inv_proof_key_candidates k ON k.id=p.key_id
   LEFT JOIN inv_key_possession_reviews v ON v.receipt_id=p.id
   WHERE k.registered_by=? ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,
   [res.locals.auth.userId]);
  res.json({items:rows,sourceIdentityAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/keys/:id/revoke',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 if(!inventoryId(req.params.id)){res.status(400).json({error:'Invalid key ID'});return;}
 let data:ReturnType<typeof reasonEvidence>;
 try{data=reasonEvidence(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [keys]=await c.query<RowDataPacket[]>(`SELECT registered_by AS registeredBy
   FROM inv_proof_key_candidates WHERE id=? FOR UPDATE`,[req.params.id]);
  if(keys.length!==1||keys[0].registeredBy!==actor){
   await c.rollback();res.status(404).json({error:'Key unavailable for revoking owner'});return;
  }
  const [prior]=await c.query<RowDataPacket[]>(`SELECT key_id FROM inv_key_retirements
   WHERE key_id=?`,[req.params.id]);
  if(prior.length)throw new ChainConflictError('Irreversible revocation already recorded');
  await c.execute(`INSERT INTO inv_key_retirements
   (key_id,initiated_by,reason,evidence_ref,event_type)
   VALUES (?,?,?,?,'EMERGENCY_REVOKED')`,[req.params.id,actor,data.reason,data.evidenceRef]);
  await audit(c,actor,'KEY',req.params.id,'EMERGENCY_REVOKED',{reason:data.reason,
   evidenceRef:data.evidenceRef});
  await c.commit();
  res.status(201).json({keyId:req.params.id,status:'REVOKED_INTERNAL',
   irreversible:true,externalTrustEstablished:false,newSignaturesAccepted:false,
   existingClaimsRevalidatedAsCurrent:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
router.get('/rotations',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,old_key_id AS oldKeyId,
   new_key_id AS newKeyId,status,reason,evidence_ref AS evidenceRef
   FROM inv_key_rotation_proposals WHERE prepared_by=?
   ORDER BY created_at DESC,id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalTrustEstablished:false,oldKeySuspendedWhenPending:true});
 }catch(e){fail(res,e);}
});
router.post('/rotations',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let data:ReturnType<typeof rotationBody>;
 try{data=rotationBody(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let c:PoolConnection|undefined;
 try{
  c=await db.getConnection();await c.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const old=await independentlyReviewedPossession(c,data.oldKeyId);
  const fresh=await independentlyReviewedPossession(c,data.newKeyId);
  if(old.key.registeredBy!==actor||fresh.key.registeredBy!==actor||
   old.key.partyKind!==fresh.key.partyKind||old.key.partyId!==fresh.key.partyId)
   throw new ChainConflictError('Rotated candidate must have same owner/party and separate reviewed possession');
  const id=randomUUID();
  await c.execute(`INSERT INTO inv_key_rotation_proposals
   (id,old_key_id,new_key_id,prepared_by,reason,evidence_ref)
   VALUES(?,?,?,?,?,?)`,
   [id,data.oldKeyId,data.newKeyId,actor,data.reason,data.evidenceRef]);
  await audit(c,actor,'ROTATION',id,'ROTATION_PROPOSED',{
   oldKeyFingerprint:old.key.fingerprint,newKeyFingerprint:fresh.key.fingerprint});
  await c.commit();
  res.status(201).json({rotationId:id,status:'PENDING_INTERNAL',
   oldKeySuspended:true,newKeySuspended:true,externalTrustEstablished:false,
   stockPostingEnabled:false});
 }catch(e){if(c)await c.rollback().catch(()=>{});fail(res,e);}
 finally{c?.release();}
});
export default router;
