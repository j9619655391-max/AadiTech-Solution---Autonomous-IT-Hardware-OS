import {randomUUID} from 'node:crypto';
import {Router,type Response} from 'express';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner,requireStepUp} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {ChainInputError,ChainConflictError,validateKey,validateClaim,
 validateTemplate,signedMessage,verifyDetachedSignature,messageDigest} from './validation';
import {readCandidate,readClaimSource} from './integrity';
import {sha} from '../dispatch/validation';
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
function fail(res:Response,e:unknown){
 if(e instanceof ChainInputError){res.status(400).json({error:e.message});return;}
 if(e instanceof ChainConflictError||(e&&typeof e==='object'&&'code' in e&&e.code==='ER_DUP_ENTRY')){
  res.status(409).json({error:'Offline signed-evidence source, identity or immutable record conflict'});return;
 }
 console.error('Offline signed proof request failed',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Offline proof prerequisite service unavailable'});
}
async function audit(c:PoolConnection,actor:string,entity:'KEY'|'CLAIM',id:string,
 event:'KEY_REGISTERED'|'SIGNED_CLAIM_RECORDED',details:object){
 await c.execute(`INSERT INTO inv_signed_proof_audit
  (id,actor_id,entity_type,entity_id,event_type,event_sha256) VALUES (?,?,?,?,?,?)`,
  [randomUUID(),actor,entity,id,event,sha(JSON.stringify(details))]);
}
router.get('/keys',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,party_kind AS partyKind,
   supplier_id AS supplierId,site_id AS siteId,
   fingerprint_sha256 AS fingerprintSha256,status,evidence_ref AS evidenceRef,
   created_at AS createdAt
   FROM inv_proof_key_candidates WHERE registered_by=?
   ORDER BY created_at DESC,id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,externalKeyOwnershipVerified:false,trustAnchorEstablished:false});
 }catch(e){fail(res,e);}
});
router.post('/keys',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateKey>;
 try{input=validateKey(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const [party]=input.partyKind==='SUPPLIER'?
   await conn.query<RowDataPacket[]>(`SELECT id FROM proc_suppliers
    WHERE id=? AND created_by=? AND status='REVIEWED_INTERNAL' FOR UPDATE`,
    [input.partyId,actor]):
   await conn.query<RowDataPacket[]>(`SELECT id FROM inventory_sites
    WHERE id=? AND created_by=? FOR UPDATE`,[input.partyId,actor]);
  if(party.length!==1){await conn.rollback();res.status(404).json({error:'No registered internal party for owner'});return;}
  const [existing]=await conn.query<RowDataPacket[]>(`SELECT id,party_kind AS kind,
   supplier_id AS supplierId,site_id AS siteId,
   evidence_ref AS evidenceRef,status
   FROM inv_proof_key_candidates WHERE fingerprint_sha256=? FOR UPDATE`,[input.fingerprint]);
  if(existing.length){
   const prior=existing[0];
   if(prior.kind!==input.partyKind||
    String(prior.supplierId??prior.siteId)!==input.partyId||prior.evidenceRef!==input.evidenceRef)
    throw new ChainConflictError('Key fingerprint already bound to distinct party/evidence');
   await conn.commit();
   res.status(200).json({id:prior.id,status:prior.status,replayed:true,
    externalKeyOwnershipVerified:false});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_proof_key_candidates
   (id,party_kind,supplier_id,site_id,registered_by,
    public_key_spki_b64,fingerprint_sha256,evidence_ref)
   VALUES(?,?,?,?,?,?,?,?)`,
   [id,input.partyKind,input.partyKind==='SUPPLIER'?input.partyId:null,
    input.partyKind==='WAREHOUSE'?input.partyId:null,
    actor,input.spkiB64,input.fingerprint,input.evidenceRef]);
  await audit(conn,actor,'KEY',id,'KEY_REGISTERED',{
   partyKind:input.partyKind,partyId:input.partyId,fingerprint:input.fingerprint});
  await conn.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',fingerprintSha256:input.fingerprint,
   externalKeyOwnershipVerified:false,trustAnchorEstablished:false,
   message:'Owner-submitted key is a CANDIDATE only. No trusted vendor or warehouse identity established.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/sources',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const actor=res.locals.auth.userId;
  const [dispatch]=await db.query<RowDataPacket[]>(`SELECT p.id AS sourceId,
   d.supplier_id AS partyId,o.snapshot_sha256 AS sourceSha256,
   'SUPPLIER' AS partyKind FROM proc_dispatch_preparations p
   JOIN proc_delivery_destinations d ON d.id=p.destination_id
   JOIN proc_dispatch_outbox_holds o ON o.preparation_id=p.id
   WHERE p.prepared_by=? AND p.status='APPROVED_INTERNAL'
   AND o.state='HELD' AND o.dispatch_state='DISABLED'
   ORDER BY p.created_at DESC,p.id DESC LIMIT 100`,[actor]);
  const [warehouse]=await db.query<RowDataPacket[]>(`SELECT h.id AS sourceId,
   i.site_id AS partyId,h.snapshot_sha256 AS sourceSha256,
   'WAREHOUSE' AS partyKind
   FROM inv_grn_held_records h
   JOIN inv_grn_reconciliation_packs p ON p.id=h.pack_id
   JOIN inv_inbound_observations i ON i.id=p.observation_id
   WHERE p.prepared_by=? AND h.status='HELD' AND h.stock_posting_state='DISABLED'
   ORDER BY h.created_at DESC,h.id DESC LIMIT 100`,[actor]);
  res.json({items:[...dispatch,...warehouse],verifiedExternally:false,
   actualSupplierOrderIssued:false,officialGrn:false});
 }catch(e){fail(res,e);}
});
async function canonicalOwnerMessage(conn:PoolConnection,actor:string,input:ReturnType<typeof validateTemplate>){
 const key=await readCandidate(conn,input.keyId,true);
 const source=await readClaimSource(conn,input.kind,input.sourceId);
 if(key.partyKind!==source.partyKind||key.partyId!==source.partyId||
  source.ownerId!==actor||key.registeredBy!==actor)
  throw new ChainConflictError('Key candidate not bound to internally held source/owner');
 const message=signedMessage({...input,sourceSha256:source.sourceSha256,partyId:source.partyId});
 return {key,source,message,digest:messageDigest(message)};
}
router.get('/message-template',async(req,res)=>{
 let input:ReturnType<typeof validateTemplate>;
 try{input=validateTemplate(req.query);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const result=await canonicalOwnerMessage(conn,String(res.locals.auth.userId),input);
  await conn.commit();
  res.json({message:result.message,canonicalUtf8:JSON.stringify(result.message),
   messageSha256:result.digest,algorithm:'Ed25519',
   trustAnchorEstablished:false,officialGrnAuthenticated:false,
   warning:'Sign this EXACT UTF-8 string only for offline cryptographic practice. Registered key is not verified supplier/warehouse identity.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/claims',async(req,res)=>{
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 try{
  const [rows]=await db.query<RowDataPacket[]>(`SELECT id,claim_kind AS kind,
   key_id AS keyId,dispatch_preparation_id AS preparationId,
   held_grn_id AS heldGrnId,message_sha256 AS messageSha256,
   signature_matched AS signatureMatched,status,created_at AS createdAt
   FROM inv_signed_proof_claims WHERE created_by=?
   ORDER BY created_at DESC,id DESC LIMIT 100`,[res.locals.auth.userId]);
  res.json({items:rows,issuerAuthenticated:false,warehouseGrnAuthenticated:false});
 }catch(e){fail(res,e);}
});
router.post('/claims',requirePrivilegedMfa,requireStepUp,async(req,res)=>{
 let input:ReturnType<typeof validateClaim>;
 try{input=validateClaim(req.body);}catch(e){fail(res,e);return;}
 const db=getPool();if(!db){res.status(503).json({error:'Database unavailable'});return;}
 let conn:PoolConnection|undefined;
 try{
  conn=await db.getConnection();await conn.beginTransaction();
  const actor=String(res.locals.auth.userId);
  const {signatureB64,...unsigned}=input;
  const prepared=await canonicalOwnerMessage(conn,actor,unsigned);
  if(!verifyDetachedSignature(prepared.key.publicKey,prepared.message,signatureB64))
   throw new ChainConflictError('Detached signature does not match registered candidate key and frozen source');
  const [prior]=await conn.query<RowDataPacket[]>(`SELECT id,key_id AS keyId,
   message_sha256 AS messageSha256,signature_b64 AS signatureB64,status
   FROM inv_signed_proof_claims
   WHERE claim_kind=? AND (dispatch_preparation_id=? OR held_grn_id=?)
   FOR UPDATE`,[input.kind,input.kind==='WAREHOUSE_GRN_ASSERTION'?null:input.sourceId,
    input.kind==='WAREHOUSE_GRN_ASSERTION'?input.sourceId:null]);
  if(prior.length){
   if(prior[0].keyId!==input.keyId||prior[0].messageSha256!==prepared.digest||
    prior[0].signatureB64!==signatureB64)
    throw new ChainConflictError('Different signed claim already bound to frozen source');
   await conn.commit();
   res.status(200).json({id:prior[0].id,status:prior[0].status,replayed:true,
    detachedSignatureMatched:true,identityAuthenticated:false,officialGrnVerified:false});return;
  }
  const id=randomUUID();
  await conn.execute(`INSERT INTO inv_signed_proof_claims
   (id,key_id,created_by,claim_kind,dispatch_preparation_id,held_grn_id,
    source_sha256,message_sha256,message_json,signature_b64,signature_matched)
   VALUES(?,?,?,?,?,?,?,?,?,?,1)`,
   [id,input.keyId,actor,input.kind,
    input.kind==='WAREHOUSE_GRN_ASSERTION'?null:input.sourceId,
    input.kind==='WAREHOUSE_GRN_ASSERTION'?input.sourceId:null,
    prepared.source.sourceSha256,prepared.digest,JSON.stringify(prepared.message),signatureB64]);
  await conn.execute(`INSERT INTO inv_signed_proof_blockers(claim_id) VALUES(?)`,[id]);
  await audit(conn,actor,'CLAIM',id,'SIGNED_CLAIM_RECORDED',{
   kind:input.kind,sourceId:input.sourceId,messageSha256:prepared.digest,
   keyFingerprint:prepared.key.fingerprint});
  await conn.commit();
  res.status(201).json({id,status:'PENDING_INTERNAL',messageSha256:prepared.digest,
   detachedSignatureMatched:true,issuerAuthenticated:false,officialGrnVerified:false,
   stockPostingEnabled:false,replayed:false,
   message:'Ed25519 signature matches SELF-REGISTERED key only. No external source authentication, issued PO or GRN.'});
 }catch(e){if(conn)await conn.rollback().catch(()=>{});fail(res,e);}
 finally{conn?.release();}
});
router.get('/authority',(_req,res)=>{
 res.json({publicKeysTrusted:false,externalPoIssued:false,
  supplierAcknowledgmentAuthenticated:false,officialGrnAuthenticated:false,
  warehouseReceiptAuthorized:false,stockLedgerEnabled:false,
  serialOwnershipEstablished:false,availableToSell:null,stockPostingState:'DISABLED'});
});
export default router;
