import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {checkHeldSource} from '../evidenceChain/integrity';
import {readHeldGrnSource} from '../stockFoundation/integrity';
import {sha} from '../dispatch/validation';
import {ChainConflictError,candidatePublicKey,validateClaim,signedMessage,
 verifyDetachedSignature,messageDigest,verifyDeepFrozenSnapshot,
 type ProofKind} from './validation';
function deny():never{throw new ChainConflictError('Offline key, source, digest or signature integrity conflict');}
export async function readCandidate(conn:PoolConnection,keyId:string,reviewed:boolean){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,party_kind AS partyKind,
   supplier_id AS supplierId,site_id AS siteId,registered_by AS registeredBy,
   public_key_spki_b64 AS spkiB64,fingerprint_sha256 AS fingerprint,
   status FROM inv_proof_key_candidates WHERE id=? FOR UPDATE`,[keyId]);
 if(rows.length!==1)deny();
 const r=rows[0];
 const parsed=candidatePublicKey(r.spkiB64);
 if(parsed.fingerprint!==r.fingerprint||
  !['SUPPLIER','WAREHOUSE'].includes(r.partyKind)||
  (r.partyKind==='SUPPLIER'&&(!r.supplierId||r.siteId))||
  (r.partyKind==='WAREHOUSE'&&(!r.siteId||r.supplierId)))deny();
 if(reviewed){
  if(r.status!=='REVIEWED_UNTRUSTED')deny();
  const [reviews]=await conn.query<RowDataPacket[]>(`SELECT decision,
   reviewer_id AS reviewerId,document_inspected AS inspected
   FROM inv_proof_key_reviews WHERE key_id=?`,[keyId]);
  if(reviews.length!==1||reviews[0].decision!=='REVIEWED_UNTRUSTED'||
   reviews[0].reviewerId===r.registeredBy||
   Number(reviews[0].inspected)!==1)deny();
 }
 return {id:String(r.id),partyKind:r.partyKind as 'SUPPLIER'|'WAREHOUSE',
  partyId:String(r.partyKind==='SUPPLIER'?r.supplierId:r.siteId),
  registeredBy:String(r.registeredBy),status:String(r.status),
  publicKey:parsed.publicKey,spkiB64:parsed.spkiB64,fingerprint:parsed.fingerprint};
}
export async function readClaimSource(conn:PoolConnection,kind:ProofKind,sourceId:string){
 if(kind==='WAREHOUSE_GRN_ASSERTION'){
  const source=await readHeldGrnSource(conn,sourceId);
  return {sourceId,sourceSha256:source.heldGrnSha256,partyKind:'WAREHOUSE' as const,
   partyId:source.siteId,ownerId:source.ownerId};
 }
 const source=await checkHeldSource(conn,sourceId);
 return {sourceId,sourceSha256:source.outboxSha256,partyKind:'SUPPLIER' as const,
  partyId:source.supplierId,ownerId:source.ownerId};
}
export async function readVerifiedClaim(conn:PoolConnection,claimId:string){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,key_id AS keyId,
   claim_kind AS kind,created_by AS createdBy,
   dispatch_preparation_id AS preparationId,held_grn_id AS heldGrnId,
   source_sha256 AS sourceSha256,message_sha256 AS messageSha256,
   message_json AS messageJson,signature_b64 AS signatureB64,
   signature_matched AS matched,status
   FROM inv_signed_proof_claims WHERE id=?`,[claimId]);
 if(rows.length!==1)deny();
 const r=rows[0];
 const sourceId=String(r.kind==='WAREHOUSE_GRN_ASSERTION'?r.heldGrnId:r.preparationId);
 const key=await readCandidate(conn,String(r.keyId),true);
 const source=await readClaimSource(conn,r.kind,sourceId);
 const [locked]=await conn.query<RowDataPacket[]>(`SELECT message_sha256 AS digest,
  message_json AS payload,signature_b64 AS signatureB64,
  signature_matched AS matched,status
  FROM inv_signed_proof_claims WHERE id=? FOR UPDATE`,[claimId]);
 if(locked.length!==1||locked[0].digest!==r.messageSha256||
  locked[0].status!==r.status||locked[0].signatureB64!==r.signatureB64)deny();
 if(key.partyKind!==source.partyKind||key.partyId!==source.partyId||
  key.registeredBy!==source.ownerId||r.createdBy!==source.ownerId||
  r.sourceSha256!==source.sourceSha256||Number(r.matched)!==1||
  Number(locked[0].matched)!==1)deny();
 const raw=typeof locked[0].payload==='string'?
  JSON.parse(locked[0].payload):locked[0].payload;
 if(!raw||typeof raw!=='object')deny();
 const v=raw as Record<string,unknown>;
 const timestamp=String(v.issuedAt),reference=String(v.reference),documentSha256=String(v.documentSha256);
 const validated=validateClaim({keyId:r.keyId,kind:r.kind,sourceId,
  reference,documentSha256,issuedAt:timestamp,signatureB64:r.signatureB64});
 const message=signedMessage({...validated,sourceSha256:source.sourceSha256,
  partyId:source.partyId});
 const digest=messageDigest(message);
 if(digest!==r.messageSha256||!verifyDetachedSignature(key.publicKey,message,validated.signatureB64))deny();
 verifyDeepFrozenSnapshot(locked[0].payload,message,digest);
 const [block]=await conn.query<RowDataPacket[]>(`SELECT party_identity AS party,
  actual_po_issued AS po,supplier_ack_authenticated AS ack,
  official_grn_authenticated AS grn,stock_posting AS posting
  FROM inv_signed_proof_blockers WHERE claim_id=?`,[claimId]);
 if(block.length!==1||block[0].party!=='UNVERIFIED'||block[0].po!=='NO'||
  block[0].ack!=='NO'||block[0].grn!=='NO'||block[0].posting!=='DISABLED')deny();
 return {id:claimId,kind:r.kind as ProofKind,status:String(r.status),
  ownerId:source.ownerId,sourceId,sourceSha256:source.sourceSha256,
  partyId:source.partyId,partyKind:source.partyKind,keyId:key.id,
  keyFingerprint:key.fingerprint,messageSha256:digest,message,
  signatureB64:r.signatureB64};
}
