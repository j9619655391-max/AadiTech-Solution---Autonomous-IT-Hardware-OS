import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {readCandidate} from '../proofFoundation/integrity';
import {ChainConflictError,sha256,possessionMessage,verifyPossession} from './validation';
function deny():never{throw new ChainConflictError('Candidate key possession, review, rotation or source integrity mismatch');}
export async function inspectReceipt(conn:PoolConnection,receiptId:string,
 allowPendingRotation=false){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT r.id,r.challenge_id AS challengeId,
  r.key_id AS keyId,r.nonce_b64 AS nonceB64,r.signature_b64 AS signatureB64,
  r.signature_sha256 AS signatureSha256,r.status,
  c.prepared_by AS preparedBy,c.message_sha256 AS messageSha256,
  c.status AS challengeStatus,c.consumed_at AS consumedAt,c.expires_at AS expiresAt,
  (c.consumed_at<=c.expires_at) AS consumedOnTime
  FROM inv_key_possession_receipts r JOIN inv_key_possession_challenges c
   ON c.id=r.challenge_id
  WHERE r.id=?`,[receiptId]);
 if(rows.length!==1)deny();
 const r=rows[0],key=await readCandidate(conn,String(r.keyId),true,allowPendingRotation);
 const [locked]=await conn.query<RowDataPacket[]>(`SELECT r.id,r.nonce_b64 AS nonceB64,
   r.signature_b64 AS signatureB64,r.signature_sha256 AS signatureSha256,
   r.status,c.message_sha256 AS messageSha256,
   c.status AS challengeStatus,c.consumed_at AS consumedAt,
   (c.consumed_at<=c.expires_at) AS consumedOnTime
   FROM inv_key_possession_receipts r JOIN inv_key_possession_challenges c
   ON c.id=r.challenge_id WHERE r.id=? FOR UPDATE`,[receiptId]);
 if(locked.length!==1||r.preparedBy!==key.registeredBy||
  r.challengeStatus!=='MATCHED_INTERNAL'||locked[0].challengeStatus!=='MATCHED_INTERNAL'||
  r.status!=='MATCHED_INTERNAL'||locked[0].status!=='MATCHED_INTERNAL'||
  !r.consumedAt||!locked[0].consumedAt||Number(r.consumedOnTime)!==1||
  Number(locked[0].consumedOnTime)!==1||locked[0].messageSha256!==r.messageSha256||
  locked[0].nonceB64!==r.nonceB64||locked[0].signatureB64!==r.signatureB64||
  locked[0].signatureSha256!==r.signatureSha256)deny();
 const message=possessionMessage({challengeId:String(r.challengeId),keyId:key.id,
  keyFingerprint:key.fingerprint,partyKind:key.partyKind,partyId:key.partyId,
  nonceB64:r.nonceB64});
 if(sha256(JSON.stringify(message))!==r.messageSha256||
  sha256(Buffer.from(String(r.signatureB64),'base64').toString('hex'))!==r.signatureSha256||
  !verifyPossession(key.publicKey,message,String(r.signatureB64)))deny();
 return {id:receiptId,challengeId:String(r.challengeId),key,signatureB64:String(r.signatureB64),
  message,status:'MATCHED_INTERNAL' as const};
}
export async function independentlyReviewedPossession(conn:PoolConnection,keyId:string,
 allowPendingRotation=false){
 const key=await readCandidate(conn,keyId,true,allowPendingRotation);
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT p.id AS receiptId,
  v.id AS reviewId,v.reviewer_id AS reviewerId,
  v.decision,v.possession_inspected AS inspected
  FROM inv_key_possession_receipts p
  JOIN inv_key_possession_reviews v ON v.receipt_id=p.id
  WHERE p.key_id=? AND v.decision='REVIEWED_UNTRUSTED'
  ORDER BY v.created_at DESC,v.id DESC LIMIT 1`,[keyId]);
 if(rows.length!==1||rows[0].reviewerId===key.registeredBy||
  Number(rows[0].inspected)!==1)deny();
 const receipt=await inspectReceipt(conn,String(rows[0].receiptId),allowPendingRotation);
 if(receipt.key.id!==key.id)deny();
 return {key,receipt,reviewId:String(rows[0].reviewId)};
}
export async function inspectRotation(conn:PoolConnection,id:string){
 const [rows]=await conn.query<RowDataPacket[]>(`SELECT id,old_key_id AS oldKeyId,
  new_key_id AS newKeyId,prepared_by AS preparedBy,reason,evidence_ref AS evidenceRef,status
  FROM inv_key_rotation_proposals WHERE id=? FOR UPDATE`,[id]);
 if(rows.length!==1)deny();
 const r=rows[0];
 if(r.oldKeyId===r.newKeyId||r.status!=='PENDING_INTERNAL')deny();
 const old=await independentlyReviewedPossession(conn,String(r.oldKeyId),true);
 const fresh=await independentlyReviewedPossession(conn,String(r.newKeyId),true);
 if(old.key.registeredBy!==r.preparedBy||fresh.key.registeredBy!==r.preparedBy||
  old.key.partyKind!==fresh.key.partyKind||old.key.partyId!==fresh.key.partyId||
  old.key.fingerprint===fresh.key.fingerprint)deny();
 return {id,old,newKey:fresh,preparedBy:String(r.preparedBy),status:r.status};
}
