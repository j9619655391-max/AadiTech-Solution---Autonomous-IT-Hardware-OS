import {createHash,createPublicKey,verify} from 'node:crypto';
import type {Pool,RowDataPacket} from 'mysql2/promise';
import {phase1AwCheckpointSigningBytes,phase1AwCheckpointReceiptSha256}
 from '../../scripts/lib/phase1AwSignedCheckpoint.mjs';

// No API route, provider credential, signer enrollment, release or real authority.
// This is an isolated, offline, internal-evidence ledger for CI/disposable staging.
type Pin={role:'LEGAL'|'SECURITY';reviewerRef:string;keyId:string;publicKeyPem:string;publicKeySha256:string};
type Checkpoint={signatures:Array<{role:string;reviewerRef:string;keyId:string;signatureBase64:string}>;
 sequence:number;providerCode:string;requestedScope:string;issuedAt:string;expiresAt:string;
 priorCheckpointSha256:string|null;[key:string]:unknown};
type Outcome='ACCEPTED_UNTRUSTED'|'REPLAY'|'REPLAY_VARIANT'|'FORK'|'ROLLBACK'|'GAP'|'UNAUTHORIZED_KEY_CHANGE'|'QUARANTINED_OBSERVATION';
const OPAQUE=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const PUBLIC_PEM=/^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----\n?$/;
const PREFIX='AADITECH-PHASE-1AX-RECEIPT-CLAIM-V1\0';

export function axEvidenceWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.AX_CHECKPOINT_EVIDENCE_WRITE_APPROVED==='YES'&&
   env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
   /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&
   env.DB_SSL==='true'&&env.NODE_ENV!=='production')return 'staging';
 throw Error('Phase 1AX write restricted to disposable CI or explicitly approved isolated TLS staging');
}
function validate(checkpoint:Checkpoint,pins:Pin[],now:Date){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime()))throw Error('Invalid clock');
 if(!Array.isArray(pins)||pins.length!==2||!Array.isArray(checkpoint?.signatures)||
    checkpoint.signatures.length!==2)throw Error('Two pinned reviewer signatures required');
 // The previous Phase 1AW routine checks exact schema and canonical signature
 // encodings before calculating a receipt. It never grants provider authority.
 const receipt=phase1AwCheckpointReceiptSha256(checkpoint);
 const {signatures,...body}=checkpoint;
 const message=phase1AwCheckpointSigningBytes(body);
 if(Date.parse(checkpoint.issuedAt)>now.getTime()+5*60000||
    Date.parse(checkpoint.expiresAt)<=now.getTime())throw Error('Expired or future checkpoint');
 const refs=new Set<string>(),ids=new Set<string>();
 for(let i=0;i<2;i++){
  const pin=pins[i],sig=checkpoint.signatures[i];
  if(!pin||!sig||pin.role!==(i===0?'LEGAL':'SECURITY')||
     sig.role!==pin.role||sig.reviewerRef!==pin.reviewerRef||sig.keyId!==pin.keyId||
     !OPAQUE.test(pin.reviewerRef)||!OPAQUE.test(pin.keyId)||!SHA.test(pin.publicKeySha256)||
     refs.has(pin.reviewerRef)||ids.has(pin.keyId))throw Error('Reviewer pin role/identity mismatch');
  refs.add(pin.reviewerRef);ids.add(pin.keyId);
  if(typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>1024||
     !PUBLIC_PEM.test(pin.publicKeyPem))throw Error('Only bounded public SPKI pins permitted');
  const pub=createPublicKey(pin.publicKeyPem);
  if(pub.asymmetricKeyType!=='ed25519'||
     createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')!==pin.publicKeySha256)
   throw Error('Invalid pinned Ed25519 key fingerprint');
  if(!verify(null,message,pub,Buffer.from(sig.signatureBase64,'base64')))
   throw Error('Invalid detached checkpoint signature');
 }
 return {receipt,claim:createHash('sha256').update(PREFIX).update(message).digest('hex'),
  signerPinHash:createHash('sha256').update('AADITECH-PHASE-1AX-PIN-COMMITMENT-V1\\0')
   .update(JSON.stringify(pins.map(p=>[p.role,p.reviewerRef,p.keyId,p.publicKeySha256]))).digest('hex')};
}
export interface AxWriteArgs{
 logRef:string;checkpoint:Checkpoint;pins:Pin[];now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1AxOfflineCheckpoint(pool:Pool,{
 logRef,checkpoint,pins,now=new Date(),env=process.env
}:AxWriteArgs){
 axEvidenceWriteTarget(env);
 if(typeof logRef!=='string'||!OPAQUE.test(logRef))throw Error('Invalid checkpoint log reference');
 if(Buffer.byteLength(JSON.stringify(checkpoint),'utf8')>8192)
  throw Error('Checkpoint evidence exceeds bounded storage limit');
 const {receipt,claim,signerPinHash}=validate(checkpoint,pins,now);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // A single row for each opaque log is the per-stream InnoDB mutex. Concurrent
  // inserts serialize here; the SELECT FOR UPDATE sees the latest committed head.
  await conn.execute(`INSERT INTO inv_ax_checkpoint_streams
    (log_ref,provider_code,requested_scope) VALUES (?,?,?)
    ON DUPLICATE KEY UPDATE log_ref=log_ref`,
    [logRef,checkpoint.providerCode,checkpoint.requestedScope]);
  const [heads]=await conn.execute<RowDataPacket[]>(
    `SELECT provider_code,requested_scope,last_sequence,last_receipt_sha256,
       last_claim_sha256,last_signer_pin_sha256,governance_state FROM inv_ax_checkpoint_streams
       WHERE log_ref=? FOR UPDATE`,[logRef]);
  const head=heads[0];
  if(!head||head.provider_code!==checkpoint.providerCode||
     head.requested_scope!==checkpoint.requestedScope)
   throw Error('Log scope identity mismatch');
  const priorSeq=Number(head.last_sequence);
  if(!Number.isSafeInteger(priorSeq))throw Error('Unsafe persisted sequence');
  const [existing]=await conn.execute<RowDataPacket[]>(
    `SELECT outcome FROM inv_ax_checkpoint_observations
       WHERE log_ref=? AND receipt_sha256=? FOR UPDATE`,[logRef,receipt]);
  if(existing.length){
   await conn.commit();
   return Object.freeze({phase:'1AX',outcome:'REPLAY' as Outcome,
    governanceState:head.governance_state as string,duplicateReceipt:true,
    productionReleaseAuthorized:false,releaseDecision:'HOLD'});
  }
  let outcome:Outcome;
  if(head.governance_state==='QUARANTINED')outcome='QUARANTINED_OBSERVATION';
  else if(priorSeq>0&&head.last_signer_pin_sha256!==signerPinHash)outcome='UNAUTHORIZED_KEY_CHANGE';
  else if(priorSeq===0)
   outcome=checkpoint.sequence===1&&checkpoint.priorCheckpointSha256===null?
    'ACCEPTED_UNTRUSTED':'GAP';
  else if(checkpoint.sequence===priorSeq)
   outcome=head.last_claim_sha256===claim?'REPLAY_VARIANT':'FORK';
  else if(checkpoint.sequence<priorSeq)outcome='ROLLBACK';
  else if(checkpoint.sequence!==priorSeq+1)outcome='GAP';
  else if(checkpoint.priorCheckpointSha256!==head.last_receipt_sha256)outcome='FORK';
  else outcome='ACCEPTED_UNTRUSTED';
  await conn.execute(`INSERT INTO inv_ax_checkpoint_observations
    (log_ref,checkpoint_sequence,receipt_sha256,claim_sha256,signer_pin_sha256,prior_receipt_sha256,
     outcome,signed_checkpoint_json) VALUES (?,?,?,?,?,?,?,?)`,
    [logRef,checkpoint.sequence,receipt,claim,signerPinHash,checkpoint.priorCheckpointSha256,
     outcome,JSON.stringify(checkpoint)]);
  if(outcome==='ACCEPTED_UNTRUSTED'){
   await conn.execute(`UPDATE inv_ax_checkpoint_streams SET last_sequence=?,
      last_receipt_sha256=?,last_claim_sha256=?,last_signer_pin_sha256=? WHERE log_ref=?`,
    [checkpoint.sequence,receipt,claim,signerPinHash,logRef]);
  }else if(['FORK','ROLLBACK','GAP','UNAUTHORIZED_KEY_CHANGE'].includes(outcome)){
   await conn.execute(`UPDATE inv_ax_checkpoint_streams
      SET governance_state='QUARANTINED' WHERE log_ref=?`,[logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1AX',outcome,governanceState:
    ['FORK','ROLLBACK','GAP','UNAUTHORIZED_KEY_CHANGE'].includes(outcome)?'QUARANTINED':head.governance_state as string,
    duplicateReceipt:false,productionReleaseAuthorized:false,releaseDecision:'HOLD'});
 }catch(error){await conn.rollback();throw error;}
 finally{conn.release();}
}
export async function inspectPhase1AxOfflineHistory(pool:Pool,logRef:string,env:NodeJS.ProcessEnv=process.env){
 axEvidenceWriteTarget(env);
 if(typeof logRef!=='string'||!OPAQUE.test(logRef))throw Error('Invalid log reference');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [heads]=await conn.execute<RowDataPacket[]>(
   `SELECT * FROM inv_ax_checkpoint_streams WHERE log_ref=? FOR UPDATE`,[logRef]);
  if(heads.length!==1)throw Error('Missing checkpoint stream');
  const [rows]=await conn.execute<RowDataPacket[]>(`SELECT * FROM
   inv_ax_checkpoint_observations WHERE log_ref=? ORDER BY id FOR UPDATE`,[logRef]);
  const problems:string[]=[];let lastSequence=0,lastReceipt:string|null=null;
  let lastClaim:string|null=null,lastPin:string|null=null;
  for(const item of rows){
   const cp=typeof item.signed_checkpoint_json==='string'?
    JSON.parse(item.signed_checkpoint_json):item.signed_checkpoint_json;
   try{
    const {signatures,...body}=cp;
    const receipt=phase1AwCheckpointReceiptSha256(cp);
    const claim=createHash('sha256').update(PREFIX)
      .update(phase1AwCheckpointSigningBytes(body)).digest('hex');
    if(receipt!==item.receipt_sha256||claim!==item.claim_sha256||
      cp.sequence!==Number(item.checkpoint_sequence)||
      cp.priorCheckpointSha256!==item.prior_receipt_sha256)
     problems.push('OBSERVATION_DIGEST_MISMATCH');
   }catch{problems.push('OBSERVATION_INVALID');}
   if(item.outcome==='ACCEPTED_UNTRUSTED'){
    if(Number(item.checkpoint_sequence)!==lastSequence+1||
       item.prior_receipt_sha256!==lastReceipt)
     problems.push('ACCEPTED_HISTORY_GAP');
    lastSequence=Number(item.checkpoint_sequence);
    lastReceipt=item.receipt_sha256;lastClaim=item.claim_sha256;lastPin=item.signer_pin_sha256;
   }
   if(['FORK','ROLLBACK','GAP','UNAUTHORIZED_KEY_CHANGE'].includes(item.outcome)&&
      heads[0].governance_state!=='QUARANTINED')
    problems.push('INCIDENT_WITHOUT_QUARANTINE');
  }
  if(lastSequence!==Number(heads[0].last_sequence)||
     lastReceipt!==heads[0].last_receipt_sha256||
     lastClaim!==heads[0].last_claim_sha256||
     lastPin!==heads[0].last_signer_pin_sha256)problems.push('HEAD_DIVERGES_FROM_ACCEPTED_HISTORY');
  await conn.commit();
  return Object.freeze({phase:'1AX',logRef,acceptedSequence:lastSequence,
    observationCount:rows.length,governanceState:heads[0].governance_state as string,
    localHistoryConsistent:problems.length===0,
    anomalyCodes:Object.freeze([...new Set(problems)].sort()),
    immutableExternalStorageVerified:false,externalReviewersAuthenticated:false,
    productionReleaseAuthorized:false,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}
 finally{conn.release();}
}
