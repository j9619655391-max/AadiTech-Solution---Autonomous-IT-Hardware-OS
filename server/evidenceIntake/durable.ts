import type {Pool,RowDataPacket,ResultSetHeader} from 'mysql2/promise';
import {assessPhase1BbEvidenceIntake} from '../../scripts/lib/phase1BbEvidenceIntake.mjs';

// Offline digest-only intake; no raw signatures, public keys, evidence objects,
// contract or personal data are persisted. This is NOT immutable storage.
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
export function bbWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.NODE_ENV==='test'&&env.DB_NAME==='aaditech_ci')
  return 'ci';
 if(env.NODE_ENV!=='production'&&env.BB_EVIDENCE_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&env.DB_SSL==='true'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))return 'staging';
 throw Error('Phase 1BB ingestion is restricted to disposable CI or approved TLS staging');
}
export interface BbEvidenceArgs{
 azPacket:any;records:any[];sequence:number;previousBatchSha256:string|null;
 now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BbEvidence(pool:Pool,{
 azPacket,records,sequence,previousBatchSha256,now=new Date(),env=process.env
}:BbEvidenceArgs){
 bbWriteTarget(env);
 if(!Number.isSafeInteger(sequence)||sequence<1||sequence>1000000||
   (previousBatchSha256!==null&&
    (typeof previousBatchSha256!=='string'||!SHA.test(previousBatchSha256))))
  throw Error('Phase 1BB invalid sequence or prior hash');
 if(Buffer.byteLength(JSON.stringify({azPacket,records}),'utf8')>24000)
  throw Error('Phase 1BB bounded offline evidence limit exceeded');
 const a=assessPhase1BbEvidenceIntake({azPacket,records,now});
 const logRef=azPacket?.archive?.logRef;
 if(!a.internalEvidenceConsistent||typeof logRef!=='string'||!ID.test(logRef)||
    typeof a.batchSha256!=='string'||!SHA.test(a.batchSha256))
  throw Error('Phase 1BB unauthenticated, malformed or conflicting digest claims refused');
 const hash=a.batchSha256,claims=a.challengeDigests;
 const conn=await pool.getConnection();
 let globalNonceMutex=false;
 try{
  // Each batch touches six globally unique nonce keys. Two unrelated logs
  // must serialize nonce reservation BEFORE acquiring their stream locks,
  // otherwise InnoDB inserts can form cross-log deadlock cycles.
  // This local MySQL advisory mutex is for isolated CI/staging only;
  // it is not a multi-primary distributed lock or external trust evidence.
  const [lease]=await conn.query<RowDataPacket[]>(
   "SELECT GET_LOCK('aaditech-bb-global-nonces',15) AS acquired");
  if(Number(lease[0]?.acquired)!==1)
   throw Error('Phase 1BB global nonce custody mutex unavailable');
  globalNonceMutex=true;
  await conn.beginTransaction();
  await conn.execute(
   'INSERT INTO inv_bb_evidence_streams (log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',
   [logRef]);
  const [headRows]=await conn.execute<RowDataPacket[]>(
   'SELECT last_sequence,last_batch_sha256,governance_state FROM inv_bb_evidence_streams WHERE log_ref=? FOR UPDATE',
   [logRef]);
  const head=headRows[0];
  if(!head)throw Error('Phase 1BB missing serializable stream');
  // Freeze propagates into the prior signed-intake ledger as well as BC/BD.
  // Lock order BB -> BE agrees with BE freeze's AZ -> BB -> BC -> BD -> BE.
  const [freezes]=await conn.execute<RowDataPacket[]>(
   'SELECT state FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(freezes.length&&freezes[0].state!=='HELD_UNVERIFIED')
   throw Error('Phase 1BE emergency witness revocation freeze blocks BB batch writes');
  const latest=Number(head.last_sequence);
  if(!Number.isSafeInteger(latest))throw Error('Phase 1BB invalid persisted sequence');
  if(latest===sequence&&head.last_batch_sha256===hash){
   await conn.commit();
   return Object.freeze({phase:'1BB',outcome:'REPLAY',governanceState:head.governance_state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  const [alreadyRejected]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bb_evidence_attempts WHERE log_ref=? AND batch_sha256=? AND outcome<>'ACCEPTED_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,hash]);
  if(alreadyRejected.length){
   await conn.commit();
   return Object.freeze({phase:'1BB',outcome:'DUPLICATE_REJECTED',governanceState:head.governance_state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(head.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(latest===0)
   outcome=sequence===1&&previousBatchSha256===null?
    'ACCEPTED_UNVERIFIED':'GAP_QUARANTINED';
  else if(sequence<=latest)
   outcome=sequence===latest?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(sequence!==latest+1)outcome='GAP_QUARANTINED';
  else if(previousBatchSha256!==head.last_batch_sha256)
   outcome='PREDECESSOR_QUARANTINED';
  else outcome='ACCEPTED_UNVERIFIED';

  if(outcome==='ACCEPTED_UNVERIFIED'){
   // SAVEPOINT makes the six nonce claims all-or-nothing even when a later
   // nonce is globally reused across two different concurrent log streams.
   await conn.query('SAVEPOINT bb_nonce_batch');
   for(const challenge of claims){
    const [result]=await conn.execute<ResultSetHeader>(
     'INSERT IGNORE INTO inv_bb_evidence_nonce_claims (challenge_sha256,log_ref,batch_sha256) VALUES (?,?,?)',
     [challenge,logRef,hash]);
    if(result.affectedRows!==1){
     outcome='NONCE_REPLAY_QUARANTINED';
     break;
    }
   }
   if(outcome!=='ACCEPTED_UNVERIFIED')
    await conn.query('ROLLBACK TO SAVEPOINT bb_nonce_batch');
  }
  await conn.execute(
   'INSERT INTO inv_bb_evidence_attempts (log_ref,sequence_number,batch_sha256,previous_batch_sha256,outcome) VALUES (?,?,?,?,?)',
   [logRef,sequence,hash,previousBatchSha256,outcome]);
  if(outcome==='ACCEPTED_UNVERIFIED'){
   await conn.execute(
    'UPDATE inv_bb_evidence_streams SET last_sequence=?,last_batch_sha256=? WHERE log_ref=?',
    [sequence,hash,logRef]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_bb_evidence_streams SET governance_state='QUARANTINED' WHERE log_ref=?",[logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1BB',outcome,
   governanceState:outcome==='ACCEPTED_UNVERIFIED'?head.governance_state:'QUARANTINED',
   externalEvidenceAuthenticated:false,productionReleaseAuthorized:false,
   productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}
 finally{
  try{
   if(globalNonceMutex)
    await conn.query("SELECT RELEASE_LOCK('aaditech-bb-global-nonces')");
  }finally{conn.release();}
 }
}
export async function inspectPhase1BbEvidence(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 bbWriteTarget(env);
 if(typeof logRef!=='string'||!ID.test(logRef))throw Error('Invalid Phase 1BB stream');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bb_evidence_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(heads.length!==1)throw Error('Missing Phase 1BB stream');
  const [attempts]=await conn.execute<RowDataPacket[]>(
   'SELECT sequence_number,batch_sha256,previous_batch_sha256,outcome FROM inv_bb_evidence_attempts WHERE log_ref=? ORDER BY id FOR UPDATE',
   [logRef]);
  const [nonceRows]=await conn.execute<RowDataPacket[]>(
   'SELECT batch_sha256 FROM inv_bb_evidence_nonce_claims WHERE log_ref=? FOR UPDATE',
   [logRef]);
  const countByBatch=new Map<string,number>();
  for(const item of nonceRows){
   const digest=String(item.batch_sha256);
   countByBatch.set(digest,(countByBatch.get(digest)??0)+1);
  }
  const anomalies:string[]=[];
  let acceptedSeq=0,acceptedHash:string|null=null,incident=false;
  for(const a of attempts){
   if(!SHA.test(String(a.batch_sha256))||
      (a.previous_batch_sha256!==null&&!SHA.test(String(a.previous_batch_sha256))))
    anomalies.push('INVALID_PERSISTED_HASH');
   if(a.outcome==='ACCEPTED_UNVERIFIED'){
    if(Number(a.sequence_number)!==acceptedSeq+1||
      a.previous_batch_sha256!==acceptedHash)
     anomalies.push('BROKEN_ACCEPTED_EVIDENCE_CHAIN');
    if(countByBatch.get(a.batch_sha256)!==6)
     anomalies.push('MISSING_OR_EXTRA_ACCEPTED_CHALLENGES');
    acceptedSeq=Number(a.sequence_number);acceptedHash=a.batch_sha256;
   }else incident=true;
  }
  for(const hash of countByBatch.keys())
   if(!attempts.some(a=>a.batch_sha256===hash&&a.outcome==='ACCEPTED_UNVERIFIED'))
    anomalies.push('ORPHANED_CHALLENGE_CLAIMS');
  const head=heads[0];
  if(Number(head.last_sequence)!==acceptedSeq||head.last_batch_sha256!==acceptedHash)
   anomalies.push('BATCH_HEAD_HISTORY_DIVERGENCE');
  if((head.governance_state==='QUARANTINED')!==incident)
   anomalies.push('QUARANTINE_STATE_DIVERGENCE');
  if(head.external_sources_authenticated!=='NO'||
     head.independent_key_custody_verified!=='NO'||head.production_release!=='HOLD')
   anomalies.push('UNAUTHORIZED_EXTERNAL_PROMOTION');
  await conn.commit();
  return Object.freeze({phase:'1BB',logRef,acceptedSequence:acceptedSeq,
   recordedAttempts:attempts.length,governanceState:head.governance_state,
   localDigestHistoryConsistent:anomalies.length===0,
   externalPublisherAuthenticated:false,immutableArchiveVerified:false,
   independentChallengeIssuanceVerified:false,realDRVerified:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
   anomalyCodes:Object.freeze([...new Set(anomalies)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
