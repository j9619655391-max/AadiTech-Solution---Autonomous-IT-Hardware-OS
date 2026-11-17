import {createHash} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {readCandidateQuoteSourceUnderLock,
 inspectCandidateQuoteCheckpointOnConnection,bmQuoteCheckpointWriteTarget}
 from './quoteCheckpointCustody';
import {assessCandidateQuoteHeadReconciliation,candidateQuotePinsetDigest,
 candidateQuoteReconciliationDigest,type CandidateHeadObservation,
 type CandidateKeyRollover} from './quoteHeadReconciliation';
import type {CandidatePinnedKey} from './quoteAnchors';

// 1BN: LOCAL UNTRUSTED candidate custody only. No signer enrollment, provider
// network, HTTP writer, independently authenticated trust or DR restore.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({
 independentHeadAuthenticated:false,independentRevocationAuthenticated:false,
 genuineWitnessRolloverApproved:false,realEncryptedDrWitnessed:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD' as const
});
export function bnReconciliationWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 // Respect the stricter BM guard, but require a separate explicit BN opt-in.
 const target=bmQuoteCheckpointWriteTarget(env);
 if(target==='staging'&&env.BN_RECONCILIATION_WRITE_APPROVED!=='YES')
  throw Error('Phase 1BN explicit isolated TLS staging approval required');
 return target;
}
function packetHash(args:{
 quoteId:string,revision:number,previousPacketSha256:string|null,
 observations:CandidateHeadObservation[],rollover:CandidateKeyRollover|null,
 recoverySnapshot:{sequence:number,receiptSha256:string,sourceSha256:string}|null
}){
 const evidence=candidateQuoteReconciliationDigest({observations:args.observations,
  rollover:args.rollover,recoverySnapshot:args.recoverySnapshot});
 return createHash('sha256').update('aaditech/quote/held-reconciliation-packet/v1\n'+
  JSON.stringify({quoteId:args.quoteId,revision:args.revision,
   previousPacketSha256:args.previousPacketSha256,evidence})).digest('hex');
}
export async function inspectCandidateQuoteReconciliationOnConnection(
 conn:PoolConnection,quoteId:string,bm:{
  candidateCheckpointSequence?:number,candidateCheckpointReceiptSha256?:string|null,
  candidateCheckpointSourceSha256?:string|null,
  candidateCheckpointLocallyConsistent:boolean,
  candidateCheckpointGovernanceState:string
 }){
 if(!UUID.test(quoteId))throw Error('Phase 1BN invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bn_candidate_reconciliation_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 if(!heads.length)return Object.freeze({
  candidateReconciliationExists:false,candidateReconciliationRevision:0,
  candidateReconciliationGovernanceState:'ABSENT',
  candidateReconciliationPacketSha256:null,
  candidateReconciliationAttemptCount:0,
  candidateReconciliationLocallyConsistent:true,
  candidateReconciliationAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const h=heads[0];
 const [rows]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bn_candidate_reconciliation_attempts WHERE quote_id=? ORDER BY id ASC LIMIT 1002 FOR UPDATE',
  [quoteId]);
 const errors=new Set<string>();
 let last=0,packet:null|string=null,receipt:null|string=null,
  source:null|string=null,pinset:null|string=null,epoch=0,incident=false;
 if(rows.length>1000)errors.add('BN_RECONCILIATION_INSPECTION_BOUND');
 for(const row of rows){
  const n=Number(row.revision_number),e=Number(row.claimed_revocation_epoch);
  if(!Number.isSafeInteger(n)||n<1||!Number.isSafeInteger(e)||e<1||
     !SHA.test(String(row.packet_sha256))||
     !SHA.test(String(row.claimed_receipt_sha256))||
     !SHA.test(String(row.claimed_source_sha256))||
     !SHA.test(String(row.pinset_sha256))||
     (row.previous_packet_sha256!==null&&
      !SHA.test(String(row.previous_packet_sha256))))
   errors.add('BN_RECONCILIATION_ATTEMPT_MALFORMED');
  if(row.outcome===GOOD){
   if(incident||n!==last+1||row.previous_packet_sha256!==packet||
      (last>0&&(row.pinset_sha256!==pinset||e<epoch)))
    errors.add('BN_RECONCILIATION_ACCEPTED_CHAIN_BROKEN');
   last=n;packet=row.packet_sha256;receipt=row.claimed_receipt_sha256;
   source=row.claimed_source_sha256;pinset=row.pinset_sha256;epoch=e;
  }else incident=true;
 }
 if(Number(h.last_revision)!==last||h.last_packet_sha256!==packet||
    h.last_receipt_sha256!==receipt||h.last_source_sha256!==source||
    h.last_pinset_sha256!==pinset||Number(h.last_revocation_epoch)!==epoch)
  errors.add('BN_RECONCILIATION_HEAD_HISTORY_DIVERGENCE');
 if((h.governance_state==='QUARANTINED')!==incident)
  errors.add('BN_RECONCILIATION_FREEZE_MISMATCH');
 if(h.independent_head_verified!=='NO'||h.issuer_and_revocation_verified!=='NO'||
    h.real_dr_witnessed!=='NO'||h.production_release!=='HOLD')
  errors.add('BN_RECONCILIATION_ILLICIT_TRUST_PROMOTION');
 if(last>0&&(bm.candidateCheckpointLocallyConsistent!==true||
    bm.candidateCheckpointGovernanceState!=='HELD_UNVERIFIED'||
    bm.candidateCheckpointReceiptSha256!==receipt||
    bm.candidateCheckpointSourceSha256!==source))
  errors.add('BN_RECONCILIATION_UPSTREAM_CHECKPOINT_CHANGED');
 return Object.freeze({
  candidateReconciliationExists:true,candidateReconciliationRevision:last,
  candidateReconciliationAttemptCount:rows.length,
  candidateReconciliationGovernanceState:String(h.governance_state),
  candidateReconciliationPacketSha256:packet,
  candidateReconciliationLocallyConsistent:errors.size===0,
  candidateReconciliationAnomalyCodes:Object.freeze([...errors].sort()),
  ...HOLD
 });
}
export async function inspectCandidateQuoteReconciliation(
 pool:Pool,quoteId:string,env:NodeJS.ProcessEnv=process.env){
 bnReconciliationWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {commitment}=await readCandidateQuoteSourceUnderLock(conn,quoteId);
  const bm=await inspectCandidateQuoteCheckpointOnConnection(conn,quoteId,
   commitment.sourceCommitmentSha256);
  const result=await inspectCandidateQuoteReconciliationOnConnection(conn,quoteId,bm);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateQuoteReconciliation(pool:Pool,args:{
 quoteId:string,revision:number,previousPacketSha256:string|null,
 observations:CandidateHeadObservation[],pinnedKeys:CandidatePinnedKey[],
 rollover?:CandidateKeyRollover|null,
 recoverySnapshot?:{sequence:number,receiptSha256:string,sourceSha256:string}|null,
 now?:Date,env?:NodeJS.ProcessEnv
}){
 bnReconciliationWriteTarget(args.env??process.env);
 const {quoteId,revision,previousPacketSha256}=args;
 if(!UUID.test(quoteId)||!Number.isSafeInteger(revision)||revision<1||
    revision>1000||(previousPacketSha256!==null&&
    !SHA.test(previousPacketSha256)))
  throw Error('Phase 1BN malformed bound/revision/previous hash');
 if(!Array.isArray(args.observations)||args.observations.length!==2)
  throw Error('Phase 1BN two claimed candidate witness sources required');
 const pins=candidateQuotePinsetDigest(args.pinnedKeys);
 const now=args.now??new Date();
 const rollover=args.rollover??null,recoverySnapshot=args.recoverySnapshot??null;
 const digest=packetHash({quoteId,revision,previousPacketSha256,
  observations:args.observations,rollover,recoverySnapshot});
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {commitment,sourceValid}=await readCandidateQuoteSourceUnderLock(conn,quoteId);
  const bm=await inspectCandidateQuoteCheckpointOnConnection(conn,quoteId,
   commitment.sourceCommitmentSha256);
  if(!bm.candidateCheckpointExists||!bm.candidateCheckpointReceiptSha256||
     !bm.candidateCheckpointSourceSha256)
   throw Error('Phase 1BN missing predecessor BM held checkpoint');
  const review=assessCandidateQuoteHeadReconciliation({
   quoteId,checkpointSequence:bm.candidateCheckpointSequence,
   checkpointReceiptSha256:bm.candidateCheckpointReceiptSha256,
   checkpointSourceSha256:bm.candidateCheckpointSourceSha256,
   observations:args.observations,pinnedKeys:args.pinnedKeys,
   rollover,recoverySnapshot,now
  });
  // An invalid self-proclaimed signature is not enough to enter the ledger
  // or cause an incident. Signed conflicting claims remain deny-only.
  if(review.candidateReconciliationAnomalyCodes.some(code=>
     ['BN_OBSERVATION_SIGNATURE_INVALID','BN_OBSERVATION_SHAPE_INVALID',
      'BN_PINSET_INVALID','BN_TWO_INDEPENDENT_CANDIDATE_SOURCES_REQUIRED'].includes(code)))
   throw Error('Phase 1BN unverified/unbound signed candidate observations');
  await conn.execute(
   'INSERT INTO quote_bn_candidate_reconciliation_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [quoteId]);
  const [headRows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bn_candidate_reconciliation_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
  const h=headRows[0],last=Number(h.last_revision);
  if(!h||!Number.isSafeInteger(last)||last<0||last>1000||
     (last===0&&(h.last_packet_sha256!==null||h.last_receipt_sha256!==null||
       h.last_source_sha256!==null||h.last_pinset_sha256!==null||
       Number(h.last_revocation_epoch)!==0)))
   throw Error('Phase 1BN corrupt candidate reconciliation head');
  const prior=await inspectCandidateQuoteReconciliationOnConnection(conn,quoteId,{
   ...bm,candidateCheckpointLocallyConsistent:true,
   candidateCheckpointGovernanceState:String(bm.candidateCheckpointGovernanceState)
  });
  if(!prior.candidateReconciliationLocallyConsistent&&
     !prior.candidateReconciliationAnomalyCodes.every(c=>
      c==='BN_RECONCILIATION_UPSTREAM_CHECKPOINT_CHANGED'))
   throw Error('Phase 1BN persisted candidate reconciliation history inconsistent');
  const [duplicates]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bn_candidate_reconciliation_attempts WHERE quote_id=? AND packet_sha256=? LIMIT 2 FOR UPDATE',
   [quoteId,digest]);
  if(h.governance_state==='HELD_UNVERIFIED'&&
     revision===last&&h.last_packet_sha256===digest&&
     sourceValid&&bm.candidateCheckpointLocallyConsistent&&
     review.candidateReconciliationConsistent&&duplicates.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(duplicates.length){
   await conn.commit();return Object.freeze({outcome:'DUPLICATE_REJECTED',
    governanceState:String(h.governance_state),...HOLD});
  }
  const first=args.observations[0].body;
  const currentEpoch=first.revocationEpoch;
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(!sourceValid||!bm.candidateCheckpointLocallyConsistent||
     bm.candidateCheckpointGovernanceState!=='HELD_UNVERIFIED')
   outcome='LOCAL_CHECKPOINT_DRIFT_QUARANTINED';
  else if(currentEpoch<Number(h.last_revocation_epoch))
   outcome='REVOCATION_REGRESSION_QUARANTINED';
  else if(!review.candidateReconciliationConsistent)
   outcome='CLAIM_CONFLICT_QUARANTINED';
  else if(last>0&&pins!==h.last_pinset_sha256)
   outcome='PINSET_ROLLOVER_UNVERIFIED_QUARANTINED';
  else if(last===0)outcome=revision===1&&previousPacketSha256===null?
   GOOD:'GAP_QUARANTINED';
  else if(revision<=last)
   outcome=revision===last?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(revision!==last+1)outcome='GAP_QUARANTINED';
  else if(previousPacketSha256!==h.last_packet_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else if(h.last_receipt_sha256!==first.receiptSha256||
      h.last_source_sha256!==first.sourceSha256)
   outcome='LOCAL_CHECKPOINT_DRIFT_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_bn_candidate_reconciliation_attempts (quote_id,revision_number,packet_sha256,previous_packet_sha256,claimed_receipt_sha256,claimed_source_sha256,pinset_sha256,claimed_revocation_epoch,outcome) VALUES (?,?,?,?,?,?,?,?,?)',
   [quoteId,revision,digest,previousPacketSha256,
    first.receiptSha256,first.sourceSha256,pins,currentEpoch,outcome]);
  if(outcome===GOOD)
   await conn.execute(
    'UPDATE quote_bn_candidate_reconciliation_streams SET last_revision=?,last_packet_sha256=?,last_receipt_sha256=?,last_source_sha256=?,last_pinset_sha256=?,last_revocation_epoch=? WHERE quote_id=?',
    [revision,digest,first.receiptSha256,first.sourceSha256,pins,currentEpoch,quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')
   await conn.execute(
    "UPDATE quote_bn_candidate_reconciliation_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
    [quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',
   candidateEvidenceOnly:true,...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
