import {randomBytes,createHash} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {boAuthorityDossierWriteTarget,
 readCandidateAuthorityExpectedUnderLock,
 inspectCandidateExternalAuthorityDossierOnConnection}
 from './quoteAuthorityCustody';
import {assessCandidateExternalIntake,candidateIntakePacketDigest,
 candidateIntakePinsetDigest,type IntakeCandidatePacket,
 type IntakePinnedCandidateKey,type IntakeExpected}
 from './quoteEvidenceIntake';

// Internal candidate custody only. No HTTP challenge endpoint, live third
// party retrieval, true provider trust or WORM. Pin SHA must be supplied by
// a separately administered environment, not by the uploaded evidence packet.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({candidateOnly:true,
 authenticatedExternalKeyEnrollment:false,trustedIndependentHeadRetrieved:false,
 actualCrlOcspChainAuthenticated:false,independentWormObjectLockVerified:false,
 realWitnessedDrRecoveryVerified:false,issuerLegalAuthorityVerified:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD' as const
});
export function bpCandidateIntakeWriteTarget(env:NodeJS.ProcessEnv){
 const target=boAuthorityDossierWriteTarget(env);
 if(target==='staging'&&env.BP_INTAKE_WRITE_APPROVED!=='YES')
  throw Error('Phase 1BP separate disposable TLS staging opt-in required');
 return target;
}
async function expectedUnderLock(conn:PoolConnection,quoteId:string){
 const {expected:boExpected,sourceValid}=await readCandidateAuthorityExpectedUnderLock(conn,quoteId);
 const bo=await inspectCandidateExternalAuthorityDossierOnConnection(conn,quoteId,boExpected);
 const [rows]=await conn.execute<RowDataPacket[]>(
  'SELECT last_claimed_revocation_epoch FROM quote_bo_candidate_authority_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 const expected:IntakeExpected={
  quoteId,boDossierSha256:bo.candidateAuthorityDossierSha256??'',
  bmReceiptSha256:boExpected.bmReceiptSha256,
  bnPacketSha256:boExpected.bnPacketSha256,
  sourceSha256:boExpected.quoteSourceSha256,
  bmSequence:boExpected.bmSequence,
  minimumRevocationEpoch:Math.max(boExpected.bnRevocationEpoch,
   Number(rows[0]?.last_claimed_revocation_epoch??0)),
  boExists:bo.candidateAuthorityDossierExists,
  boLocallyConsistent:bo.candidateAuthorityDossierLocallyConsistent&&sourceValid,
  boGovernanceState:bo.candidateAuthorityDossierGovernanceState as IntakeExpected['boGovernanceState']
 };
 return {expected,bo};
}
export async function inspectCandidateEvidenceIntakeOnConnection(
 conn:PoolConnection,quoteId:string,expected:IntakeExpected){
 if(!UUID.test(quoteId))throw Error('Phase 1BP invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bp_candidate_intake_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
 if(!heads.length)return Object.freeze({
  candidateIntakeExists:false,candidateIntakeVersion:0,
  candidateIntakePacketSha256:null,
  candidateIntakeGovernanceState:'ABSENT',candidateIntakeAttemptCount:0,
  candidateIntakeLocallyConsistent:true,
  candidateIntakeAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const h=heads[0],errors=new Set<string>();
 const [events]=await conn.execute<RowDataPacket[]>(
  `SELECT a.*,c.status AS nonce_status,
     c.consumed_packet_sha256 AS nonce_packet_sha256
   FROM quote_bp_candidate_intake_attempts a
   LEFT JOIN quote_bp_candidate_intake_challenges c
    ON c.challenge_sha256=a.challenge_sha256 AND c.quote_id=a.quote_id
   WHERE a.quote_id=? ORDER BY a.id ASC LIMIT 1002 FOR UPDATE`,[quoteId]);
 let version=0,packet:null|string=null,bo:null|string=null,
  bm:null|string=null,bn:null|string=null,pinset:null|string=null,
  challenge:null|string=null,epoch=0,incident=false;
 if(events.length>1000)errors.add('BP_LEDGER_BOUND');
 const seenChallenges=new Set<string>();
 for(const e of events){
  const n=Number(e.version_number),v=Number(e.revocation_epoch);
  if(!Number.isSafeInteger(n)||n<1||!Number.isSafeInteger(v)||v<1||
      ![e.packet_sha256,e.bo_dossier_sha256,e.bm_receipt_sha256,
        e.bn_packet_sha256,e.signer_pinset_sha256,e.challenge_sha256]
       .every(x=>SHA.test(String(x)))||
      (e.predecessor_packet_sha256!==null&&
       !SHA.test(String(e.predecessor_packet_sha256))))
   errors.add('BP_EVENT_MALFORMED');
  if(e.outcome===GOOD&&(e.nonce_status!=='CONSUMED'||
     e.nonce_packet_sha256!==e.packet_sha256))
   errors.add('BP_CHALLENGE_NOT_CONSUMED_OR_MISMATCHED');
  if(e.outcome===GOOD){
   if(incident||n!==version+1||
      e.predecessor_packet_sha256!==packet||
      seenChallenges.has(String(e.challenge_sha256))||
      (version>0&&(e.signer_pinset_sha256!==pinset||v<epoch)))
    errors.add('BP_ACCEPTED_HISTORY_INCONSISTENT');
   version=n;packet=e.packet_sha256;bo=e.bo_dossier_sha256;
   bm=e.bm_receipt_sha256;bn=e.bn_packet_sha256;
   pinset=e.signer_pinset_sha256;challenge=e.challenge_sha256;epoch=v;
  }else incident=true;
  seenChallenges.add(String(e.challenge_sha256));
 }
 if(Number(h.last_version)!==version||
    h.last_packet_sha256!==packet||h.last_bo_dossier_sha256!==bo||
    h.last_bm_receipt_sha256!==bm||h.last_bn_packet_sha256!==bn||
    h.last_signer_pinset_sha256!==pinset||h.last_challenge_sha256!==challenge||
    Number(h.last_revocation_epoch)!==epoch)
  errors.add('BP_HEAD_EVENT_HISTORY_MISMATCH');
 if((h.governance_state==='QUARANTINED')!==incident)
  errors.add('BP_STICKY_QUARANTINE_MISMATCH');
 if(h.trusted_external_key_enrollment!=='NO'||h.independent_head_retrieved!=='NO'||
    h.crl_ocsp_authority_verified!=='NO'||
    h.real_worm_delete_denial_verified!=='NO'||h.actual_dr_witnessed!=='NO'||
    h.production_release!=='HOLD')
  errors.add('BP_FORBIDDEN_AUTHORITY_PROMOTION');
 if(version>0&&(expected.boLocallyConsistent!==true||
    expected.boGovernanceState!=='HELD_UNVERIFIED'||
    expected.boDossierSha256!==bo||expected.bmReceiptSha256!==bm||
    expected.bnPacketSha256!==bn||
    expected.minimumRevocationEpoch>epoch))
  errors.add('BP_UPSTREAM_BO_BN_BM_DRIFT');
 return Object.freeze({
  candidateIntakeExists:true,candidateIntakeVersion:version,
  candidateIntakePacketSha256:packet,
  candidateIntakeGovernanceState:String(h.governance_state),
  candidateIntakeAttemptCount:events.length,
  candidateIntakeLocallyConsistent:errors.size===0,
  candidateIntakeAnomalyCodes:Object.freeze([...errors].sort()),...HOLD
 });
}
export async function inspectCandidateEvidenceIntake(pool:Pool,quoteId:string,
 env:NodeJS.ProcessEnv=process.env){
 bpCandidateIntakeWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,quoteId);
  const result=await inspectCandidateEvidenceIntakeOnConnection(conn,quoteId,expected);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function readCandidateIntakeExpectedUnderLock(conn:PoolConnection,quoteId:string){
 return expectedUnderLock(conn,quoteId);
}
export async function issueCandidateIntakeChallenge(pool:Pool,args:{
 quoteId:string,env?:NodeJS.ProcessEnv,now?:Date
}){
 bpCandidateIntakeWriteTarget(args.env??process.env);
 if(!UUID.test(args.quoteId))throw Error('Phase 1BP invalid quote ID');
 const at=args.now??new Date(),time=at.getTime();
 if(!Number.isFinite(time))throw Error('Phase 1BP invalid challenge clock');
 const nonce=createHash('sha256').update(
  'aaditech/quote/evidence-intake/server-nonce/v1\n'+
  randomBytes(32).toString('hex')).digest('hex');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,args.quoteId);
  if(!expected.boExists||!expected.boLocallyConsistent||
      expected.boGovernanceState!=='HELD_UNVERIFIED')
   throw Error('Phase 1BP cannot issue challenge for untrusted BO state');
  await conn.execute(
   'INSERT INTO quote_bp_candidate_intake_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT governance_state FROM quote_bp_candidate_intake_streams WHERE quote_id=? FOR UPDATE',[args.quoteId]);
  const prior=await inspectCandidateEvidenceIntakeOnConnection(conn,args.quoteId,expected);
  if(heads[0]?.governance_state!=='HELD_UNVERIFIED'||
    !prior.candidateIntakeLocallyConsistent)
   throw Error('Phase 1BP challenge issuance denied by local incident');
  const expires=new Date(time+5*60000);
  await conn.execute(
   'INSERT INTO quote_bp_candidate_intake_challenges (challenge_sha256,quote_id,issued_at,expires_at) VALUES (?,?,?,?)',
   [nonce,args.quoteId,at,expires]);
  await conn.commit();
  return Object.freeze({challengeSha256:nonce,expiresAt:expires.toISOString(),
   source:'SERVER_ISSUED_CANDIDATE',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateEvidenceIntake(pool:Pool,args:{
 quoteId:string,version:number,previousPacketSha256:string|null,
 packet:IntakeCandidatePacket,pinnedKeys:IntakePinnedCandidateKey[],
 now?:Date,env?:NodeJS.ProcessEnv
}){
 const env=args.env??process.env;bpCandidateIntakeWriteTarget(env);
 if(!UUID.test(args.quoteId)||!Number.isSafeInteger(args.version)||
    args.version<1||args.version>1000||
    (args.previousPacketSha256!==null&&!SHA.test(args.previousPacketSha256)))
  throw Error('Phase 1BP invalid bound/version/predecessor');
 if(!SHA.test(String(env.BP_INTAKE_PINSET_SHA256)))
  throw Error('Phase 1BP requires separately configured pinset digest');
 const configured=candidateIntakePinsetDigest(args.pinnedKeys);
 if(configured!==env.BP_INTAKE_PINSET_SHA256)
  throw Error('Phase 1BP applicant signer pin substitution refused');
 const at=args.now??new Date();
 const packetHash=candidateIntakePacketDigest(args.packet);
 const claims=args.packet?.claims;
 const revocationEpoch=claims?.[0]?.body?.revocationEpoch;
 if(!Number.isSafeInteger(revocationEpoch)||!revocationEpoch||revocationEpoch<1)
  throw Error('Phase 1BP malformed revocation epoch');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,args.quoteId);
  if(!expected.boExists)throw Error('Phase 1BP missing BO candidate dossier');
  const analysis=assessCandidateExternalIntake({packet:args.packet,expected,
   pinnedKeys:args.pinnedKeys,
   expectedPinsetSha256:env.BP_INTAKE_PINSET_SHA256,now:at});
  if(analysis.candidateIntakeAnomalyCodes.some(x=>[
   'BP_PACKET_SHAPE_INVALID','BP_CLAIM_SHAPE_INVALID','BP_PINSET_INVALID',
   'BP_CONFIGURED_PINSET_MISMATCH','BP_SIGNED_CANDIDATE_EVIDENCE_INVALID'
  ].includes(x)))
   throw Error('Phase 1BP unsigned or malformed candidate intake rejected');
  await conn.execute(
   'INSERT INTO quote_bp_candidate_intake_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bp_candidate_intake_streams WHERE quote_id=? FOR UPDATE',[args.quoteId]);
  const h=heads[0],last=Number(h.last_version);
  if(!h||!Number.isSafeInteger(last)||last<0||last>1000)
   throw Error('Phase 1BP local ledger head malformed');
  const prior=await inspectCandidateEvidenceIntakeOnConnection(conn,args.quoteId,expected);
  if(!prior.candidateIntakeLocallyConsistent&&
    !prior.candidateIntakeAnomalyCodes.every(x=>x==='BP_UPSTREAM_BO_BN_BM_DRIFT'))
   throw Error('Phase 1BP local intake history corrupt');
  const [challengeRows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bp_candidate_intake_challenges WHERE quote_id=? AND challenge_sha256=? FOR UPDATE',
   [args.quoteId,args.packet.challengeSha256]);
  const ch=challengeRows[0];
  if(!ch)throw Error('Phase 1BP missing server-issued challenge');
  const [duplicate]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bp_candidate_intake_attempts WHERE quote_id=? AND packet_sha256=? LIMIT 2 FOR UPDATE',
   [args.quoteId,packetHash]);
  if(h.governance_state==='HELD_UNVERIFIED'&&last===args.version&&
    h.last_packet_sha256===packetHash&&
    ch.status==='CONSUMED'&&ch.consumed_packet_sha256===packetHash&&
    prior.candidateIntakeLocallyConsistent&&analysis.candidateIntakeConsistent&&
    duplicate.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(duplicate.length){
   await conn.commit();return Object.freeze({outcome:'DUPLICATE_REJECTED',
    governanceState:String(h.governance_state),...HOLD});
  }
  const time=at.getTime(),issued=new Date(ch.issued_at).getTime(),
   expiry=new Date(ch.expires_at).getTime();
  if(!Number.isFinite(time)||!Number.isFinite(issued)||!Number.isFinite(expiry)||
     issued>time+60000)throw Error('Phase 1BP invalid local challenge clock');
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(ch.status!=='ISSUED'||ch.consumed_packet_sha256!==null||
      time>expiry)outcome='CHALLENGE_REPLAY_QUARANTINED';
  else if(!expected.boLocallyConsistent||
      expected.boGovernanceState!=='HELD_UNVERIFIED'||
      prior.candidateIntakeAnomalyCodes.includes('BP_UPSTREAM_BO_BN_BM_DRIFT'))
   outcome='UPSTREAM_DRIFT_QUARANTINED';
  else if(revocationEpoch<Number(h.last_revocation_epoch)||
      revocationEpoch<expected.minimumRevocationEpoch)
   outcome='EPOCH_REGRESSION_QUARANTINED';
  else if(!analysis.candidateIntakeConsistent)
   outcome='CROSS_SOURCE_CONFLICT_QUARANTINED';
  else if(last>0&&configured!==h.last_signer_pinset_sha256)
   outcome='PINSET_CHANGE_QUARANTINED';
  else if(last===0)outcome=args.version===1&&args.previousPacketSha256===null?
   GOOD:'GAP_QUARANTINED';
  else if(args.version<=last)outcome=args.version===last?
   'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(args.version!==last+1)outcome='GAP_QUARANTINED';
  else if(args.previousPacketSha256!==h.last_packet_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_bp_candidate_intake_attempts (quote_id,version_number,packet_sha256,predecessor_packet_sha256,bo_dossier_sha256,bm_receipt_sha256,bn_packet_sha256,signer_pinset_sha256,challenge_sha256,revocation_epoch,outcome) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
   [args.quoteId,args.version,packetHash,args.previousPacketSha256,
    args.packet.boDossierSha256,expected.bmReceiptSha256,expected.bnPacketSha256,
    configured,args.packet.challengeSha256,revocationEpoch,outcome]);
  if(ch.status==='ISSUED')await conn.execute(
   "UPDATE quote_bp_candidate_intake_challenges SET status='CONSUMED',consumed_packet_sha256=? WHERE quote_id=? AND challenge_sha256=?",
   [packetHash,args.quoteId,args.packet.challengeSha256]);
  if(outcome===GOOD)await conn.execute(
   'UPDATE quote_bp_candidate_intake_streams SET last_version=?,last_packet_sha256=?,last_bo_dossier_sha256=?,last_bm_receipt_sha256=?,last_bn_packet_sha256=?,last_signer_pinset_sha256=?,last_challenge_sha256=?,last_revocation_epoch=? WHERE quote_id=?',
   [args.version,packetHash,expected.boDossierSha256,expected.bmReceiptSha256,
    expected.bnPacketSha256,configured,args.packet.challengeSha256,
    revocationEpoch,args.quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')await conn.execute(
   "UPDATE quote_bp_candidate_intake_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
   [args.quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
