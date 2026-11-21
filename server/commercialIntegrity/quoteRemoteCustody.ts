import {createHash,randomBytes} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {bpCandidateIntakeWriteTarget,readCandidateIntakeExpectedUnderLock,
 inspectCandidateEvidenceIntakeOnConnection} from './quoteEvidenceCustody';
import {assessCandidateRemoteEvidence,candidateRemotePacketDigest,
 candidateRegistrarPinDigest,candidateCollectorPinsetDigest,
 candidateEndpointConfigDigest,type CandidateRemotePacket,
 type CandidateRegistrarPin,type CandidateCollectorPin,
 type CandidateEndpointConfig,type CandidateRemoteExpected}
 from './quoteRemoteEvidence';

// Candidate-only, no network client, no trusted provider signer and no HTTP
// mutation route. No actual external authority can be granted by this module.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({
 candidateRemoteOnly:true,authenticatedRegistrarEnrollment:false,
 authenticatedIssuerChain:false,liveRemoteCheckpointRetrieved:false,
 actualTlsSessionVerified:false,liveSignedCrlOcspValidated:false,
 independentWormVerified:false,realDrRecoveryWitnessed:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD' as const
});
export function bqRemoteWriteTarget(env:NodeJS.ProcessEnv){
 const result=bpCandidateIntakeWriteTarget(env);
 if(result==='staging'&&env.BQ_REMOTE_WRITE_APPROVED!=='YES')
  throw Error('Phase 1BQ separate disposable TLS staging opt-in required');
 return result;
}
async function expectedUnderLock(conn:PoolConnection,quoteId:string){
 const {expected:bpExpected}=await readCandidateIntakeExpectedUnderLock(conn,quoteId);
 const bp=await inspectCandidateEvidenceIntakeOnConnection(conn,quoteId,bpExpected);
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT last_revocation_epoch FROM quote_bp_candidate_intake_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 const e:CandidateRemoteExpected={
  quoteId,bpPacketSha256:bp.candidateIntakePacketSha256??'',
  bmReceiptSha256:bpExpected.bmReceiptSha256,
  sourceSha256:bpExpected.sourceSha256,bmSequence:bpExpected.bmSequence,
  minRevocationEpoch:Math.max(bpExpected.minimumRevocationEpoch,
   Number(heads[0]?.last_revocation_epoch??0)),
  bpExists:bp.candidateIntakeExists,
  bpLocallyConsistent:bp.candidateIntakeLocallyConsistent&&
   bpExpected.boLocallyConsistent===true,
  bpGovernanceState:bp.candidateIntakeGovernanceState as CandidateRemoteExpected['bpGovernanceState']
 };
 return {expected:e,bp};
}
export async function readCandidateRemoteExpectedUnderLock(
 conn:PoolConnection,quoteId:string){
 return expectedUnderLock(conn,quoteId);
}
export async function inspectCandidateRemoteEvidenceOnConnection(
 conn:PoolConnection,quoteId:string,expected:CandidateRemoteExpected){
 if(!UUID.test(quoteId))throw Error('Phase 1BQ invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bq_candidate_remote_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 if(!heads.length)return Object.freeze({
  candidateRemoteExists:false,candidateRemoteVersion:0,
  candidateRemotePacketSha256:null,candidateRemoteAttemptCount:0,
  candidateRemoteGovernanceState:'ABSENT',
  candidateRemoteLocallyConsistent:true,
  candidateRemoteAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const h=heads[0],issues=new Set<string>();
 const [events]=await conn.execute<RowDataPacket[]>(
  `SELECT a.*,c.status AS challenge_status,
    c.consumed_packet_sha256 AS challenge_consumed_sha256
   FROM quote_bq_candidate_remote_attempts a
   LEFT JOIN quote_bq_candidate_remote_challenges c
    ON c.challenge_sha256=a.challenge_sha256 AND c.quote_id=a.quote_id
   WHERE a.quote_id=? ORDER BY a.id ASC LIMIT 1002 FOR UPDATE`,[quoteId]);
 let version=0,packet:null|string=null,bp:null|string=null,
  root:null|string=null,pins:null|string=null,endpoints:null|string=null,
  challenge:null|string=null,epoch=0,incident=false;
 const usedChallenges=new Set<string>();
 if(events.length>1000)issues.add('BQ_ATTEMPT_HISTORY_LIMIT');
 for(const row of events){
  const n=Number(row.version_number),rev=Number(row.claimed_revocation_epoch);
  if(!Number.isSafeInteger(n)||n<1||
    !Number.isSafeInteger(rev)||rev<1||
    ![row.packet_sha256,row.bp_packet_sha256,row.registrar_pin_sha256,
      row.collector_pinset_sha256,row.endpoint_config_sha256,row.challenge_sha256]
      .every(x=>SHA.test(String(x)))||
    (row.predecessor_packet_sha256!==null&&!SHA.test(String(row.predecessor_packet_sha256))))
   issues.add('BQ_ATTEMPT_ROW_MALFORMED');
  if(row.outcome===GOOD){
   if(incident||n!==version+1||row.predecessor_packet_sha256!==packet||
      usedChallenges.has(String(row.challenge_sha256))||
      (version>0&&(row.registrar_pin_sha256!==root||
       row.collector_pinset_sha256!==pins||
       row.endpoint_config_sha256!==endpoints||rev<epoch)))
    issues.add('BQ_ACCEPTED_HISTORY_CHAIN_BROKEN');
   if(row.challenge_status!=='CONSUMED'||
      row.challenge_consumed_sha256!==row.packet_sha256)
    issues.add('BQ_CHALLENGE_CONSUMPTION_TAMPERED');
   version=n;packet=row.packet_sha256;bp=row.bp_packet_sha256;
   root=row.registrar_pin_sha256;pins=row.collector_pinset_sha256;
   endpoints=row.endpoint_config_sha256;challenge=row.challenge_sha256;epoch=rev;
  }else incident=true;
  usedChallenges.add(String(row.challenge_sha256));
 }
 if(Number(h.last_version)!==version||h.last_packet_sha256!==packet||
    h.last_bp_packet_sha256!==bp||h.last_registrar_pin_sha256!==root||
    h.last_collector_pinset_sha256!==pins||
    h.last_endpoint_config_sha256!==endpoints||
    h.last_challenge_sha256!==challenge||
    Number(h.last_claimed_revocation_epoch)!==epoch)
  issues.add('BQ_STORED_HEAD_HISTORY_DIVERGENCE');
 if((h.governance_state==='QUARANTINED')!==incident)
  issues.add('BQ_QUARANTINE_STATE_MISMATCH');
 if(h.authenticated_registrar_enrollment!=='NO'||
    h.remotely_retrieved_head_verified!=='NO'||
    h.live_issuer_crl_ocsp_verified!=='NO'||
    h.independent_worm_verified!=='NO'||
    h.actual_dr_recovery_witnessed!=='NO'||h.production_release!=='HOLD')
  issues.add('BQ_FORBIDDEN_TRUST_PROMOTION');
 if(version>0&&(
    expected.bpLocallyConsistent!==true||
    expected.bpGovernanceState!=='HELD_UNVERIFIED'||
    expected.bpPacketSha256!==bp||expected.minRevocationEpoch>epoch))
  issues.add('BQ_UPSTREAM_BP_CHANGED');
 return Object.freeze({
  candidateRemoteExists:true,candidateRemoteVersion:version,
  candidateRemotePacketSha256:packet,
  candidateRemoteAttemptCount:events.length,
  candidateRemoteGovernanceState:String(h.governance_state),
  candidateRemoteLocallyConsistent:issues.size===0,
  candidateRemoteAnomalyCodes:Object.freeze([...issues].sort()),...HOLD
 });
}
export async function inspectCandidateRemoteEvidence(pool:Pool,quoteId:string,
 env:NodeJS.ProcessEnv=process.env){
 bqRemoteWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,quoteId);
  const result=await inspectCandidateRemoteEvidenceOnConnection(conn,quoteId,expected);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function issueCandidateRemoteChallenge(pool:Pool,args:{
 quoteId:string,env?:NodeJS.ProcessEnv,now?:Date
}){
 bqRemoteWriteTarget(args.env??process.env);
 if(!UUID.test(args.quoteId))throw Error('Phase 1BQ invalid quote ID');
 const at=args.now??new Date(),ms=at.getTime();
 if(!Number.isFinite(ms))throw Error('Phase 1BQ invalid clock');
 const challenge=createHash('sha256').update(
  'aaditech/quote/remote/nonce/v1\n'+randomBytes(32).toString('hex')).digest('hex');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,args.quoteId);
  if(!expected.bpExists||!expected.bpLocallyConsistent||
     expected.bpGovernanceState!=='HELD_UNVERIFIED')
   throw Error('Phase 1BQ upstream BP not held and consistent');
  await conn.execute(
   'INSERT INTO quote_bq_candidate_remote_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const prior=await inspectCandidateRemoteEvidenceOnConnection(
   conn,args.quoteId,expected);
  if(!prior.candidateRemoteLocallyConsistent||
     prior.candidateRemoteGovernanceState!=='HELD_UNVERIFIED')
   throw Error('Phase 1BQ challenge blocked by previous incident');
  const expiresAt=new Date(ms+5*60000);
  await conn.execute(
   'INSERT INTO quote_bq_candidate_remote_challenges(challenge_sha256,quote_id,issued_at,expires_at) VALUES (?,?,?,?)',
   [challenge,args.quoteId,at,expiresAt]);
  await conn.commit();
  return Object.freeze({challengeSha256:challenge,
   expiresAt:expiresAt.toISOString(),origin:'SERVER_ISSUED_OFFLINE_CANDIDATE',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateRemoteEvidence(pool:Pool,args:{
 quoteId:string,version:number,previousPacketSha256:string|null,
 packet:CandidateRemotePacket,registrarPin:CandidateRegistrarPin,
 collectorPins:CandidateCollectorPin[],endpoints:CandidateEndpointConfig[],
 now?:Date,env?:NodeJS.ProcessEnv
}){
 const env=args.env??process.env;bqRemoteWriteTarget(env);
 if(!UUID.test(args.quoteId)||!Number.isSafeInteger(args.version)||
    args.version<1||args.version>1000||
    (args.previousPacketSha256!==null&&!SHA.test(args.previousPacketSha256)))
  throw Error('Phase 1BQ invalid bound/version/predecessor');
 if(![env.BQ_REGISTRAR_PIN_SHA256,env.BQ_COLLECTOR_PINSET_SHA256,
       env.BQ_ENDPOINT_CONFIG_SHA256].every(x=>SHA.test(String(x))))
  throw Error('Phase 1BQ three separate operator-configured binding digests required');
 const root=candidateRegistrarPinDigest(args.registrarPin),
  pins=candidateCollectorPinsetDigest(args.collectorPins),
  origins=candidateEndpointConfigDigest(args.endpoints);
 if(root!==env.BQ_REGISTRAR_PIN_SHA256||
    pins!==env.BQ_COLLECTOR_PINSET_SHA256||
    origins!==env.BQ_ENDPOINT_CONFIG_SHA256)
  throw Error('Phase 1BQ independent candidate registrar/endpoint config mismatch');
 const packetHash=candidateRemotePacketDigest(args.packet);
 const epoch=args.packet?.captures?.[0]?.body?.revocationEpoch;
 if(!Number.isSafeInteger(epoch)||!epoch||epoch<1)
  throw Error('Phase 1BQ malformed claimed epoch');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await expectedUnderLock(conn,args.quoteId);
  if(!expected.bpExists)throw Error('Phase 1BQ missing BP candidate predecessor');
  const assessed=assessCandidateRemoteEvidence({
   packet:args.packet,expected,registrarPin:args.registrarPin,
   collectorPins:args.collectorPins,endpoints:args.endpoints,
   expectedRegistrarPinSha256:env.BQ_REGISTRAR_PIN_SHA256,
   expectedCollectorPinsetSha256:env.BQ_COLLECTOR_PINSET_SHA256,
   expectedEndpointConfigSha256:env.BQ_ENDPOINT_CONFIG_SHA256,
   now:args.now??new Date()
  });
  if(assessed.candidateRemoteEvidenceAnomalyCodes.some(x=>[
    'BQ_PACKET_INVALID','BQ_MANIFEST_SHAPE_OR_AUTHORITY_CLAIM_INVALID',
    'BQ_CAPTURE_SHAPE_OR_NETWORK_PROOF_INVALID',
    'BQ_MANIFEST_SIGNATURE_INVALID','BQ_CAPTURE_SIGNATURE_INVALID',
    'BQ_REGISTRAR_PIN_INVALID','BQ_COLLECTOR_PINS_INVALID',
    'BQ_OPERATOR_CONFIG_PIN_MISMATCH'
   ].includes(x)))
   throw Error('Phase 1BQ malformed/unsigned candidate receipt rejected');
  await conn.execute(
   'INSERT INTO quote_bq_candidate_remote_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bq_candidate_remote_streams WHERE quote_id=? FOR UPDATE',
   [args.quoteId]);
  const h=heads[0],last=Number(h.last_version);
  if(!h||!Number.isSafeInteger(last)||last<0||last>1000)
   throw Error('Phase 1BQ stored stream invalid');
  const prior=await inspectCandidateRemoteEvidenceOnConnection(conn,args.quoteId,expected);
  if(!prior.candidateRemoteLocallyConsistent&&
    !prior.candidateRemoteAnomalyCodes.every(x=>x==='BQ_UPSTREAM_BP_CHANGED'))
   throw Error('Phase 1BQ local history corrupt');
  const [challenges]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bq_candidate_remote_challenges WHERE quote_id=? AND challenge_sha256=? FOR UPDATE',
   [args.quoteId,args.packet.challengeSha256]);
  const challenge=challenges[0];
  if(!challenge)throw Error('Phase 1BQ server challenge does not exist');
  const [dup]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bq_candidate_remote_attempts WHERE quote_id=? AND packet_sha256=? LIMIT 2 FOR UPDATE',
   [args.quoteId,packetHash]);
  if(h.governance_state==='HELD_UNVERIFIED'&&last===args.version&&
    h.last_packet_sha256===packetHash&&challenge.status==='CONSUMED'&&
    challenge.consumed_packet_sha256===packetHash&&
    prior.candidateRemoteLocallyConsistent&&
    assessed.candidateRemoteEvidenceConsistent&&dup.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(dup.length){
   await conn.commit();return Object.freeze({outcome:'DUPLICATE_REJECTED',
    governanceState:String(h.governance_state),...HOLD});
  }
  const time=(args.now??new Date()).getTime(),
   issued=new Date(challenge.issued_at).getTime(),
   expires=new Date(challenge.expires_at).getTime();
  if(!Number.isFinite(time)||!Number.isFinite(issued)||!Number.isFinite(expires)||
    issued>time+60000)throw Error('Phase 1BQ invalid challenge clock');
  let outcome:string;
  if(h.governance_state==='QUARANTINED')
   outcome='POST_INCIDENT_QUARANTINED';
  else if(challenge.status!=='ISSUED'||
      challenge.consumed_packet_sha256!==null||time>expires)
   outcome='CHALLENGE_REPLAY_QUARANTINED';
  else if(!expected.bpLocallyConsistent||
      expected.bpGovernanceState!=='HELD_UNVERIFIED'||
      prior.candidateRemoteAnomalyCodes.includes('BQ_UPSTREAM_BP_CHANGED'))
   outcome='UPSTREAM_DRIFT_QUARANTINED';
  else if(epoch<Number(h.last_claimed_revocation_epoch)||
      epoch<expected.minRevocationEpoch)
   outcome='REVOCATION_REGRESSION_QUARANTINED';
  else if(!assessed.candidateRemoteEvidenceConsistent)
   outcome='REMOTE_CLAIM_CONFLICT_QUARANTINED';
  else if(last>0&&(root!==h.last_registrar_pin_sha256||
      pins!==h.last_collector_pinset_sha256||
      origins!==h.last_endpoint_config_sha256))
   outcome='REGISTRAR_OR_ENDPOINT_CHANGE_QUARANTINED';
  else if(last===0)outcome=args.version===1&&args.previousPacketSha256===null?
    GOOD:'GAP_QUARANTINED';
  else if(args.version<=last)outcome=args.version===last?
    'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(args.version!==last+1)outcome='GAP_QUARANTINED';
  else if(args.previousPacketSha256!==h.last_packet_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_bq_candidate_remote_attempts (quote_id,version_number,packet_sha256,predecessor_packet_sha256,bp_packet_sha256,registrar_pin_sha256,collector_pinset_sha256,endpoint_config_sha256,challenge_sha256,claimed_revocation_epoch,outcome) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
   [args.quoteId,args.version,packetHash,args.previousPacketSha256,
    expected.bpPacketSha256,root,pins,origins,args.packet.challengeSha256,
    epoch,outcome]);
  if(challenge.status==='ISSUED')await conn.execute(
   "UPDATE quote_bq_candidate_remote_challenges SET status='CONSUMED',consumed_packet_sha256=? WHERE quote_id=? AND challenge_sha256=?",
   [packetHash,args.quoteId,args.packet.challengeSha256]);
  if(outcome===GOOD)await conn.execute(
   'UPDATE quote_bq_candidate_remote_streams SET last_version=?,last_packet_sha256=?,last_bp_packet_sha256=?,last_registrar_pin_sha256=?,last_collector_pinset_sha256=?,last_endpoint_config_sha256=?,last_challenge_sha256=?,last_claimed_revocation_epoch=? WHERE quote_id=?',
   [args.version,packetHash,expected.bpPacketSha256,root,pins,origins,
    args.packet.challengeSha256,epoch,args.quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')
   await conn.execute(
    "UPDATE quote_bq_candidate_remote_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
    [args.quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
