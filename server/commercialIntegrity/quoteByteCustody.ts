import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {bqRemoteWriteTarget,readCandidateRemoteExpectedUnderLock,
 inspectCandidateRemoteEvidenceOnConnection} from './quoteRemoteCustody';
import {assessCandidateProviderBytes,candidateBytePacketDigest,
 candidateRootCertificateDigest,type CandidateProviderBytePacket,
 type CandidateByteExpected} from './quoteProviderBytes';
import type {CandidateRemotePacket} from './quoteRemoteEvidence';

// 1BR: local offline byte custody only. Actual provider agreement, trusted
// registrar/root PKI, live TLS, CRL/OCSP, WORM, DR and legal release absent.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const SHA=/^[0-9a-f]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({
 candidateByteCustodyOnly:true,enrolledExternalRootAuthenticated:false,
 liveTlsProviderSessionVerified:false,
 authorizedIssuerPolicyAndCertificatePathVerified:false,
 signedCrlOcspAndResponderAuthorized:false,
 independentWormObjectLockVerified:false,
 realEncryptedDrRestorationWitnessed:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD' as const
});
export function brCandidateByteWriteTarget(env:NodeJS.ProcessEnv){
 const target=bqRemoteWriteTarget(env);
 if(target==='staging'&&env.BR_BYTE_INTAKE_APPROVED!=='YES')
  throw Error('Phase 1BR separate approved disposable TLS staging only');
 return target;
}
export async function readCandidateByteExpectedUnderLock(conn:PoolConnection,quoteId:string){
 const {expected:bqExpected}=await readCandidateRemoteExpectedUnderLock(conn,quoteId);
 const bq=await inspectCandidateRemoteEvidenceOnConnection(conn,quoteId,bqExpected);
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT last_claimed_revocation_epoch FROM quote_bq_candidate_remote_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 const expected:CandidateByteExpected={
  quoteId,bqPacketSha256:bq.candidateRemotePacketSha256??'',
  bmReceiptSha256:bqExpected.bmReceiptSha256,
  sourceSha256:bqExpected.sourceSha256,sequence:bqExpected.bmSequence,
  revocationEpoch:Number(heads[0]?.last_claimed_revocation_epoch??0),
  bqExists:bq.candidateRemoteExists,
  bqLocallyConsistent:bq.candidateRemoteLocallyConsistent&&
   bqExpected.bpLocallyConsistent,
  bqGovernanceState:bq.candidateRemoteGovernanceState as CandidateByteExpected['bqGovernanceState']
 };
 return {expected,bq};
}
export async function inspectCandidateProviderBytesOnConnection(conn:PoolConnection,
 quoteId:string,expected:CandidateByteExpected){
 if(!UUID.test(quoteId))throw Error('Phase 1BR invalid quote ID');
 const [rows]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_br_candidate_byte_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
 if(rows.length===0)return Object.freeze({
  candidateByteExists:false,candidateByteVersion:0,candidateBytePacketSha256:null,
  candidateByteAttemptCount:0,candidateByteGovernanceState:'ABSENT',
  candidateByteLocallyConsistent:true,
  candidateByteAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const head=rows[0],errors=new Set<string>();
 const [attempts]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_br_candidate_byte_attempts WHERE quote_id=? ORDER BY id ASC LIMIT 1002 FOR UPDATE',
  [quoteId]);
 let version=0,packet:null|string=null,bq:null|string=null,
  root:null|string=null,epoch=0,incident=false;
 const acceptedBq=new Set<string>();
 if(attempts.length>1000)errors.add('BR_HISTORY_LIMIT');
 for(const row of attempts){
  const v=Number(row.version_number),rev=Number(row.claimed_revocation_epoch);
  if(!Number.isSafeInteger(v)||v<1||
     !Number.isSafeInteger(rev)||rev<1||
     ![row.packet_sha256,row.bq_packet_sha256,row.root_cert_sha256]
      .every(x=>SHA.test(String(x)))||
     (row.predecessor_packet_sha256!==null&&!SHA.test(String(row.predecessor_packet_sha256))))
   errors.add('BR_LEDGER_ROW_INVALID');
  if(row.outcome===GOOD){
   if(incident||v!==version+1||row.predecessor_packet_sha256!==packet||
      acceptedBq.has(row.bq_packet_sha256)||
      (version>0&&(row.root_cert_sha256!==root||rev<epoch)))
    errors.add('BR_ACCEPTED_HISTORY_BROKEN');
   version=v;packet=row.packet_sha256;bq=row.bq_packet_sha256;
   root=row.root_cert_sha256;epoch=rev;acceptedBq.add(bq);
  }else incident=true;
 }
 if(Number(head.last_version)!==version||head.last_packet_sha256!==packet||
    head.last_bq_packet_sha256!==bq||head.last_root_cert_sha256!==root||
    Number(head.last_claimed_revocation_epoch)!==epoch)
  errors.add('BR_HEAD_LEDGER_DIVERGENCE');
 if((head.governance_state==='QUARANTINED')!==incident)
  errors.add('BR_QUARANTINE_STATE_DIVERGENCE');
 if(head.provider_root_independently_authenticated!=='NO'||
    head.live_provider_tls_attested!=='NO'||
    head.issuer_policy_and_chain_authorized!=='NO'||
    head.signed_crl_ocsp_authorized!=='NO'||
    head.independent_worm_verified!=='NO'||
    head.actual_dr_restore_witnessed!=='NO'||
    head.production_release!=='HOLD')
  errors.add('BR_FORBIDDEN_TRUST_PROMOTION');
 if(version>0&&(expected.bqLocallyConsistent!==true||
    expected.bqGovernanceState!=='HELD_UNVERIFIED'||
    expected.bqPacketSha256!==bq||expected.revocationEpoch>epoch))
  errors.add('BR_UPSTREAM_BQ_CHANGED');
 return Object.freeze({
  candidateByteExists:true,candidateByteVersion:version,
  candidateBytePacketSha256:packet,candidateByteAttemptCount:attempts.length,
  candidateByteGovernanceState:String(head.governance_state),
  candidateByteLocallyConsistent:errors.size===0,
  candidateByteAnomalyCodes:Object.freeze([...errors].sort()),...HOLD
 });
}
export async function inspectCandidateProviderBytes(pool:Pool,quoteId:string,
 env:NodeJS.ProcessEnv=process.env){
 brCandidateByteWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateByteExpectedUnderLock(conn,quoteId);
  const result=await inspectCandidateProviderBytesOnConnection(conn,quoteId,expected);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateProviderBytes(pool:Pool,args:{
 quoteId:string,version:number,previousPacketSha256:string|null,
 packet:CandidateProviderBytePacket,bqPacket:CandidateRemotePacket,
 rootCertificatePem:string,now?:Date,env?:NodeJS.ProcessEnv
}){
 const env=args.env??process.env;brCandidateByteWriteTarget(env);
 if(!UUID.test(args.quoteId)||!Number.isSafeInteger(args.version)||
    args.version<1||args.version>1000||
    (args.previousPacketSha256!==null&&!SHA.test(args.previousPacketSha256)))
  throw Error('Phase 1BR invalid quote/version/predecessor');
 if(!SHA.test(String(env.BR_ROOT_CERT_SHA256))||
    typeof env.BR_PROVIDER_ORIGIN!=='string'||
    !/^https:\/\/[a-z0-9.-]{4,150}\/$/.test(env.BR_PROVIDER_ORIGIN))
  throw Error('Phase 1BR externally configured candidate root and origin required');
 const configuredRoot=candidateRootCertificateDigest(args.rootCertificatePem);
 if(configuredRoot!==env.BR_ROOT_CERT_SHA256)
  throw Error('Phase 1BR configured candidate trust root substituted');
 // Bounded before connection; signatures and origin are separately checked
 // below against the actual BQ upstream head under the quote parent lock.
 const packetDigest=candidateBytePacketDigest(args.packet);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateByteExpectedUnderLock(conn,args.quoteId);
  if(!expected.bqExists)throw Error('Phase 1BR missing BQ source custody');
  const assessed=assessCandidateProviderBytes({
   packet:args.packet,expected,bqPacket:args.bqPacket,
   rootCertificatePem:args.rootCertificatePem,
   expectedRootCertSha256:env.BR_ROOT_CERT_SHA256,
   expectedProviderOrigin:env.BR_PROVIDER_ORIGIN,
   now:args.now??new Date()
  });
  if(assessed.candidateBytePreflightAnomalyCodes.some(x=>[
     'BR_PACKET_SHAPE_INVALID','BR_BYTES_INVALID_NONCANONICAL_OR_DER_BOUND',
     'BR_CHECKPOINT_BODY_INVALID','BR_CERTIFICATE_PARSE_OR_SIGNATURE_FAILED',
     'BR_SIGNED_CHECKPOINT_BYTES_INVALID'
   ].includes(x)))
   throw Error('Phase 1BR malformed or unsigned provider byte packet refused');
  await conn.execute(
   'INSERT INTO quote_br_candidate_byte_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_br_candidate_byte_streams WHERE quote_id=? FOR UPDATE',[args.quoteId]);
  const h=heads[0],last=Number(h.last_version);
  if(!h||!Number.isSafeInteger(last)||last<0||last>1000)
   throw Error('Phase 1BR invalid stored stream version');
  const prior=await inspectCandidateProviderBytesOnConnection(conn,args.quoteId,expected);
  if(!prior.candidateByteLocallyConsistent&&
    !prior.candidateByteAnomalyCodes.every(x=>x==='BR_UPSTREAM_BQ_CHANGED'))
   throw Error('Phase 1BR local byte custody tamper detected');
  const [dupes]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_br_candidate_byte_attempts WHERE quote_id=? AND packet_sha256=? LIMIT 2 FOR UPDATE',
   [args.quoteId,packetDigest]);
  if(h.governance_state==='HELD_UNVERIFIED'&&last===args.version&&
    h.last_packet_sha256===packetDigest&&prior.candidateByteLocallyConsistent&&
    assessed.candidateBytePreflightConsistent&&dupes.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({
    outcome:'REPLAY',governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(dupes.length){
   await conn.commit();return Object.freeze({
    outcome:'DUPLICATE_REJECTED',governanceState:String(h.governance_state),...HOLD});
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(!expected.bqLocallyConsistent||
     expected.bqGovernanceState!=='HELD_UNVERIFIED'||
     prior.candidateByteAnomalyCodes.includes('BR_UPSTREAM_BQ_CHANGED'))
   outcome='UPSTREAM_DRIFT_QUARANTINED';
  else if(expected.revocationEpoch<Number(h.last_claimed_revocation_epoch))
   outcome='REVOCATION_REGRESSION_QUARANTINED';
  else if(last>0&&configuredRoot!==h.last_root_cert_sha256)
   outcome='ROOT_CHANGE_QUARANTINED';
  else if(last>0&&expected.bqPacketSha256===h.last_bq_packet_sha256)
   outcome='BQ_REPLAY_QUARANTINED';
  else if(!assessed.candidateBytePreflightConsistent)
   outcome='RAW_BYTES_CONFLICT_QUARANTINED';
  else if(last===0)outcome=args.version===1&&args.previousPacketSha256===null?
   GOOD:'GAP_QUARANTINED';
  else if(args.version<=last)outcome=args.version===last?
   'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(args.version!==last+1)outcome='GAP_QUARANTINED';
  else if(args.previousPacketSha256!==h.last_packet_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_br_candidate_byte_attempts (quote_id,version_number,packet_sha256,predecessor_packet_sha256,bq_packet_sha256,root_cert_sha256,claimed_revocation_epoch,outcome) VALUES (?,?,?,?,?,?,?,?)',
   [args.quoteId,args.version,packetDigest,args.previousPacketSha256,
    expected.bqPacketSha256,configuredRoot,expected.revocationEpoch,outcome]);
  if(outcome===GOOD)await conn.execute(
   'UPDATE quote_br_candidate_byte_streams SET last_version=?,last_packet_sha256=?,last_bq_packet_sha256=?,last_root_cert_sha256=?,last_claimed_revocation_epoch=? WHERE quote_id=?',
   [args.version,packetDigest,expected.bqPacketSha256,configuredRoot,
    expected.revocationEpoch,args.quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')await conn.execute(
   "UPDATE quote_br_candidate_byte_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
   [args.quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
