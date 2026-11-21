import {createHash} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {brCandidateByteWriteTarget,readCandidateByteExpectedUnderLock,
 inspectCandidateProviderBytesOnConnection} from './quoteByteCustody';
import {candidateBytePacketDigest,candidateRootCertificateDigest,
 type CandidateProviderBytePacket} from './quoteProviderBytes';
import {assessCandidateSignedRevocation,type CandidateRevocationExpected}
 from './quoteSignedRevocation';

// 1BS is candidate-only. Even signature-valid CRL/OCSP with an internally
// pinned test CA is not a real RCAI/CCA/eMudhra provider authorization.
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({
 candidateSignedRevocationOnly:true,
 independentlyEnrolledCAKey:false,genuineRCAIorCCAIssuerPolicyVerified:false,
 realProviderCrlDistributionAuthenticated:false,
 liveOcspRequestResponseAuthenticated:false,
 externalMonotonicHeadIndependentlyRetained:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD' as const
});
export function bsSignedRevocationWriteTarget(env:NodeJS.ProcessEnv){
 const target=brCandidateByteWriteTarget(env);
 if(target==='staging'&&env.BS_SIGNED_REVOCATION_WRITE_APPROVED!=='YES')
  throw Error('Phase 1BS separate disposable TLS staging opt-in required');
 return target;
}
export function candidateSignedRevocationReceiptDigest(args:{
 quoteId:string,brPacketSha256:string,rootSha256:string,
 crlNumber:number,crlUntil:number,ocspUntil:number
}){
 return createHash('sha256')
  .update('aaditech/quote/signed-revocation/candidate/v1\n'+JSON.stringify(args))
  .digest('hex');
}
export async function readCandidateSignedRevocationExpectedUnderLock(
 conn:PoolConnection,quoteId:string){
 const {expected:brExpected}=await readCandidateByteExpectedUnderLock(conn,quoteId);
 const br=await inspectCandidateProviderBytesOnConnection(conn,quoteId,brExpected);
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT last_root_cert_sha256,last_claimed_revocation_epoch FROM quote_br_candidate_byte_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 const expected:CandidateRevocationExpected={
  quoteId,brPacketSha256:br.candidateBytePacketSha256??'',
  rootCertSha256:String(heads[0]?.last_root_cert_sha256??''),
  minimumRevocationEpoch:Math.max(brExpected.revocationEpoch,
   Number(heads[0]?.last_claimed_revocation_epoch??0)),
  brExists:br.candidateByteExists,
  brLocallyConsistent:br.candidateByteLocallyConsistent&&
   brExpected.bqLocallyConsistent,
  brGovernanceState:br.candidateByteGovernanceState as CandidateRevocationExpected['brGovernanceState']
 };
 return {expected,br};
}
export async function inspectCandidateSignedRevocationOnConnection(
 conn:PoolConnection,quoteId:string,expected:CandidateRevocationExpected,
 now:Date=new Date()){
 if(!UUID.test(quoteId))throw Error('Phase 1BS invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bs_candidate_revocation_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 if(!heads.length)return Object.freeze({
  candidateSignedRevocationExists:false,candidateSignedRevocationVersion:0,
  candidateSignedRevocationPacketSha256:null,
  candidateSignedRevocationAttemptCount:0,
  candidateSignedRevocationGovernanceState:'ABSENT',
  candidateSignedRevocationLocallyConsistent:true,
  candidateSignedRevocationAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const h=heads[0],errors=new Set<string>();
 const [events]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bs_candidate_revocation_attempts WHERE quote_id=? ORDER BY id ASC LIMIT 1002 FOR UPDATE',
  [quoteId]);
 let version=0,packet:null|string=null,br:null|string=null,
  root:null|string=null,crl=0,crlUntil:null|number=null,
  ocspUntil:null|number=null,incident=false;
 const seenBr=new Set<string>();
 if(events.length>1000)errors.add('BS_LEDGER_BOUND_EXCEEDED');
 for(const row of events){
  const v=Number(row.version_number),number=Number(row.crl_number);
  if(!Number.isSafeInteger(v)||v<1||!Number.isSafeInteger(number)||
     number<0||(row.outcome===GOOD&&number<1)||
     ![row.packet_sha256,row.br_packet_sha256,row.issuer_root_sha256]
      .every(x=>SHA.test(String(x)))||
     (row.predecessor_packet_sha256!==null&&
      !SHA.test(String(row.predecessor_packet_sha256))))
   errors.add('BS_LEDGER_ROW_INVALID');
  if(row.outcome===GOOD){
   if(incident||v!==version+1||row.predecessor_packet_sha256!==packet||
      seenBr.has(row.br_packet_sha256)||
      (version>0&&(row.issuer_root_sha256!==root||number<crl)))
    errors.add('BS_ACCEPTED_HISTORY_BROKEN');
   version=v;packet=row.packet_sha256;br=row.br_packet_sha256;
   root=row.issuer_root_sha256;crl=number;
   crlUntil=new Date(row.crl_until).getTime();
   ocspUntil=new Date(row.ocsp_until).getTime();
   if(!Number.isFinite(crlUntil)||!Number.isFinite(ocspUntil))
    errors.add('BS_LEDGER_FRESHNESS_MALFORMED');
   seenBr.add(br);
  }else incident=true;
 }
 if(Number(h.last_version)!==version||h.last_packet_sha256!==packet||
    h.last_br_packet_sha256!==br||h.last_candidate_issuer_root_sha256!==root||
    Number(h.last_crl_number)!==crl||
    (version>0&&(new Date(h.last_crl_until).getTime()!==crlUntil||
      new Date(h.last_ocsp_until).getTime()!==ocspUntil))||
    (version===0&&(h.last_crl_until!==null||h.last_ocsp_until!==null)))
  errors.add('BS_HEAD_HISTORY_DIVERGENCE');
 if((h.governance_state==='QUARANTINED')!==incident)
  errors.add('BS_STICKY_QUARANTINE_MISMATCH');
 if(h.authorized_real_issuer_enrolled!=='NO'||
    h.real_signed_crl_distribution_verified!=='NO'||
    h.live_authorized_ocsp_responder_verified!=='NO'||
    h.independent_revocation_monotonicity_proven!=='NO'||
    h.production_release!=='HOLD')
  errors.add('BS_FORBIDDEN_AUTHORITY_PROMOTION');
 if(version>0&&(expected.brLocallyConsistent!==true||
    expected.brGovernanceState!=='HELD_UNVERIFIED'||
    expected.brPacketSha256!==br||expected.rootCertSha256!==root||
    expected.minimumRevocationEpoch>crl))
  errors.add('BS_UPSTREAM_BR_HEAD_CHANGED');
 if(version>0&&(!Number.isFinite(now.getTime())||
     crlUntil===null||ocspUntil===null||now.getTime()>=crlUntil||
     now.getTime()>=ocspUntil))
  errors.add('BS_SIGNED_STATUS_EXPIRED');
 return Object.freeze({
  candidateSignedRevocationExists:true,candidateSignedRevocationVersion:version,
  candidateSignedRevocationPacketSha256:packet,
  candidateSignedRevocationAttemptCount:events.length,
  candidateSignedRevocationGovernanceState:String(h.governance_state),
  candidateSignedRevocationLocallyConsistent:errors.size===0,
  candidateSignedRevocationAnomalyCodes:Object.freeze([...errors].sort()),...HOLD
 });
}
export async function inspectCandidateSignedRevocation(pool:Pool,quoteId:string,
 env:NodeJS.ProcessEnv=process.env,now:Date=new Date()){
 bsSignedRevocationWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateSignedRevocationExpectedUnderLock(conn,quoteId);
  const result=await inspectCandidateSignedRevocationOnConnection(
   conn,quoteId,expected,now);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateSignedRevocation(pool:Pool,args:{
 quoteId:string,version:number,previousPacketSha256:string|null,
 brPacket:CandidateProviderBytePacket,issuerCertificatePem:string,
 now?:Date,env?:NodeJS.ProcessEnv
}){
 const env=args.env??process.env;bsSignedRevocationWriteTarget(env);
 if(!UUID.test(args.quoteId)||!Number.isSafeInteger(args.version)||
    args.version<1||args.version>1000||
    (args.previousPacketSha256!==null&&!SHA.test(args.previousPacketSha256)))
  throw Error('Phase 1BS invalid quote/version/predecessor');
 if(!SHA.test(String(env.BS_ISSUER_ROOT_SHA256)))
  throw Error('Phase 1BS independent candidate issuer root pin required');
 const root=candidateRootCertificateDigest(args.issuerCertificatePem);
 if(root!==env.BS_ISSUER_ROOT_SHA256)
  throw Error('Phase 1BS independent candidate issuer root substitution denied');
 const at=args.now??new Date();
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateSignedRevocationExpectedUnderLock(
   conn,args.quoteId);
  if(!expected.brExists)throw Error('Phase 1BS upstream BR signed bytes absent');
  const assessed=assessCandidateSignedRevocation({
   brPacket:args.brPacket,expected,
   issuerCertificatePem:args.issuerCertificatePem,
   expectedIssuerRootSha256:env.BS_ISSUER_ROOT_SHA256,now:at
  });
  if(assessed.candidateSignedRevocationAnomalyCodes.some(x=>[
   'BS_ISSUER_SIGNATURE_INVALID','BS_ASN1_SIGNATURE_OR_STRUCTURE_INVALID',
   'BS_NONCANONICAL_BASE64','BS_UNSUPPORTED_SIGNATURE_ALGORITHM',
   'BS_ISSUER_ROOT_PIN_OR_LEAF_CHAIN_INVALID','BS_CERT_VALIDITY_INVALID'
  ].includes(x)))
   throw Error('Phase 1BS unsigned or malformed issuer status rejected');
  const packetHash=candidateBytePacketDigest(args.brPacket);
  const number=assessed.crlNumber??0;
  const responseHash=candidateSignedRevocationReceiptDigest({
   quoteId:args.quoteId,brPacketSha256:packetHash,rootSha256:root,
   crlNumber:number,crlUntil:assessed.crlUntil??0,
   ocspUntil:assessed.ocspUntil??0
  });
  await conn.execute(
   'INSERT INTO quote_bs_candidate_revocation_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [args.quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bs_candidate_revocation_streams WHERE quote_id=? FOR UPDATE',
   [args.quoteId]);
  const h=heads[0],last=Number(h.last_version);
  if(!h||!Number.isSafeInteger(last)||last<0||last>1000)
   throw Error('Phase 1BS invalid local stream version');
  const prior=await inspectCandidateSignedRevocationOnConnection(
   conn,args.quoteId,expected,at);
  if(!prior.candidateSignedRevocationLocallyConsistent&&
     !prior.candidateSignedRevocationAnomalyCodes.every(x=>
      x==='BS_UPSTREAM_BR_HEAD_CHANGED'||x==='BS_SIGNED_STATUS_EXPIRED'))
   throw Error('Phase 1BS local source ledger corrupt');
  const [dupes]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bs_candidate_revocation_attempts WHERE quote_id=? AND packet_sha256=? LIMIT 2 FOR UPDATE',
   [args.quoteId,responseHash]);
  if(h.governance_state==='HELD_UNVERIFIED'&&last===args.version&&
    h.last_packet_sha256===responseHash&&
    prior.candidateSignedRevocationLocallyConsistent&&
    assessed.candidateSignedRevocationConsistent&&
    dupes.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({
    outcome:'REPLAY',governanceState:'HELD_UNVERIFIED',...HOLD});
  }
  if(dupes.length){
   await conn.commit();return Object.freeze({
    outcome:'DUPLICATE_REJECTED',governanceState:String(h.governance_state),...HOLD});
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(!expected.brLocallyConsistent||
    expected.brGovernanceState!=='HELD_UNVERIFIED'||
    prior.candidateSignedRevocationAnomalyCodes.includes('BS_UPSTREAM_BR_HEAD_CHANGED'))
   outcome='UPSTREAM_DRIFT_QUARANTINED';
  else if(assessed.candidateSignedRevocationAnomalyCodes.includes('BS_CRL_NUMBER_ROLLBACK')||
    (assessed.crlNumber!==null&&
     (number<expected.minimumRevocationEpoch||number<Number(h.last_crl_number))))
   outcome='CRL_EPOCH_REGRESSION_QUARANTINED';
  else if(assessed.candidateSignedRevocationAnomalyCodes.some(x=>
   x.includes('STALE')||x.includes('FUTURE'))||
   prior.candidateSignedRevocationAnomalyCodes.includes('BS_SIGNED_STATUS_EXPIRED'))
   outcome='STATUS_STALE_QUARANTINED';
  else if(!assessed.candidateSignedRevocationConsistent)
   outcome='SOURCE_REVOCATION_CONFLICT_QUARANTINED';
  else if(last>0&&root!==h.last_candidate_issuer_root_sha256)
   outcome='ROOT_CHANGE_QUARANTINED';
  else if(last>0&&packetHash===h.last_br_packet_sha256)
   outcome='BR_REPLAY_QUARANTINED';
  else if(last===0)outcome=args.version===1&&args.previousPacketSha256===null?
   GOOD:'GAP_QUARANTINED';
  else if(args.version<=last)outcome=args.version===last?
   'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(args.version!==last+1)outcome='GAP_QUARANTINED';
  else if(args.previousPacketSha256!==h.last_packet_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_bs_candidate_revocation_attempts (quote_id,version_number,packet_sha256,predecessor_packet_sha256,br_packet_sha256,issuer_root_sha256,crl_number,crl_until,ocsp_until,outcome) VALUES (?,?,?,?,?,?,?,?,?,?)',
   [args.quoteId,args.version,responseHash,args.previousPacketSha256,packetHash,
    root,number,
    assessed.crlUntil!==null?new Date(assessed.crlUntil):null,
    assessed.ocspUntil!==null?new Date(assessed.ocspUntil):null,outcome]);
  if(outcome===GOOD)await conn.execute(
   'UPDATE quote_bs_candidate_revocation_streams SET last_version=?,last_packet_sha256=?,last_br_packet_sha256=?,last_candidate_issuer_root_sha256=?,last_crl_number=?,last_crl_until=?,last_ocsp_until=? WHERE quote_id=?',
   [args.version,responseHash,packetHash,root,number,
    new Date(assessed.crlUntil!),new Date(assessed.ocspUntil!),args.quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')await conn.execute(
   "UPDATE quote_bs_candidate_revocation_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
   [args.quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
