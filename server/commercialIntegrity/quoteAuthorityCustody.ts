import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {bmQuoteCheckpointWriteTarget,inspectCandidateQuoteCheckpointOnConnection,
 readCandidateQuoteSourceUnderLock} from './quoteCheckpointCustody';
import {inspectCandidateQuoteReconciliationOnConnection}
 from './quoteReconciliationCustody';
import {assessCandidateExternalAuthorityDossier,
 candidateExternalAuthorityDossierDigest,type CandidateExternalAuthorityDossier,
 type CandidateExternalAuthorityExpected} from './quoteAuthorityDossier';

// Phase 1BO: INTERNAL / UNVERIFIED dossier custody ONLY. No external enrollment,
// provider network, HTTP writer, real WORM, legal/KYC, CRL/OCSP or actual DR.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
const HOLD=Object.freeze({
 candidateOnly:true,independentProviderAgreementAuthenticated:false,
 independentKeyEnrollmentAuthenticated:false,
 trustedOutOfBandPublicationHeadVerified:false,
 independentRevocationAndCrlOcspVerified:false,
 independentWormRetentionVerified:false,
 actualEncryptedDrWitnessed:false,
 legalSignatoryIdentityVerified:false,
 independentReleaseSignoffsVerified:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,
 releaseDecision:'HOLD' as const
});
export function boAuthorityDossierWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 const target=bmQuoteCheckpointWriteTarget(env);
 if(target==='staging'&&(
   env.BN_RECONCILIATION_WRITE_APPROVED!=='YES'||
   env.BO_AUTHORITY_DOSSIER_WRITE_APPROVED!=='YES'))
  throw Error('Phase 1BO requires separate approved disposable TLS staging dossier opt-in');
 return target;
}
type Upstream={candidateCheckpointExists:boolean,
 candidateCheckpointSequence:number,candidateCheckpointReceiptSha256:string|null,
 candidateCheckpointSourceSha256:string|null,
 candidateCheckpointLocallyConsistent:boolean,
 candidateCheckpointGovernanceState:string};
type BnReadback={candidateReconciliationExists:boolean,
 candidateReconciliationPacketSha256:string|null,
 candidateReconciliationLocallyConsistent:boolean,
 candidateReconciliationGovernanceState:string};
export async function readCandidateAuthorityExpectedUnderLock(
 conn:PoolConnection,quoteId:string){
 const {commitment,sourceValid}=await readCandidateQuoteSourceUnderLock(conn,quoteId);
 const bm=await inspectCandidateQuoteCheckpointOnConnection(
  conn,quoteId,commitment.sourceCommitmentSha256);
 const bn=await inspectCandidateQuoteReconciliationOnConnection(conn,quoteId,bm);
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT last_pinset_sha256,last_revocation_epoch FROM quote_bn_candidate_reconciliation_streams WHERE quote_id=? FOR UPDATE',
  [quoteId]);
 const raw=heads[0];
 const expected:CandidateExternalAuthorityExpected={
  quoteId,
  bnPacketSha256:bn.candidateReconciliationPacketSha256??'',
  bmReceiptSha256:bm.candidateCheckpointReceiptSha256??'',
  quoteSourceSha256:commitment.sourceCommitmentSha256,
  candidatePinsetSha256:String(raw?.last_pinset_sha256??''),
  bmSequence:bm.candidateCheckpointSequence,
  bnRevocationEpoch:Number(raw?.last_revocation_epoch??0),
  bmGovernanceState:bm.candidateCheckpointGovernanceState as CandidateExternalAuthorityExpected['bmGovernanceState'],
  bnGovernanceState:bn.candidateReconciliationGovernanceState as CandidateExternalAuthorityExpected['bnGovernanceState'],
  bmLocallyConsistent:bm.candidateCheckpointLocallyConsistent,
  bnLocallyConsistent:bn.candidateReconciliationLocallyConsistent
 };
 return {expected,sourceValid,bm,bn};
}
export async function inspectCandidateExternalAuthorityDossierOnConnection(
 conn:PoolConnection,quoteId:string,
 expected:CandidateExternalAuthorityExpected){
 if(!UUID.test(quoteId))throw Error('Phase 1BO invalid quote ID');
 const [heads]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bo_candidate_authority_streams WHERE quote_id=? FOR UPDATE',[quoteId]);
 if(!heads.length)return Object.freeze({
  candidateAuthorityDossierExists:false,candidateAuthorityDossierVersion:0,
  candidateAuthorityDossierSha256:null,
  candidateAuthorityDossierGovernanceState:'ABSENT',
  candidateAuthorityDossierAttemptCount:0,
  candidateAuthorityDossierLocallyConsistent:true,
  candidateAuthorityDossierAnomalyCodes:Object.freeze([] as string[]),...HOLD
 });
 const h=heads[0],errors=new Set<string>();
 const [rows]=await conn.execute<RowDataPacket[]>(
  'SELECT * FROM quote_bo_candidate_authority_attempts WHERE quote_id=? ORDER BY id ASC LIMIT 1002 FOR UPDATE',
  [quoteId]);
 let version=0,digest:null|string=null,bnPacket:null|string=null,
  bmReceipt:null|string=null,source:null|string=null,pinset:null|string=null,
  epoch=0,incident=false;
 if(rows.length>1000)errors.add('BO_DOSSIER_HISTORY_BOUND');
 for(const row of rows){
  const n=Number(row.dossier_version),e=Number(row.claimed_revocation_epoch);
  if(!Number.isSafeInteger(n)||n<1||
     !Number.isSafeInteger(e)||e<1||
     ![row.dossier_sha256,row.bn_packet_sha256,row.bm_receipt_sha256,
       row.quote_source_sha256,row.candidate_pinset_sha256].every(v=>SHA.test(String(v)))||
     (row.predecessor_sha256!==null&&!SHA.test(String(row.predecessor_sha256))))
   errors.add('BO_DOSSIER_ATTEMPT_MALFORMED');
  if(row.outcome===GOOD){
   if(incident||n!==version+1||row.predecessor_sha256!==digest||
      (version>0&&(e<epoch||
       row.candidate_pinset_sha256!==pinset)))
    errors.add('BO_DOSSIER_ACCEPTED_HISTORY_INVALID');
   version=n;digest=row.dossier_sha256;bnPacket=row.bn_packet_sha256;
   bmReceipt=row.bm_receipt_sha256;source=row.quote_source_sha256;
   pinset=row.candidate_pinset_sha256;epoch=e;
  }else incident=true;
 }
 if(Number(h.last_version)!==version||h.last_dossier_sha256!==digest||
    h.last_bn_packet_sha256!==bnPacket||h.last_bm_receipt_sha256!==bmReceipt||
    h.last_source_sha256!==source||h.last_pinset_sha256!==pinset||
    Number(h.last_claimed_revocation_epoch)!==epoch)
  errors.add('BO_DOSSIER_HEAD_HISTORY_DIVERGENCE');
 if((h.governance_state==='QUARANTINED')!==incident)
  errors.add('BO_DOSSIER_QUARANTINE_STATE_MISMATCH');
 if(h.provider_enrolled!=='NO'||h.out_of_band_head_verified!=='NO'||
    h.independent_revocation_verified!=='NO'||h.encrypted_dr_witnessed!=='NO'||
    h.legal_signoffs_verified!=='NO'||h.production_release!=='HOLD')
  errors.add('BO_DOSSIER_ILLICIT_EXTERNAL_TRUST_PROMOTION');
 if(version>0&&(
    expected.bmGovernanceState!=='HELD_UNVERIFIED'||
    expected.bnGovernanceState!=='HELD_UNVERIFIED'||
    !expected.bmLocallyConsistent||!expected.bnLocallyConsistent||
    expected.bnPacketSha256!==bnPacket||
    expected.bmReceiptSha256!==bmReceipt||
    expected.quoteSourceSha256!==source||
    expected.candidatePinsetSha256!==pinset||
    expected.bnRevocationEpoch>epoch))
  errors.add('BO_DOSSIER_UPSTREAM_BM_BN_CHANGED');
 return Object.freeze({
  candidateAuthorityDossierExists:true,candidateAuthorityDossierVersion:version,
  candidateAuthorityDossierSha256:digest,
  candidateAuthorityDossierGovernanceState:String(h.governance_state),
  candidateAuthorityDossierAttemptCount:rows.length,
  candidateAuthorityDossierLocallyConsistent:errors.size===0,
  candidateAuthorityDossierAnomalyCodes:Object.freeze([...errors].sort()),
  ...HOLD
 });
}
export async function inspectCandidateExternalAuthorityDossier(
 pool:Pool,quoteId:string,env:NodeJS.ProcessEnv=process.env){
 boAuthorityDossierWriteTarget(env);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateAuthorityExpectedUnderLock(conn,quoteId);
  const result=await inspectCandidateExternalAuthorityDossierOnConnection(
   conn,quoteId,expected);
  await conn.commit();return result;
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
export async function recordCandidateExternalAuthorityDossier(pool:Pool,args:{
 quoteId:string,version:number,previousDossierSha256:string|null,
 dossier:CandidateExternalAuthorityDossier,now?:Date,env?:NodeJS.ProcessEnv
}){
 boAuthorityDossierWriteTarget(args.env??process.env);
 const {quoteId,version,previousDossierSha256,dossier}=args;
 if(!UUID.test(quoteId)||dossier?.quoteId!==quoteId||
    !Number.isSafeInteger(version)||version<1||version>1000||
    (previousDossierSha256!==null&&!SHA.test(previousDossierSha256)))
  throw Error('Phase 1BO malformed or unbound dossier write');
 // Validate/bound payload before opening a MySQL connection.
 const digest=candidateExternalAuthorityDossierDigest(dossier);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const {expected,sourceValid}=await readCandidateAuthorityExpectedUnderLock(conn,quoteId);
  if(!SHA.test(expected.bnPacketSha256)||!SHA.test(expected.bmReceiptSha256)||
     !SHA.test(expected.quoteSourceSha256)||!SHA.test(expected.candidatePinsetSha256))
   throw Error('Phase 1BO missing upstream BM/BN candidate evidence');
  const review=assessCandidateExternalAuthorityDossier({
   dossier,expected,now:args.now??new Date()});
  // Completely malformed payloads should never enter an audit log.
  if(review.candidateDossierAnomalyCodes.includes('BO_DOSSIER_SHAPE_OR_BINDING_INVALID'))
   throw Error('Phase 1BO candidate dossier structural invalid');
  await conn.execute(
   'INSERT INTO quote_bo_candidate_authority_streams(quote_id) VALUES (?) ON DUPLICATE KEY UPDATE quote_id=quote_id',
   [quoteId]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM quote_bo_candidate_authority_streams WHERE quote_id=? FOR UPDATE',
   [quoteId]);
  const h=heads[0],latest=Number(h.last_version);
  if(!h||!Number.isSafeInteger(latest)||latest<0||latest>1000||
     (latest===0&&(h.last_dossier_sha256!==null||
      h.last_bn_packet_sha256!==null||h.last_bm_receipt_sha256!==null||
      h.last_source_sha256!==null||h.last_pinset_sha256!==null||
      Number(h.last_claimed_revocation_epoch)!==0)))
   throw Error('Phase 1BO corrupt dossier head');
  const prior=await inspectCandidateExternalAuthorityDossierOnConnection(
   conn,quoteId,expected);
  if(!prior.candidateAuthorityDossierLocallyConsistent&&
     !prior.candidateAuthorityDossierAnomalyCodes.every(
      c=>c==='BO_DOSSIER_UPSTREAM_BM_BN_CHANGED'))
   throw Error('Phase 1BO cannot append to corrupt candidate dossier history');
  const [duplicates]=await conn.execute<RowDataPacket[]>(
   'SELECT outcome FROM quote_bo_candidate_authority_attempts WHERE quote_id=? AND dossier_sha256=? LIMIT 2 FOR UPDATE',
   [quoteId,digest]);
  if(h.governance_state==='HELD_UNVERIFIED'&&latest===version&&
     h.last_dossier_sha256===digest&&sourceValid&&
     prior.candidateAuthorityDossierLocallyConsistent&&
     review.candidateDossierInternallyConsistent&&
     duplicates.some(x=>x.outcome===GOOD)){
   await conn.commit();return Object.freeze({
    outcome:'REPLAY',governanceState:'HELD_UNVERIFIED',...HOLD
   });
  }
  if(duplicates.length){
   await conn.commit();return Object.freeze({
    outcome:'DUPLICATE_REJECTED',governanceState:String(h.governance_state),...HOLD
   });
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(!sourceValid||!expected.bmLocallyConsistent||
      !expected.bnLocallyConsistent||
      expected.bmGovernanceState!=='HELD_UNVERIFIED'||
      expected.bnGovernanceState!=='HELD_UNVERIFIED'||
      prior.candidateAuthorityDossierAnomalyCodes.includes(
       'BO_DOSSIER_UPSTREAM_BM_BN_CHANGED'))
   outcome='UPSTREAM_DRIFT_QUARANTINED';
  else if(dossier.revocation.epoch<Number(h.last_claimed_revocation_epoch)||
      dossier.revocation.epoch<expected.bnRevocationEpoch)
   outcome='REVOCATION_REGRESSION_QUARANTINED';
  else if(!review.candidateDossierInternallyConsistent)
   outcome=review.candidateDossierAnomalyCodes.includes(
    'BO_UPSTREAM_BM_BN_HEAD_OR_PINSET_MISMATCH')?
    'UPSTREAM_DRIFT_QUARANTINED':'EVIDENCE_CONFLICT_QUARANTINED';
  else if(latest===0)outcome=version===1&&previousDossierSha256===null?
   GOOD:'GAP_QUARANTINED';
  else if(version<=latest)outcome=version===latest?
   'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(version!==latest+1)outcome='GAP_QUARANTINED';
  else if(previousDossierSha256!==h.last_dossier_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else if(dossier.candidatePinsetSha256!==h.last_pinset_sha256)
   outcome='EVIDENCE_CONFLICT_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO quote_bo_candidate_authority_attempts (quote_id,dossier_version,dossier_sha256,predecessor_sha256,bn_packet_sha256,bm_receipt_sha256,quote_source_sha256,candidate_pinset_sha256,claimed_revocation_epoch,outcome) VALUES (?,?,?,?,?,?,?,?,?,?)',
   [quoteId,version,digest,previousDossierSha256,dossier.bnPacketSha256,
    dossier.bmReceiptSha256,dossier.quoteSourceSha256,
    dossier.candidatePinsetSha256,dossier.revocation.epoch,outcome]);
  if(outcome===GOOD)await conn.execute(
   'UPDATE quote_bo_candidate_authority_streams SET last_version=?,last_dossier_sha256=?,last_bn_packet_sha256=?,last_bm_receipt_sha256=?,last_source_sha256=?,last_pinset_sha256=?,last_claimed_revocation_epoch=? WHERE quote_id=?',
   [version,digest,dossier.bnPacketSha256,dossier.bmReceiptSha256,
    dossier.quoteSourceSha256,dossier.candidatePinsetSha256,
    dossier.revocation.epoch,quoteId]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')await conn.execute(
   "UPDATE quote_bo_candidate_authority_streams SET governance_state='QUARANTINED' WHERE quote_id=?",
   [quoteId]);
  await conn.commit();
  return Object.freeze({outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',...HOLD});
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
