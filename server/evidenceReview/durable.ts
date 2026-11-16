import {createHash} from 'node:crypto';
import type {Pool,RowDataPacket} from 'mysql2/promise';
import {phase1AzAssessReadiness} from '../../scripts/lib/phase1AzExternalReadiness.mjs';
import {assessPhase1BbEvidenceIntake} from '../../scripts/lib/phase1BbEvidenceIntake.mjs';
import {assessPhase1BdEvidenceReview} from '../../scripts/lib/phase1BdEvidenceReview.mjs';

// Internal digest-only evidence history: NOT WORM, externally authenticated,
// immutable, genuine recovery proof, or a production authority.
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const ALLOWED='RECORDED_UNVERIFIED';
export function bdWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
   env.BD_EVIDENCE_WRITE_APPROVED==='YES'&&
   env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
   /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))return 'staging';
 throw Error('Phase 1BD reviews only on disposable CI or approved isolated TLS staging');
}
function pinset(witnesses:any[]){
 const values=witnesses.map(w=>[w.witnessRef,w.organizationRef,
  w.administrativeAuthorityRef,w.publicKeySpkiSha256])
  .sort((a,b)=>a[0].localeCompare(b[0]));
 return createHash('sha256').update('AADITECH-PHASE-1BC-OBSERVED-CUSTODY-V1\0')
  .update(JSON.stringify(['WITNESS_PIN_CANDIDATES',values])).digest('hex');
}
export interface BdReviewArgs{
 azPacket:any;bbRecords:any[];witnessEnrollments:any[];
 storageReceipt:any;recoveryAttestations:any[];
 revision:number;previousReviewSha256:string|null;
 now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BdEvidenceReview(pool:Pool,{
 azPacket,bbRecords,witnessEnrollments,storageReceipt,recoveryAttestations,
 revision,previousReviewSha256,now=new Date(),env=process.env
}:BdReviewArgs){
 bdWriteTarget(env);
 if(!Number.isSafeInteger(revision)||revision<1||revision>1000000||
   (previousReviewSha256!==null&&
    (typeof previousReviewSha256!=='string'||!SHA.test(previousReviewSha256))))
  throw Error('Phase 1BD invalid revision or predecessor');
 const verdict=assessPhase1BdEvidenceReview({
  azPacket,bbRecords,witnessEnrollments,storageReceipt,recoveryAttestations,now
 });
 if(!verdict.offlineEvidenceConsistent||
    typeof verdict.reviewDigestSha256!=='string'||!SHA.test(verdict.reviewDigestSha256))
  throw Error('Phase 1BD inconsistent candidate evidence refused');
 const logRef=azPacket?.archive?.logRef;
 if(typeof logRef!=='string'||!REF.test(logRef))throw Error('Phase 1BD invalid log');
 const az=phase1AzAssessReadiness(azPacket,{now});
 const bb=assessPhase1BbEvidenceIntake({azPacket,records:bbRecords,now});
 if(!az.internalEvidenceConsistent||!bb.internalEvidenceConsistent||
    typeof az.packetSha256!=='string'||typeof bb.batchSha256!=='string')
  throw Error('Phase 1BD predecessor evidence invalid');
 const digest=verdict.reviewDigestSha256;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [azRows]=await conn.execute<RowDataPacket[]>(
   'SELECT last_packet_sha256,governance_state FROM inv_az_readiness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bbRows]=await conn.execute<RowDataPacket[]>(
   'SELECT last_batch_sha256,governance_state FROM inv_bb_evidence_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bcRows]=await conn.execute<RowDataPacket[]>(
   'SELECT last_tree_size,last_az_packet_sha256,last_witness_pinset_sha256,governance_state FROM inv_bc_witness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(azRows.length!==1||azRows[0].last_packet_sha256!==az.packetSha256||
     azRows[0].governance_state!=='HELD_UNVERIFIED'||
     bbRows.length!==1||bbRows[0].last_batch_sha256!==bb.batchSha256||
     bbRows[0].governance_state!=='HELD_UNVERIFIED'||
     bcRows.length!==1||bcRows[0].last_az_packet_sha256!==az.packetSha256||
     bcRows[0].last_witness_pinset_sha256!==pinset(azPacket.witnesses)||
     Number(bcRows[0].last_tree_size)<1||
     bcRows[0].governance_state!=='HELD_UNVERIFIED')
   throw Error('Phase 1BD missing or quarantined AZ/BB/BC predecessor');
  await conn.execute(
   'INSERT INTO inv_bd_review_streams(log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',[logRef]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bd_review_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const h=heads[0],last=Number(h?.last_revision);
  if(!h||!Number.isSafeInteger(last)||last<0)throw Error('Phase 1BD invalid head');
  if(last===revision&&h.last_review_sha256===digest){
   await conn.commit();
   return Object.freeze({phase:'1BD',outcome:'REPLAY',governanceState:h.governance_state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  const [incidents]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bd_review_attempts WHERE log_ref=? AND review_sha256=? AND outcome<>'RECORDED_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,digest]);
  if(incidents.length){
   await conn.commit();
   return Object.freeze({phase:'1BD',outcome:'DUPLICATE_REJECTED',governanceState:h.governance_state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(last===0)outcome=revision===1&&previousReviewSha256===null?
    ALLOWED:'GAP_QUARANTINED';
  else if(h.last_az_packet_sha256!==az.packetSha256||
     h.last_bb_batch_sha256!==bb.batchSha256)
   outcome='UPSTREAM_CHANGED_QUARANTINED';
  else if(revision<=last)outcome=revision===last?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(revision!==last+1)outcome='GAP_QUARANTINED';
  else if(previousReviewSha256!==h.last_review_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=ALLOWED;
  await conn.execute(
   'INSERT INTO inv_bd_review_attempts(log_ref,revision_number,review_sha256,previous_review_sha256,az_packet_sha256,bb_batch_sha256,outcome) VALUES (?,?,?,?,?,?,?)',
   [logRef,revision,digest,previousReviewSha256,az.packetSha256,bb.batchSha256,outcome]);
  if(outcome===ALLOWED){
   await conn.execute(
    'UPDATE inv_bd_review_streams SET last_revision=?,last_review_sha256=?,last_az_packet_sha256=?,last_bb_batch_sha256=? WHERE log_ref=?',
    [revision,digest,az.packetSha256,bb.batchSha256,logRef]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_bd_review_streams SET governance_state='QUARANTINED' WHERE log_ref=?",[logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1BD',outcome,governanceState:outcome===ALLOWED?
   h.governance_state:'QUARANTINED',
   independentExternalAuthorityAuthenticated:false,actualObjectLockVerified:false,
   actualEncryptedRestoreVerified:false,productionReleaseAuthorized:false,
   productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1BdEvidenceReview(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 bdWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef))throw Error('Phase 1BD invalid log');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bd_review_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(heads.length!==1)throw Error('Phase 1BD stream not found');
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bd_review_attempts WHERE log_ref=? ORDER BY id FOR UPDATE',[logRef]);
  const anomalies:string[]=[];
  let rev=0,prior:string|null=null,az:string|null=null,bb:string|null=null,incident=false;
  for(const row of rows){
   for(const field of ['review_sha256','az_packet_sha256','bb_batch_sha256'])
    if(!SHA.test(String(row[field])))anomalies.push('INVALID_PERSISTED_DIGEST');
   if(row.previous_review_sha256!==null&&!SHA.test(String(row.previous_review_sha256)))
    anomalies.push('INVALID_PREDECESSOR_DIGEST');
   if(row.outcome===ALLOWED){
    if(Number(row.revision_number)!==rev+1||row.previous_review_sha256!==prior)
     anomalies.push('BROKEN_ACCEPTED_CHAIN');
    if(rev>0&&(row.az_packet_sha256!==az||row.bb_batch_sha256!==bb))
     anomalies.push('UPSTREAM_CHANGE_ACCEPTED');
    rev=Number(row.revision_number);prior=row.review_sha256;
    az=row.az_packet_sha256;bb=row.bb_batch_sha256;
   }else incident=true;
  }
  const h=heads[0];
  if(Number(h.last_revision)!==rev||h.last_review_sha256!==prior||
     h.last_az_packet_sha256!==az||h.last_bb_batch_sha256!==bb)
   anomalies.push('REVIEW_HEAD_MISMATCH');
  if((h.governance_state==='QUARANTINED')!==incident)
   anomalies.push('QUARANTINE_STATE_MISMATCH');
  if(h.independent_authority_verified!=='NO'||h.object_lock_provider_verified!=='NO'||
     h.encrypted_dr_witnessed!=='NO'||h.production_release!=='HOLD')
   anomalies.push('UNAUTHORIZED_EXTERNAL_TRUST_PROMOTION');
  await conn.commit();
  return Object.freeze({phase:'1BD',logRef,latestRevision:rev,recordedAttempts:rows.length,
   governanceState:h.governance_state,
   localReviewDigestHistoryConsistent:anomalies.length===0,
   evidenceContentsIndependentlyReverified:false,
   externallyAuthenticatedAuthority:false,actualWormVerified:false,
   realEncryptedDRVerified:false,productionReleaseAuthorized:false,
   productionReleaseBlocked:true,releaseDecision:'HOLD',
   anomalyCodes:Object.freeze([...new Set(anomalies)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
