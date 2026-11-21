import type {Pool,RowDataPacket} from 'mysql2/promise';
import {assessPhase1BeRevocationFreeze}
 from '../../scripts/lib/phase1BeRevocationFreeze.mjs';

// Digest-only internal incident register. Only disposable CI and separately
// authorized isolated TLS staging. Not independent revocation, cloud WORM,
// authentic provider trust or an external release/unfreeze implementation.
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const INCIDENT='FROZEN_UNVERIFIED';
export function beFreezeWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BE_FREEZE_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BE freezes only on disposable CI or approved isolated TLS staging');
}
export interface BeFreezeArgs {
 bdEvidence:any;body:any;survivingWitnessSignature:any;
 governanceSignatures:any[];now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BeRevocationFreeze(pool:Pool,{
 bdEvidence,body,survivingWitnessSignature,governanceSignatures,
 now=new Date(),env=process.env
}:BeFreezeArgs){
 beFreezeWriteTarget(env);
 if(Buffer.byteLength(JSON.stringify({bdEvidence,body,survivingWitnessSignature,
     governanceSignatures}),'utf8')>52000)
  throw Error('Phase 1BE oversized candidate freeze evidence');
 const verdict=assessPhase1BeRevocationFreeze({
  bdEvidence,body,survivingWitnessSignature,governanceSignatures,now
 });
 if(!verdict.locallyCoSignedFreezeConsistent||
    typeof verdict.incidentSha256!=='string'||!SHA.test(verdict.incidentSha256)||
    typeof verdict.bdReviewSha256!=='string'||!SHA.test(verdict.bdReviewSha256)||
    typeof verdict.azPacketSha256!=='string'||!SHA.test(verdict.azPacketSha256)||
    typeof body?.logRef!=='string'||!REF.test(body.logRef)||
    typeof body?.revokedWitnessRef!=='string'||!REF.test(body.revokedWitnessRef)||
    typeof body?.revokedKeySpkiSha256!=='string'||!SHA.test(body.revokedKeySpkiSha256))
  throw Error('Phase 1BE refuses inconsistent or unauthenticated freeze claim');
 const logRef=body.logRef;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // Shared lock order: AZ -> BB -> BC -> BD -> BE. A compromised
  // witness freezes the *entire* log, not merely an unsigned key flag.
  const [az]=await conn.execute<RowDataPacket[]>(
   'SELECT last_packet_sha256,governance_state FROM inv_az_readiness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bb]=await conn.execute<RowDataPacket[]>(
   'SELECT governance_state FROM inv_bb_evidence_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bc]=await conn.execute<RowDataPacket[]>(
   'SELECT governance_state FROM inv_bc_witness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bd]=await conn.execute<RowDataPacket[]>(
   'SELECT last_review_sha256,governance_state FROM inv_bd_review_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(az.length!==1||az[0].last_packet_sha256!==verdict.azPacketSha256||
     az[0].governance_state!=='HELD_UNVERIFIED'||
     bb.length!==1||bb[0].governance_state!=='HELD_UNVERIFIED'||
     bc.length!==1||bc[0].governance_state!=='HELD_UNVERIFIED'||
     bd.length!==1||bd[0].last_review_sha256!==verdict.bdReviewSha256||
     bd[0].governance_state!=='HELD_UNVERIFIED')
   throw Error('Phase 1BE missing/changed or quarantined AZ BB BC BD predecessor');
  await conn.execute(
   'INSERT INTO inv_be_freeze_streams(log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',[logRef]);
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(rows.length!==1)throw Error('Phase 1BE missing locked freeze row');
  const h=rows[0],fingerprint=verdict.incidentSha256;
  const [accepted]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_be_freeze_attempts WHERE log_ref=? AND incident_sha256=? AND outcome='FROZEN_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,fingerprint]);
  if(h.state==='FROZEN_UNVERIFIED'&&h.last_incident_sha256===fingerprint&&
     h.frozen_key_spki_sha256===body.revokedKeySpkiSha256&&accepted.length===1){
   await conn.commit();
   return Object.freeze({phase:'1BE',outcome:'REPLAY',state:'FROZEN_UNVERIFIED',
    productionReleaseAuthorized:false,productionReleaseBlocked:true,
    releaseDecision:'HOLD',independentRevocationVerified:false});
  }
  if(h.state==='QUARANTINED'&&h.last_incident_sha256===fingerprint&&accepted.length){
   await conn.commit();
   return Object.freeze({phase:'1BE',outcome:'DUPLICATE_REJECTED',state:'QUARANTINED',
    productionReleaseAuthorized:false,productionReleaseBlocked:true,
    releaseDecision:'HOLD',independentRevocationVerified:false});
  }
  const [known]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_be_freeze_attempts WHERE log_ref=? AND incident_sha256=? AND outcome<>'FROZEN_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,fingerprint]);
  if(known.length){
   await conn.commit();
   return Object.freeze({phase:'1BE',outcome:'DUPLICATE_REJECTED',state:h.state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,
    releaseDecision:'HOLD',independentRevocationVerified:false});
  }
  if(h.state==='HELD_UNVERIFIED'&&
     (h.last_incident_sha256!==null||h.frozen_key_spki_sha256!==null||
      h.frozen_witness_ref!==null||h.last_bd_review_sha256!==null))
   throw Error('Phase 1BE inconsistent candidate freeze genesis');
  let outcome:string;
  if(h.state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(h.state==='FROZEN_UNVERIFIED')outcome='CONFLICT_QUARANTINED';
  else outcome=INCIDENT;
  await conn.execute(
   'INSERT INTO inv_be_freeze_attempts(log_ref,incident_sha256,bd_review_sha256,az_packet_sha256,frozen_witness_ref,frozen_key_spki_sha256,outcome) VALUES (?,?,?,?,?,?,?)',
   [logRef,fingerprint,verdict.bdReviewSha256,verdict.azPacketSha256,
    body.revokedWitnessRef,body.revokedKeySpkiSha256,outcome]);
  if(outcome===INCIDENT){
   await conn.execute(
    "UPDATE inv_be_freeze_streams SET state='FROZEN_UNVERIFIED',last_incident_sha256=?,frozen_witness_ref=?,frozen_key_spki_sha256=?,last_bd_review_sha256=? WHERE log_ref=?",
    [fingerprint,body.revokedWitnessRef,body.revokedKeySpkiSha256,
     verdict.bdReviewSha256,logRef]);
  }else if(outcome==='CONFLICT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_be_freeze_streams SET state='QUARANTINED' WHERE log_ref=?",[logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1BE',outcome,
   state:outcome===INCIDENT?'FROZEN_UNVERIFIED':'QUARANTINED',
   independentRevocationVerified:false,providerWormVerified:false,
   encryptedRecoveryVerified:false,productionReleaseAuthorized:false,
   productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1BeRevocationFreeze(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 beFreezeWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef))
  throw Error('Phase 1BE invalid log reference');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(rows.length!==1)throw Error('Phase 1BE log freeze record not found');
  const [attempts]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_be_freeze_attempts WHERE log_ref=? ORDER BY id FOR UPDATE',[logRef]);
  const h=rows[0],issues:string[]=[];
  const accepted=attempts.filter(x=>x.outcome===INCIDENT);
  const rejected=attempts.filter(x=>x.outcome!==INCIDENT);
  if(accepted.length>1||accepted.length===0&&attempts.length>0)
   issues.push('INVALID_FIRST_FREEZE_HISTORY');
  if(accepted.length===1){
   const first=accepted[0];
   if(h.last_incident_sha256!==first.incident_sha256||
      h.last_bd_review_sha256!==first.bd_review_sha256||
      h.frozen_witness_ref!==first.frozen_witness_ref||
      h.frozen_key_spki_sha256!==first.frozen_key_spki_sha256)
    issues.push('FROZEN_HEAD_HISTORY_MISMATCH');
  }else if(h.last_incident_sha256!==null||h.last_bd_review_sha256!==null||
     h.frozen_witness_ref!==null||h.frozen_key_spki_sha256!==null)
   issues.push('ORPHANED_FROZEN_HEAD');
  for(const row of attempts){
   if(!SHA.test(String(row.incident_sha256))||
      !SHA.test(String(row.bd_review_sha256))||
      !SHA.test(String(row.az_packet_sha256))||
      !SHA.test(String(row.frozen_key_spki_sha256))||
      !REF.test(String(row.frozen_witness_ref)))
    issues.push('MALFORMED_PERSISTED_DIGEST_OR_REFERENCE');
  }
  if((h.state==='FROZEN_UNVERIFIED'&&
       (accepted.length!==1||rejected.length!==0))||
     (h.state==='QUARANTINED'&&
       (accepted.length!==1||rejected.length<1))||
     (h.state==='HELD_UNVERIFIED'&&attempts.length!==0))
   issues.push('FREEZE_AND_QUARANTINE_STATE_CONTRADICTION');
  if(h.independent_witness_authority_authenticated!=='NO'||
     h.independently_published_revocation_verified!=='NO'||
     h.provider_worm_denial_verified!=='NO'||
     h.encrypted_dr_restore_witnessed!=='NO'||h.production_release!=='HOLD')
   issues.push('UNAUTHORIZED_EXTERNAL_REVOCATION_OR_RELEASE_PROMOTION');
  await conn.commit();
  return Object.freeze({phase:'1BE',logRef,state:h.state,
   attempts:attempts.length,revokedWitnessRef:h.frozen_witness_ref,
   locallyConsistentHistory:issues.length===0,
   sourceOfTruthAuthenticated:false,revocationExternallyPublished:false,
   cloudObjectLockVerified:false,encryptedDRWitnessed:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,
   releaseDecision:'HOLD',anomalyCodes:Object.freeze([...new Set(issues)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
