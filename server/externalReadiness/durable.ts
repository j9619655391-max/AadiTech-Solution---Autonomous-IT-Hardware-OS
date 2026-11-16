import type {Pool,RowDataPacket} from 'mysql2/promise';
import {phase1AzAssessReadiness} from '../../scripts/lib/phase1AzExternalReadiness.mjs';

// Internal, digest-only evidence storage. No provider/private credentials,
// external object store, signed approval, release or production endpoint.
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
export function azReadinessWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test')return 'ci';
 if(env.AZ_READINESS_WRITE_APPROVED==='YES'&&env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
   /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??'')&&env.DB_SSL==='true'&&
   env.NODE_ENV!=='production')return 'staging';
 throw Error('1AZ evidence write denied outside disposable CI/approved isolated TLS staging');
}
export interface AzReadinessArgs {
 logRef:string;packet:any;now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1AzReadiness(pool:Pool,{
 logRef,packet,now=new Date(),env=process.env
}:AzReadinessArgs){
 azReadinessWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef)||packet?.archive?.logRef!==logRef)
  throw Error('1AZ log identity does not match archive packet');
 if(Buffer.byteLength(JSON.stringify(packet),'utf8')>16384)
  throw Error('1AZ bounded digest evidence packet exceeded');
 const assessment=phase1AzAssessReadiness(packet,{now});
 if(!assessment.packetInspected||typeof assessment.packetSha256!=='string')
  throw Error('1AZ missing digest readiness packet');
 const digest=assessment.packetSha256;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  await conn.execute(
   'INSERT INTO inv_az_readiness_streams (log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',
   [logRef]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT last_revision,last_packet_sha256,governance_state FROM inv_az_readiness_streams WHERE log_ref=? FOR UPDATE',
   [logRef]);
  const head=heads[0];
  if(!head)throw Error('1AZ missing locked history');
  const revision=Number(head.last_revision);
  if(!Number.isSafeInteger(revision)||revision<0)throw Error('1AZ invalid last revision');
  const current=head.last_packet_sha256 as string|null;
  if(revision===packet.revision&&current===digest){
   await conn.commit();
   return Object.freeze({phase:'1AZ',outcome:'REPLAY',governanceState:head.governance_state,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  // Repeated rejected evidence is idempotent. An already accepted historical
  // digest still produces a *first* rollback incident when replayed after a
  // newer head, but duplicates of that incident must not grow the ledger.
  const [recordedIncidents]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_az_readiness_packets WHERE log_ref=? AND packet_sha256=? AND outcome<>'RECORDED_UNTRUSTED' LIMIT 1 FOR UPDATE",
   [logRef,digest]);
  if(recordedIncidents.length){
   await conn.commit();
   return Object.freeze({phase:'1AZ',outcome:'DUPLICATE_REJECTED',
    governanceState:head.governance_state,productionReleaseAuthorized:false,
    productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(head.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(!assessment.internalEvidenceConsistent)outcome='INVALID_CLAIM_QUARANTINED';
  else if(revision===0)
   outcome=packet.revision===1&&packet.previousPacketSha256===null?'RECORDED_UNTRUSTED':'GAP_QUARANTINED';
  else if(packet.revision<=revision)
   outcome=packet.revision===revision?'CONFLICT_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(packet.revision!==revision+1)outcome='GAP_QUARANTINED';
  else if(packet.previousPacketSha256!==current)outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome='RECORDED_UNTRUSTED';
  const [priorAttempts]=await conn.execute<RowDataPacket[]>(
   'SELECT id FROM inv_az_readiness_packets WHERE log_ref=? AND packet_sha256=? AND outcome=? LIMIT 1 FOR UPDATE',
   [logRef,digest,outcome]);
  if(priorAttempts.length){
   await conn.commit();
   return Object.freeze({phase:'1AZ',outcome:'DUPLICATE_REJECTED',
    governanceState:head.governance_state,productionReleaseAuthorized:false,
    productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  await conn.execute(
   'INSERT INTO inv_az_readiness_packets (log_ref,revision,packet_sha256,previous_packet_sha256,internal_evidence_consistent,outcome) VALUES (?,?,?,?,?,?)',
   [logRef,packet.revision,digest,packet.previousPacketSha256,
     assessment.internalEvidenceConsistent?1:0,outcome]);
  if(outcome==='RECORDED_UNTRUSTED'){
   await conn.execute(
    'UPDATE inv_az_readiness_streams SET last_revision=?,last_packet_sha256=? WHERE log_ref=?',
    [packet.revision,digest,logRef]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_az_readiness_streams SET governance_state='QUARANTINED' WHERE log_ref=?",[logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1AZ',outcome,
   governanceState:outcome==='RECORDED_UNTRUSTED'?head.governance_state:'QUARANTINED',
   selfReportedReadinessOnly:true,externallyAuthenticated:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1AzReadiness(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 azReadinessWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef))throw Error('Invalid 1AZ log');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_az_readiness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(heads.length!==1)throw Error('1AZ log not found');
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_az_readiness_packets WHERE log_ref=? ORDER BY id FOR UPDATE',[logRef]);
  const anomalies:string[]=[];
  let lastRevision=0,lastDigest:string|null=null,hasIncident=false;
  for(const row of rows){
   if(!SHA.test(String(row.packet_sha256))||
      (row.previous_packet_sha256!==null&&!SHA.test(String(row.previous_packet_sha256))))
    anomalies.push('INVALID_PERSISTED_DIGEST');
   if(row.outcome==='RECORDED_UNTRUSTED'){
    if(Number(row.revision)!==lastRevision+1||row.previous_packet_sha256!==lastDigest||
       Number(row.internal_evidence_consistent)!==1)
     anomalies.push('BROKEN_ACCEPTED_CHAIN');
    lastRevision=Number(row.revision);lastDigest=row.packet_sha256;
   }else hasIncident=true;
  }
  if(Number(heads[0].last_revision)!==lastRevision||
     heads[0].last_packet_sha256!==lastDigest)anomalies.push('HEAD_MISMATCH');
  if((heads[0].governance_state==='QUARANTINED')!==hasIncident)
   anomalies.push('INCIDENT_QUARANTINE_MISMATCH');
  if(heads[0].external_witnesses_authenticated!=='NO'||
     heads[0].immutable_storage_verified!=='NO'||
     heads[0].real_dr_restore_verified!=='NO'||heads[0].production_release!=='HOLD')
   anomalies.push('ILLEGAL_EXTERNAL_TRUST_PROMOTION');
  await conn.commit();
  return Object.freeze({phase:'1AZ',logRef,latestRevision:lastRevision,
   recordedAttempts:rows.length,governanceState:heads[0].governance_state,
   localDigestHistoryConsistent:anomalies.length===0,
   evidenceContentsIndependentlyReverified:false,
   immutableExternalArchiveVerified:false,independentWitnessAuthorityVerified:false,
   realEncryptedRestoreVerified:false,productionReleaseAuthorized:false,
   productionReleaseBlocked:true,releaseDecision:'HOLD',
   anomalyCodes:Object.freeze([...new Set(anomalies)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
