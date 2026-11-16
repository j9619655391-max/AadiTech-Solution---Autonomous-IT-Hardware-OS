import type {Pool,RowDataPacket} from 'mysql2/promise';
import {assessPhase1BfPublication}
 from '../../scripts/lib/phase1BfRevocationPublication.mjs';

// Phase 1BF: isolated CI/staging, digest-only revocation publication claims.
// No actual authenticated revocation, external issuer enrollment, WORM, DR,
// production release or unfreeze API; privileged DB admins can modify records.
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const RECORDED='RECORDED_UNVERIFIED';
export function bfPublicationWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BF_PUBLICATION_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BF writes only allowed in disposable CI or approved TLS isolated staging');
}
export interface BfPublicationArgs {
 freezeEvidence:any;body:any;publisher:any;survivingWitness:any;
 securityReviewer:any;now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BfPublication(pool:Pool,{
 freezeEvidence,body,publisher,survivingWitness,securityReviewer,
 now=new Date(),env=process.env
}:BfPublicationArgs){
 bfPublicationWriteTarget(env);
 if(Buffer.byteLength(JSON.stringify({
  freezeEvidence,body,publisher,survivingWitness,securityReviewer
 }),'utf8')>56000)throw Error('Phase 1BF overlarge candidate publication packet');
 const verdict=assessPhase1BfPublication({
  freezeEvidence,body,publisher,survivingWitness,securityReviewer,now
 });
 if(!verdict.locallySignedPublicationConsistent||
    typeof body?.logRef!=='string'||!REF.test(body.logRef)||
    typeof verdict.publicationSha256!=='string'||!SHA.test(verdict.publicationSha256)||
    typeof verdict.freezeIncidentSha256!=='string'||!SHA.test(verdict.freezeIncidentSha256)||
    typeof body.publisherPublicKeySha256!=='string'||!SHA.test(body.publisherPublicKeySha256))
  throw Error('Phase 1BF refuses invalid or unauthenticated publication claim');
 const ref=body.logRef,sha=verdict.publicationSha256,seq=body.publicationSequence;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // BE -> BF lock order; BE cannot be un-frozen by a publication.
  const [upstream]=await conn.execute<RowDataPacket[]>(
   'SELECT state,last_incident_sha256,last_bd_review_sha256,frozen_witness_ref,frozen_key_spki_sha256 FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[ref]);
  if(upstream.length!==1||upstream[0].state!=='FROZEN_UNVERIFIED'||
     upstream[0].last_incident_sha256!==verdict.freezeIncidentSha256||
     upstream[0].last_bd_review_sha256!==body.bdReviewSha256||
     upstream[0].frozen_witness_ref!==body.revokedWitnessRef||
     upstream[0].frozen_key_spki_sha256!==body.revokedKeySpkiSha256)
   throw Error('Phase 1BF missing, quarantined or altered emergency freeze predecessor');
  await conn.execute('INSERT INTO inv_bf_publication_streams(log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',[ref]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bf_publication_streams WHERE log_ref=? FOR UPDATE',[ref]);
  const head=heads[0],last=Number(head?.last_sequence);
  if(!head||!Number.isSafeInteger(last)||last<0||
     (last===0&&head.last_publication_sha256!==null))
   throw Error('Phase 1BF malformed candidate publication head');
  const [accepted]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bf_publication_attempts WHERE log_ref=? AND publication_sha256=? AND outcome='RECORDED_UNVERIFIED' LIMIT 1 FOR UPDATE",[ref,sha]);
  if(head.governance_state==='HELD_UNVERIFIED'&&last===seq&&
     head.last_publication_sha256===sha&&accepted.length===1){
   await conn.commit();
   return Object.freeze({phase:'1BF',outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',independentRevocationVerified:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  const [oldIncident]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bf_publication_attempts WHERE log_ref=? AND publication_sha256=? AND outcome<>'RECORDED_UNVERIFIED' LIMIT 1 FOR UPDATE",[ref,sha]);
  if(oldIncident.length||head.governance_state==='QUARANTINED'&&accepted.length){
   await conn.commit();
   return Object.freeze({phase:'1BF',outcome:'DUPLICATE_REJECTED',
    governanceState:head.governance_state,independentRevocationVerified:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(head.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(last===0)outcome=seq===1&&body.previousPublicationSha256===null?
   RECORDED:'GAP_QUARANTINED';
  else if(head.last_freeze_incident_sha256!==verdict.freezeIncidentSha256)
   outcome='UPSTREAM_FREEZE_CHANGED_QUARANTINED';
  else if(seq<=last)outcome=seq===last?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(seq!==last+1)outcome='GAP_QUARANTINED';
  else if(head.last_publisher_spki_sha256!==body.publisherPublicKeySha256)
   outcome='ISSUER_KEY_CHANGE_QUARANTINED';
  else if(body.previousPublicationSha256!==head.last_publication_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else outcome=RECORDED;
  await conn.execute(
   'INSERT INTO inv_bf_publication_attempts(log_ref,publication_sequence,publication_sha256,previous_publication_sha256,freeze_incident_sha256,publisher_spki_sha256,outcome) VALUES (?,?,?,?,?,?,?)',
   [ref,seq,sha,body.previousPublicationSha256,verdict.freezeIncidentSha256,
    body.publisherPublicKeySha256,outcome]);
  if(outcome===RECORDED){
   await conn.execute(
    'UPDATE inv_bf_publication_streams SET last_sequence=?,last_publication_sha256=?,last_freeze_incident_sha256=?,last_publisher_spki_sha256=? WHERE log_ref=?',
    [seq,sha,verdict.freezeIncidentSha256,body.publisherPublicKeySha256,ref]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_bf_publication_streams SET governance_state='QUARANTINED' WHERE log_ref=?",[ref]);
  }
  await conn.commit();
  return Object.freeze({phase:'1BF',outcome,
   governanceState:outcome===RECORDED?'HELD_UNVERIFIED':'QUARANTINED',
   candidateEvidenceOnly:true,independentRevocationVerified:false,
   actualObjectLockVerified:false,actualEncryptedDrVerified:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1BfPublication(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 bfPublicationWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef))
  throw Error('Phase 1BF invalid log');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // Preserve writer/readback lock order: BE upstream then BF stream.
  const [upstream]=await conn.execute<RowDataPacket[]>(
   'SELECT state,last_incident_sha256 FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bf_publication_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(heads.length!==1)throw Error('Phase 1BF publication stream missing');
  const [attempts]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bf_publication_attempts WHERE log_ref=? ORDER BY id FOR UPDATE',[logRef]);
  const problems:string[]=[],head=heads[0];
  let seq=0,lastSha:null|string=null,incident:null|string=null,
   publisher:null|string=null,quarantine=false;
  for(const attempt of attempts){
   for(const name of ['publication_sha256','freeze_incident_sha256','publisher_spki_sha256'])
    if(!SHA.test(String(attempt[name])))problems.push('INVALID_PERSISTED_PUBLICATION_HASH');
   if(attempt.previous_publication_sha256!==null&&
      !SHA.test(String(attempt.previous_publication_sha256)))
    problems.push('INVALID_PERSISTED_PREDECESSOR');
   const next=Number(attempt.publication_sequence);
   if(!Number.isSafeInteger(next)||next<1)problems.push('INVALID_PUBLICATION_SEQUENCE');
   if(attempt.outcome===RECORDED){
    if(quarantine||next!==seq+1||
       attempt.previous_publication_sha256!==lastSha||
       (seq!==0&&(attempt.publisher_spki_sha256!==publisher||
                    attempt.freeze_incident_sha256!==incident)))
     problems.push('BROKEN_ACCEPTED_PUBLICATION_CHAIN');
    seq=next;lastSha=attempt.publication_sha256;
    incident=attempt.freeze_incident_sha256;
    publisher=attempt.publisher_spki_sha256;
   }else quarantine=true;
  }
  if(Number(head.last_sequence)!==seq||head.last_publication_sha256!==lastSha||
     head.last_freeze_incident_sha256!==incident||
     head.last_publisher_spki_sha256!==publisher)
   problems.push('PUBLICATION_HEAD_HISTORY_DIVERGENCE');
  if((head.governance_state==='QUARANTINED')!==quarantine)
   problems.push('PUBLICATION_QUARANTINE_MISMATCH');
  for(const name of ['independent_issuer_authenticated','active_crl_ocsp_independently_verified',
   'revoked_key_externally_confirmed','object_lock_provider_verified',
   'encrypted_dr_witnessed'])
   if(head[name]!=='NO')problems.push('UNAUTHORIZED_EXTERNAL_TRUST_PROMOTION');
  if(head.production_release!=='HOLD')
   problems.push('UNAUTHORIZED_PUBLICATION_RELEASE');
  if(upstream.length!==1||upstream[0].state==='HELD_UNVERIFIED'||
     upstream[0].last_incident_sha256!==incident)
   problems.push('BE_FREEZE_PREDECESSOR_DIVERGENCE');
  await conn.commit();
  return Object.freeze({phase:'1BF',logRef,
   governanceState:head.governance_state,attempts:attempts.length,
   lastCandidatePublicationSequence:seq,
   localDigestHistoryConsistent:problems.length===0,
   issuerIndependentlyAuthenticated:false,
   actualRevocationExternallyVerified:false,
   genuineWormRetentionVerified:false,encryptedDRIndependentlyWitnessed:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,
   releaseDecision:'HOLD',
   anomalyCodes:Object.freeze([...new Set(problems)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
