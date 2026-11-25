import type {Pool,RowDataPacket} from 'mysql2/promise';
import {assessPhase1BgEvidenceQuorum}
 from '../../scripts/lib/phase1BgCrossSourceAcceptance.mjs';

// Candidate-only audit quorum history; no external CA/CRL/OCSP, provider
// object lock, KMS, encrypted restore, production approval or unfreeze.
const REF=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const GOOD='RECORDED_UNVERIFIED';
export function bgWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BG_CROSS_SOURCE_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BG audit writes refused outside disposable CI/approved isolated TLS staging');
}
export interface BgReviewArgs{
 publication:any;manifest:any;auditors:any[];
 now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BgCrossSource(pool:Pool,{
 publication,manifest,auditors,now=new Date(),env=process.env
}:BgReviewArgs){
 bgWriteTarget(env);
 if(Buffer.byteLength(JSON.stringify({publication,manifest,auditors}),'utf8')>70000)
  throw Error('Phase 1BG oversized candidate audit packet');
 const verified=assessPhase1BgEvidenceQuorum({publication,manifest,auditors,now});
 if(!verified.locallyConsistentAuditQuorum||
    typeof manifest?.logRef!=='string'||!REF.test(manifest.logRef)||
    typeof verified.reviewSha256!=='string'||!SHA.test(verified.reviewSha256)||
    typeof verified.previousPublicationSha256!=='string'||!SHA.test(verified.previousPublicationSha256)||
    typeof verified.auditorPinSetSha256!=='string'||!SHA.test(verified.auditorPinSetSha256))
  throw Error('Phase 1BG invalid or unbound three-source candidate audit');
 const logRef=manifest.logRef,revision=manifest.reviewRevision;
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // BE -> BF -> BG lock ordering: freeze cannot be cleared by source review.
  const [freeze]=await conn.execute<RowDataPacket[]>(
   'SELECT state,last_incident_sha256 FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',
   [logRef]);
  if(freeze.length!==1||freeze[0].state!=='FROZEN_UNVERIFIED'||
     freeze[0].last_incident_sha256!==manifest.freezeIncidentSha256)
   throw Error('Phase 1BG missing, changed or quarantined BE freeze');
  const [bf]=await conn.execute<RowDataPacket[]>(
   'SELECT last_publication_sha256,last_sequence,last_publisher_spki_sha256,governance_state FROM inv_bf_publication_streams WHERE log_ref=? FOR UPDATE',
   [logRef]);
  if(bf.length!==1||bf[0].governance_state!=='HELD_UNVERIFIED'||
     bf[0].last_publication_sha256!==verified.previousPublicationSha256||
     Number(bf[0].last_sequence)!==manifest.publicationSequence||
     bf[0].last_publisher_spki_sha256!==manifest.publisherPinSha256)
   throw Error('Phase 1BG missing or quarantined BF publication source');
  await conn.execute(
   'INSERT INTO inv_bg_cross_source_streams(log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',[logRef]);
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bg_cross_source_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const h=rows[0],last=Number(h?.last_revision),current=verified.reviewSha256;
  if(!h||!Number.isSafeInteger(last)||last<0||
     (last===0&&(h.last_review_sha256!==null||
      h.last_publication_sha256!==null||h.last_auditor_pinset_sha256!==null)))
   throw Error('Phase 1BG corrupt candidate audit stream head');
  const [accepted]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bg_cross_source_attempts WHERE log_ref=? AND review_sha256=? AND outcome='RECORDED_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,current]);
  if(h.governance_state==='HELD_UNVERIFIED'&&revision===last&&
    h.last_review_sha256===current&&accepted.length===1){
   await conn.commit();
   return Object.freeze({phase:'1BG',outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',externallyAuthenticatedIssuer:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,
    releaseDecision:'HOLD'});
  }
  const [duplicateIncident]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bg_cross_source_attempts WHERE log_ref=? AND review_sha256=? AND outcome<>'RECORDED_UNVERIFIED' LIMIT 1 FOR UPDATE",
   [logRef,current]);
  if(duplicateIncident.length||
    (h.governance_state==='QUARANTINED'&&accepted.length)){
   await conn.commit();
   return Object.freeze({phase:'1BG',outcome:'DUPLICATE_REJECTED',
    governanceState:h.governance_state,externallyAuthenticatedIssuer:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,
    releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(h.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(last===0)
   outcome=revision===1&&manifest.previousReviewSha256===null?
    GOOD:'GAP_QUARANTINED';
  else if(revision<=last)
   outcome=revision===last?'FORK_QUARANTINED':'ROLLBACK_QUARANTINED';
  else if(revision!==last+1)outcome='GAP_QUARANTINED';
  else if(manifest.previousReviewSha256!==h.last_review_sha256)
   outcome='PREDECESSOR_MISMATCH_QUARANTINED';
  else if(h.last_publisher_pin_sha256!==manifest.publisherPinSha256)
   outcome='PUBLISHER_PIN_CHANGE_QUARANTINED';
  else if(h.last_auditor_pinset_sha256!==verified.auditorPinSetSha256)
   outcome='AUDITOR_PINSET_CHANGE_QUARANTINED';
  else if(manifest.crlNumber<Number(h.last_crl_number)||
     Date.parse(manifest.crlThisUpdate)<Number(h.last_crl_this_update_ms))
   outcome='CRL_REGRESSION_QUARANTINED';
  else outcome=GOOD;
  await conn.execute(
   'INSERT INTO inv_bg_cross_source_attempts(log_ref,review_revision,review_sha256,previous_review_sha256,publication_sha256,publisher_pin_sha256,auditor_pinset_sha256,crl_number,crl_this_update_ms,outcome) VALUES (?,?,?,?,?,?,?,?,?,?)',
   [logRef,revision,current,manifest.previousReviewSha256,
    verified.previousPublicationSha256,manifest.publisherPinSha256,
    verified.auditorPinSetSha256,manifest.crlNumber,Date.parse(manifest.crlThisUpdate),
    outcome]);
  if(outcome===GOOD)
   await conn.execute(
    'UPDATE inv_bg_cross_source_streams SET last_revision=?,last_review_sha256=?,last_publication_sha256=?,last_auditor_pinset_sha256=?,last_publisher_pin_sha256=?,last_crl_number=?,last_crl_this_update_ms=? WHERE log_ref=?',
    [revision,current,verified.previousPublicationSha256,
     verified.auditorPinSetSha256,manifest.publisherPinSha256,
     manifest.crlNumber,Date.parse(manifest.crlThisUpdate),logRef]);
  else if(outcome!=='POST_INCIDENT_QUARANTINED')
   await conn.execute(
    "UPDATE inv_bg_cross_source_streams SET governance_state='QUARANTINED' WHERE log_ref=?",
    [logRef]);
  await conn.commit();
  return Object.freeze({phase:'1BG',outcome,
   governanceState:outcome===GOOD?'HELD_UNVERIFIED':'QUARANTINED',
   candidateAuditOnly:true,externallyAuthenticatedIssuer:false,
   independentlyAuthenticatedAuditors:false,actualWormVerified:false,
   actualEncryptedRestoreWitnessed:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1BgCrossSource(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 bgWriteTarget(env);
 if(typeof logRef!=='string'||!REF.test(logRef))throw Error('Phase 1BG invalid log');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [freeze]=await conn.execute<RowDataPacket[]>(
   'SELECT state FROM inv_be_freeze_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [bf]=await conn.execute<RowDataPacket[]>(
   'SELECT governance_state,last_publication_sha256,last_publisher_spki_sha256 FROM inv_bf_publication_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const [headRows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bg_cross_source_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(headRows.length!==1)throw Error('Phase 1BG audit stream absent');
  const [attempts]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bg_cross_source_attempts WHERE log_ref=? ORDER BY id FOR UPDATE',[logRef]);
  const head=headRows[0],problems:string[]=[];
  let revision=0,lastSha:null|string=null,publication:null|string=null,
   publisher:null|string=null,auditors:null|string=null,
   crl=0,crlTime=0,incident=false;
  for(const row of attempts){
   for(const k of ['review_sha256','publication_sha256','auditor_pinset_sha256','publisher_pin_sha256'])
    if(!SHA.test(String(row[k])))problems.push('INVALID_AUDIT_HASH');
   if(row.previous_review_sha256!==null&&!SHA.test(String(row.previous_review_sha256)))
    problems.push('INVALID_PREDECESSOR_HASH');
   const n=Number(row.review_revision),number=Number(row.crl_number),
    updated=Number(row.crl_this_update_ms);
   if(!Number.isSafeInteger(n)||n<1||
     !Number.isSafeInteger(number)||number<1||
     !Number.isSafeInteger(updated)||updated<1)
    problems.push('INVALID_CRYPTOGRAPHIC_AUDIT_SEQUENCE');
   if(row.outcome===GOOD){
    if(incident||n!==revision+1||row.previous_review_sha256!==lastSha||
      (revision>0&&(row.publisher_pin_sha256!==publisher||
       row.auditor_pinset_sha256!==auditors||
       number<crl||updated<crlTime)))
     problems.push('BROKEN_ACCEPTED_CRL_AUDIT_HISTORY');
    revision=n;lastSha=row.review_sha256;publication=row.publication_sha256;
    publisher=row.publisher_pin_sha256;auditors=row.auditor_pinset_sha256;
    crl=number;crlTime=updated;
   }else incident=true;
  }
  if(Number(head.last_revision)!==revision||head.last_review_sha256!==lastSha||
    head.last_publication_sha256!==publication||
    head.last_auditor_pinset_sha256!==auditors||
    head.last_publisher_pin_sha256!==publisher||
    Number(head.last_crl_number)!==crl||
    Number(head.last_crl_this_update_ms)!==crlTime)
   problems.push('AUDIT_HEAD_HISTORY_DIVERGENCE');
  if((head.governance_state==='QUARANTINED')!==incident)
   problems.push('AUDIT_QUARANTINE_STATE_MISMATCH');
  if(freeze.length!==1||freeze[0].state!=='FROZEN_UNVERIFIED'||
    bf.length!==1||bf[0].governance_state!=='HELD_UNVERIFIED'||
    (revision>0&&(bf[0].last_publication_sha256!==publication||
       bf[0].last_publisher_spki_sha256!==publisher)))
   problems.push('SOURCE_PUBLICATION_OR_FREEZE_CHANGED');
  for(const k of ['independently_authenticated_issuer','trusted_live_crl_ocsp',
    'independently_pinned_auditors','externally_enforced_object_lock','real_encrypted_dr_witnessed'])
   if(head[k]!=='NO')problems.push('ILLICIT_EXTERNAL_TRUST_PROMOTION');
  if(head.production_release!=='HOLD')problems.push('ILLICIT_PRODUCTION_RELEASE');
  await conn.commit();
  return Object.freeze({phase:'1BG',logRef,
   lastCandidateReviewRevision:revision,attempts:attempts.length,
   governanceState:head.governance_state,
   localAuditHistoryConsistent:problems.length===0,
   verifiedCrlOcspAuthority:false,independentlyPinnedAuditors:false,
   actualWormVerified:false,actuallyWitnessedEncryptedDr:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD',
   anomalyCodes:Object.freeze([...new Set(problems)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
