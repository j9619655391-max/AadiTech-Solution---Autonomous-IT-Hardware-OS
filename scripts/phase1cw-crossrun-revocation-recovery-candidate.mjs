import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {assessDetachedCandidate,canonical}
 from './phase1cv-policy-freeze-detached-candidate.mjs';

// Phase 1CW: OFFLINE candidate-only independently-signed checkpoint,
// revocation, two-witness anti-equivocation & recovery proof preflight.
// All inputs (including public-key pins and prior high-watermark) are supplied
// by an operator and NOT independently enrolled/retrieved or externally CAS'd.
// Four extra mathematical signatures and a good candidate do NOT grant GO.
export const ROLES=Object.freeze([
 'SECURITY_WITNESS','BUSINESS_WITNESS','REVOCATION_AUTHORITY',
 'CHECKPOINT_WITNESS_A','CHECKPOINT_WITNESS_B','RECOVERY_AUDITOR'
]);
export const EXTERNAL_ROLES=Object.freeze(ROLES.slice(2));
const SHA=/^[0-9a-f]{40}$/,HEX=/^[0-9a-f]{64}$/,
 B64=/^[A-Za-z0-9+/]{86}==$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 HOST=/^[a-z0-9](?:[a-z0-9.-]{1,110}[a-z0-9])\.[a-z]{2,15}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>own(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const positive=x=>Number.isSafeInteger(x)&&x>0;
const digest=x=>createHash('sha256').update(x).digest('hex');
const date=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
};
const stampOk=(issued,expires,now)=>{
 const i=date(issued),e=date(expires);
 return Number.isFinite(i)&&Number.isFinite(e)&&Number.isFinite(now)&&
  i>=now-900000&&i<=now+300000&&e>now&&e>i&&e-i<=900000;
};
export function claimSigningBytes(kind,statement){
 if(!['checkpoint','revocation','observation','recovery'].includes(kind)||
    !own(statement)||JSON.stringify(statement).length>8192)
  throw Error('CW_UNSUPPORTED_KIND_OR_OVERSIZE_CANDIDATE_CLAIM');
 return Buffer.from('aaditech/phase1cw/'+kind+'/v1\n'+canonical(statement),'utf8');
}
function evidenceSha(kind,statement){
 try{return digest(claimSigningBytes(kind,statement));}
 catch{return null;}
}
const CK=['schemaVersion','repository','sourceHeadSha','mainBaseSha',
 'policyFingerprintSha256','cvCandidateSha256','pushRunId','prRunId',
 'epoch','previousDigest','nonce','objectVersion','archiveDigest',
 'primaryRegion','issuedAt','expiresAt'];
const REV=['schemaVersion','repository','checkpointDigest','version',
 'previousVersion','previousDigest','revokedKeyIds','issuedAt','expiresAt'];
const OBS=['schemaVersion','role','repository','sourceHeadSha','checkpointDigest',
 'revocationDigest','epoch','nonce','endpointHost','observedAt','expiresAt'];
const REC=['schemaVersion','repository','sourceHeadSha','checkpointDigest',
 'revocationDigest','objectVersion','archiveDigest','primaryRegion',
 'recoveryRegion','restoreObservedAt','retentionUntil',
 'restoreSucceeded','restoreHashMatches','deleteDeniedClaim'];
const ANCHOR=['epoch','checkpointDigest','revocationVersion','revocationDigest',
 'observedAt'];
const KEY=['keyId','publicKeyPem','spkiSha256','validFrom','validUntil'];
const SIGN=['role','keyId','algorithm','signature'];
function validKey(role,roster,pins,issued,now,used,revoked){
 const key=roster?.[role];
 if(!exact(key,KEY)||!ID.test(key.keyId??'')||
    typeof key.publicKeyPem!=='string'||key.publicKeyPem.length>4096||
    !HEX.test(key.spkiSha256??'')||pins?.[role]!==key.spkiSha256||
    revoked.has(key.keyId)||!Number.isFinite(date(key.validFrom))||
    !Number.isFinite(date(key.validUntil))||
    date(key.validFrom)>issued||date(key.validUntil)<=now)
  return null;
 try{
  const pub=createPublicKey(key.publicKeyPem);
  if(pub.asymmetricKeyType!=='ed25519')return null;
  const fingerprint=digest(pub.export({type:'spki',format:'der'}));
  if(fingerprint!==key.spkiSha256||used.has(fingerprint))return null;
  used.add(fingerprint);
  return pub;
 }catch{return null;}
}
function signatureValid(kind,statement,signature,role,pub,roster){
 if(!exact(signature,SIGN)||signature.role!==role||
    signature.keyId!==roster?.[role]?.keyId||
    signature.algorithm!=='Ed25519'||!B64.test(signature.signature??'')||
    !pub)return false;
 try{
  const raw=Buffer.from(signature.signature,'base64');
  return raw.length===64&&raw.toString('base64')===signature.signature&&
    verify(null,claimSigningBytes(kind,statement),pub,raw);
 }catch{return false;}
}
export function assessCrossRunRecoveryCandidate({
 cvEvidence=null,roster={},operatorPins={},previous=null,
 checkpoint=null,revocation=null,witnesses=[],recovery=null,
 now='2026-11-19T22:41:00.000Z'
}={}){
 const errors=new Set();
 const add=(ok,code)=>{if(!ok)errors.add(code);};
 const time=date(now);
 add(Number.isFinite(time),'CW_VERIFICATION_CLOCK_INVALID');
 let cv=null;
 try{
  cv=assessDetachedCandidate({
   before:cvEvidence?.before,after:cvEvidence?.after,
   statement:cvEvidence?.statement,signatures:cvEvidence?.signatures,
   registry:cvEvidence?.registry,checkpoint:cvEvidence?.checkpoint,now
  });
 }catch{}
 const current=cv?.twoSnapshotsAndDetachedCandidateMathematicallyConsistent===true&&
  cv?.productionReleaseAuthorized===false&&cv?.releaseDecision==='HOLD';
 add(current,'CW_PRECEDING_1CV_CANDIDATE_MATHEMATICS_INVALID');
 add(exact(roster,ROLES)&&exact(operatorPins,ROLES),
  'CW_SIX_DISTINCT_OPERATOR_PINNED_ROLE_KEYS_REQUIRED');
 const used=new Set(),keyIds=new Set(),pubs={};
 const revived=new Set(
  Array.isArray(revocation?.statement?.revokedKeyIds)?
    revocation.statement.revokedKeyIds:[]);
 const checkpointIssued=date(checkpoint?.issuedAt);
 for(const role of ROLES){
  const key=roster?.[role];
  if(typeof key?.keyId==='string'){
   if(keyIds.has(key.keyId))errors.add('CW_ROLE_KEY_ID_REUSED');
   keyIds.add(key.keyId);
  }
  const pub=validKey(role,roster,operatorPins,checkpointIssued,time,used,revived);
  if(!pub)errors.add('CW_PIN_KEY_EXPIRY_REVOCATION_OR_ROLE_COLLISION_'+role);
  else pubs[role]=pub;
 }
 for(const [role,roleName] of [
  ['SECURITY_WITNESS','SECURITY_WITNESS'],
  ['BUSINESS_WITNESS','BUSINESS_WITNESS']
 ]){
  const key=cvEvidence?.registry?.[roleName],selected=roster?.[role];
  if(!key||!selected||selected.spkiSha256!==key.spkiSha256||
     selected.publicKeyPem!==key.publicKeyPem||
     selected.keyId!==key.keyId)
   errors.add('CW_CV_SIGNER_KEY_OR_PIN_SUBSTITUTED_'+role);
 }
 const snap=checkpoint;
 if(!exact(snap,CK)||snap.schemaVersion!==1||
    snap.repository!==REPO||!SHA.test(snap.sourceHeadSha??'')||
    !SHA.test(snap.mainBaseSha??'')||
    !HEX.test(snap.policyFingerprintSha256??'')||
    !HEX.test(snap.cvCandidateSha256??'')||
    !HEX.test(snap.previousDigest??'')||
    !HEX.test(snap.nonce??'')||snap.nonce==='0'.repeat(64)||
    !positive(snap.pushRunId)||!positive(snap.prRunId)||
    snap.pushRunId===snap.prRunId||!positive(snap.epoch)||
    typeof snap.objectVersion!=='string'||!ID.test(snap.objectVersion)||
    !HEX.test(snap.archiveDigest??'')||
    !/^[a-z]{2}-[a-z]+-\d$/.test(snap.primaryRegion??'')||
    !stampOk(snap.issuedAt,snap.expiresAt,time))
  errors.add('CW_CHECKPOINT_SOURCE_NONCE_SCHEMA_OR_TTL_INVALID');
 add(current&&snap?.sourceHeadSha===cv.currentHeadSha&&
  snap?.mainBaseSha===cv.mainBaseSha&&
  snap?.policyFingerprintSha256===cv.policyFingerprintSha256&&
  snap?.cvCandidateSha256===cv.detachedCandidateSha256&&
  snap?.pushRunId===cvEvidence.statement.pushRunId&&
  snap?.prRunId===cvEvidence.statement.prRunId&&
  snap?.archiveDigest===cv.policyFingerprintSha256,
  'CW_CHECKPOINT_NOT_BOUND_TO_1CV_SIGNED_FREEZE');
 if(!exact(previous,ANCHOR)||!Number.isSafeInteger(previous.epoch)||
    previous.epoch<0||!HEX.test(previous.checkpointDigest??'')||
    !Number.isSafeInteger(previous.revocationVersion)||
    previous.revocationVersion<0||!HEX.test(previous.revocationDigest??'')||
    !Number.isFinite(date(previous.observedAt))||
    snap?.epoch!==previous.epoch+1||
    snap?.previousDigest!==previous.checkpointDigest||
    previous.epoch!==cvEvidence?.statement?.epoch||
    previous.checkpointDigest!==cv?.detachedCandidateSha256||
    date(previous.observedAt)>=date(snap?.issuedAt))
  errors.add('CW_CROSS_RUN_CHECKPOINT_REPLAY_ROLLBACK_OR_GAP');
 const checkpointDigest=evidenceSha('checkpoint',snap);
 add(HEX.test(checkpointDigest??''),'CW_CHECKPOINT_CANONICAL_DIGEST_INVALID');
 const rev=revocation?.statement,revSig=revocation?.signature;
 const revoked=rev?.revokedKeyIds;
 const revokedValid=Array.isArray(revoked)&&revoked.length<=12&&
  revoked.every(x=>typeof x==='string'&&ID.test(x))&&
  new Set(revoked).size===revoked.length&&
  JSON.stringify(revoked)===JSON.stringify([...revoked].sort());
 add(revokedValid,'CW_REVOCATION_LIST_MALFORMED_OR_DUPLICATE');
 if(!exact(rev,REV)||rev.schemaVersion!==1||
    rev.repository!==REPO||rev.checkpointDigest!==checkpointDigest||
    !positive(rev.version)||rev.version!==previous?.revocationVersion+1||
    rev.previousVersion!==previous?.revocationVersion||
    rev.previousDigest!==previous?.revocationDigest||
    !stampOk(rev.issuedAt,rev.expiresAt,time)||
    date(rev.issuedAt)<checkpointIssued)
  errors.add('CW_REVOCATION_SOURCE_VERSION_OR_FRESHNESS_INVALID');
 if(ROLES.some(role=>revived.has(roster?.[role]?.keyId)))
  errors.add('CW_ACTIVE_SIGNER_REVOKED_BY_CURRENT_REVOCATION');
 const revDigest=evidenceSha('revocation',rev);
 if(!signatureValid('revocation',rev,revSig,'REVOCATION_AUTHORITY',
    pubs.REVOCATION_AUTHORITY,roster))
  errors.add('CW_REVOCATION_PUBLISHER_SIGNATURE_INVALID');
 const seen=new Set(),hosts=new Set();
 let signedWitnesses=0,latestObservation=Number.NEGATIVE_INFINITY;
 if(!Array.isArray(witnesses)||witnesses.length!==2)
  errors.add('CW_INDEPENDENT_WITNESS_COUNT_NOT_EXACT_TWO');
 for(const item of Array.isArray(witnesses)?witnesses.slice(0,3):[]){
  const statement=item?.statement,signature=item?.signature,role=statement?.role;
  if(!['CHECKPOINT_WITNESS_A','CHECKPOINT_WITNESS_B'].includes(role)||
     seen.has(role)){
   errors.add('CW_UNREVIEWED_OR_DUPLICATED_WITNESS_ROLE');continue;
  }
  seen.add(role);
  const observed=date(statement?.observedAt);
  if(!exact(statement,OBS)||statement.schemaVersion!==1||
    statement.repository!==REPO||
    statement.sourceHeadSha!==snap?.sourceHeadSha||
    statement.checkpointDigest!==checkpointDigest||
    statement.revocationDigest!==revDigest||
    statement.epoch!==snap?.epoch||
    statement.nonce!==snap?.nonce||
    !HOST.test(statement.endpointHost??'')||
    !Number.isFinite(observed)||observed<date(rev?.issuedAt)||
    observed>time+300000||
    !stampOk(statement.observedAt,statement.expiresAt,time)){
   errors.add('CW_WITNESS_SOURCE_FORK_NONCE_OR_CLOCK_INVALID_'+role);
  }
  if(hosts.has(statement?.endpointHost))
   errors.add('CW_SAME_ASSERTED_WITNESS_ENDPOINT');
  if(typeof statement?.endpointHost==='string')hosts.add(statement.endpointHost);
  if(!signatureValid('observation',statement,signature,role,pubs[role],roster))
   errors.add('CW_WITNESS_DETACHED_SIGNATURE_INVALID_'+role);
  else signedWitnesses++;
  latestObservation=Math.max(latestObservation,observed);
 }
 if(seen.size!==2)errors.add('CW_TWO_DISTINCT_WITNESS_QUORUM_ABSENT');
 const rec=recovery?.statement;
 if(!exact(rec,REC)||rec.schemaVersion!==1||
    rec.repository!==REPO||rec.sourceHeadSha!==snap?.sourceHeadSha||
    rec.checkpointDigest!==checkpointDigest||
    rec.revocationDigest!==revDigest||
    rec.objectVersion!==snap?.objectVersion||
    rec.archivedDigest!==snap?.archiveDigest||
    rec.primaryRegion!==snap?.primaryRegion||
    !/^[a-z]{2}-[a-z]+-\d$/.test(rec.recoveryRegion??'')||
    rec.recoveryRegion===snap?.primaryRegion||
    !Number.isFinite(date(rec.restoreObservedAt))||
    date(rec.restoreObservedAt)<latestObservation||
    date(rec.restoreObservedAt)>time+300000||
    !Number.isFinite(date(rec.retentionUntil))||
    date(rec.retentionUntil)<=time+30*86400000||
    rec.restoreSucceeded!==true||rec.restoreHashMatches!==true||
    rec.deleteDeniedClaim!==true)
  errors.add('CW_RECOVERY_VERSION_REGION_RETENTION_OR_RESTORE_INVALID');
 if(!signatureValid('recovery',rec,recovery?.signature,
    'RECOVERY_AUDITOR',pubs.RECOVERY_AUDITOR,roster))
  errors.add('CW_RECOVERY_AUDITOR_SIGNATURE_INVALID');
 const valid=errors.size===0&&current&&signedWitnesses===2;
 const binding={
  sourceHead:snap?.sourceHeadSha??null,epoch:snap?.epoch??null,
  checkpointDigest,revocationDigest:revDigest,
  witnessCount:signedWitnesses,claimedRecoveryVersion:snap?.objectVersion??null
 };
 return Object.freeze({
  phase:'1CW',schemaVersion:1,
  kind:'UNTRUSTED_CROSS_RUN_REVOCATION_WITNESS_AND_DR_CANDIDATE_HOLD',
  repository:REPO,
  candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent:valid,
  prior1CVCandidateMathematicallyConsistent:current,
  candidateSignedWitnessCount:signedWitnesses,
  candidateSnapshotFingerprintSha256:digest(JSON.stringify(binding)),
  candidateCheckpointDigest:checkpointDigest,
  candidateRevocationDigest:revDigest,
  anomalyCodes:Object.freeze([...errors].sort()),
  keysAndPinsIndependentlyEnrolledAndRoleMandated:false,
  liveSignedRevocationSourceAndRevokedSerialsAuthenticated:false,
  independentlyRetrievedDurableMonotonicOffsiteAnchorVerified:false,
  separateWitnessEndpointTlsAndOrganizationAuthenticated:false,
  crossRunForkOrReplayExternallyQuarantined:false,
  actualWormComplianceLockAndDeleteDenialMeasured:false,
  offsiteRecoveryRestoreRtoRpoIndependentlyValidated:false,
  approvedEmudhraCcaRcaiMcaOrStagingVerified:false,
  genuineOidcSlsaWorkloadAttestationVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function safeJson(path){
 if(typeof path!=='string'||path.length<2||path.length>4096)
  throw Error('CW_OPERATOR_OFFREPO_CANDIDATE_PATH_INVALID');
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>262144)
  throw Error('CW_OPERATOR_CANDIDATE_NOT_REGULAR_OR_BOUNDED_FILE');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==2||
    args[0]!=='--inspect-offrepo-candidate')
  throw Error('CW_ONLY_EXPLICIT_OPERATOR_LOCAL_READONLY_INSPECTION');
 const input=safeJson(args[1]);
 const receipt=assessCrossRunRecoveryCandidate(input);
 console.log(JSON.stringify(receipt,null,2));
 if(!receipt.candidateSignedCheckpointRevocationForkAndRecoveryMathematicallyConsistent)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main()}catch(error){
  console.error('CW unsigned external enrollment/recovery HOLD:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 }
}
