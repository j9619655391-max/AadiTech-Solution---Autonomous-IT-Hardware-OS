import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {assessOfflineObserverEnrollmentRevocationCandidate}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';
import {DV_ROLES} from './phase1dv-offline-observer-publication-candidate.mjs';
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES}
 from './phase1dw-offline-observer-enrollment-revocation.mjs';

// Phase 1DX: deterministic OFFLINE read-only evidence admission and frozen
// incident-recovery REHEARSAL. All evidence bytes, signers, clocks, endpoints,
// recovery anchor and metadata are caller-supplied. No external fetch or thaw.
export const DX_SOURCES=Object.freeze([
 'PUBLISHER_RETRIEVAL','ARCHIVE_RETRIEVAL','REVOCATION_RETRIEVAL'
]);
export const DX_RECOVERY_ROLES=Object.freeze([
 'LEGAL_RECOVERY_CUSTODIAN','SECURITY_RECOVERY_CUSTODIAN'
]);
export const DX_STAGES=Object.freeze([
 'FREEZE_EVIDENCE','QUARANTINE_SOURCES','READ_ONLY_RESTORE_REHEARSAL'
]);
const SRC_DOMAIN='aaditech/phase1dx/offline-source-evidence/v1\n';
const SET_DOMAIN='aaditech/phase1dx/candidate-evidence-set/v1\n';
const STEP_DOMAIN='aaditech/phase1dx/read-only-recovery-ledger/v1\n';
const REC_DOMAIN='aaditech/phase1dx/recovery-custodian/v1\n';
const TOP=['custodyCandidate','sourceReceipts','sourcePins','sourceBytes',
 'previousRecoveryAnchor','incident','recoverySteps',
 'recoverySigners','recoveryPins','now'];
const SOURCE_PIN=['keyId','spkiSha256','operatorId',
 'operatorOrganizationId','endpointHost','tlsPeerSpkiSha256'];
const RECOVERY_PIN=['keyId','spkiSha256','operatorId',
 'operatorOrganizationId'];
const PACKET=['statement','publicKeyPem','signature'];
const SOURCE_STATEMENT=['schemaVersion','kind','role','repository',
 'organizationId','sourceHeadSha','mainBaseSha','checkpointSha256',
 'archiveSha256','revocationDigestSha256','challengeNonce',
 'contentSha256',...SOURCE_PIN,'httpStatus','redirectCount',
 'observedAt','expiresAt','decision'];
const INCIDENT=['schemaVersion','kind','incidentId','repository',
 'organizationId','sourceHeadSha','mainBaseSha','checkpointSha256',
 'archiveSha256','revocationDigestSha256','evidenceSetDigestSha256',
 'challengeNonce','observedAt','decision'];
const ANCHOR=['sequence','digestSha256'];
const STEP=['schemaVersion','kind','incidentId','sequence',
 'previousDigestSha256','stage','evidenceSetDigestSha256',
 'challengeNonce','observedAt','decision'];
const RECOVERY_STATEMENT=['schemaVersion','kind','role','repository',
 'organizationId','sourceHeadSha','mainBaseSha','incidentId',
 'evidenceSetDigestSha256','recoveryLedgerDigestSha256',
 'previousRecoveryDigestSha256','recoverySequence',
 'revocationDigestSha256','challengeNonce',...RECOVERY_PIN,
 'observedAt','expiresAt','decision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HEX=/^[a-f0-9]{64}$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,max){try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}}
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))
  return NaN;
 const t=Date.parse(x);
 return Number.isFinite(t)&&new Date(t).toISOString()===x?t:NaN;
}
function validPin(x,source){
 const keys=source?SOURCE_PIN:RECOVERY_PIN;
 return EXACT(x,keys)&&
  ['keyId','operatorId','operatorOrganizationId'].every(k=>ID.test(x[k]??''))&&
  HEX.test(x.spkiSha256??'')&&(!source||(
   HEX.test(x.tlsPeerSpkiSha256??'')&&
   typeof x.endpointHost==='string'&&x.endpointHost.length>=7&&
   x.endpointHost.length<=253&&/^[a-z0-9.-]+$/.test(x.endpointHost)&&
   !x.endpointHost.startsWith('.')&&!x.endpointHost.endsWith('.')&&
   !x.endpointHost.includes('..')));
}
function validClock(observed,expiry,clock,earliest=null){
 const a=utc(observed),b=utc(expiry);
 return Number.isFinite(clock)&&Number.isFinite(a)&&Number.isFinite(b)&&
  a>=clock-900000&&a<=clock+300000&&b>clock&&b>a&&
  b-a<=900000&&(earliest===null||a>=earliest);
}
function signatureValid(packet,role,signingBytes){
 try{
  if(!EXACT(packet,PACKET)||typeof packet.publicKeyPem!=='string'||
   packet.publicKeyPem.length>4096||typeof packet.signature!=='string'||
   !SIG.test(packet.signature))return false;
  const key=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return key.asymmetricKeyType==='ed25519'&&sig.length===64&&
   sig.toString('base64')===packet.signature&&
   hash(key.export({type:'spki',format:'der'}))===
    packet.statement.spkiSha256&&
   verify(null,signingBytes(role,packet.statement),key,sig);
 }catch{return false;}
}
function decodeBytes(value){
 if(typeof value!=='string'||value.length<4||value.length>24576||
  !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
  return null;
 const bytes=Buffer.from(value,'base64');
 return bytes.length>0&&bytes.length<=16384&&
  bytes.toString('base64')===value?bytes:null;
}
function scopeMatches(s,expected){
 return OWN(expected)&&s.repository===REPO&&
  ['organizationId','sourceHeadSha','mainBaseSha','checkpointSha256',
   'archiveSha256','revocationDigestSha256','challengeNonce']
   .every(k=>s[k]===expected[k]);
}
function sourcePinDiversity(sourcePins,recoveryPins,dw){
 if(!EXACT(sourcePins,DX_SOURCES)||!EXACT(recoveryPins,DX_RECOVERY_ROLES)||
  !DX_SOURCES.every(r=>validPin(sourcePins[r],true))||
  !DX_RECOVERY_ROLES.every(r=>validPin(recoveryPins[r],false)))
  return false;
 const current=[...DX_SOURCES.map(r=>sourcePins[r]),
  ...DX_RECOVERY_ROLES.map(r=>recoveryPins[r])];
 const prior=[...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins?.[r]),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins?.[r]),
  ...DV_ROLES.map(r=>dw.publicationCandidate?.comparisonPins?.[r])];
 const all=[...current,...prior];
 for(const k of ['keyId','spkiSha256','operatorId']){
  const values=all.map(x=>x?.[k]);
  if(values.some(v=>typeof v!=='string')||
   new Set(values).size!==values.length)return false;
 }
 const organizations=[
  ...current.map(x=>x.operatorOrganizationId),
  ...DW_ENROLLMENT_ROLES.map(r=>dw.enrollmentPins?.[r]?.custodianOrganizationId),
  ...DW_REVOCATION_ROLES.map(r=>dw.revocationPins?.[r]?.custodianOrganizationId)
 ];
 if(organizations.some(x=>typeof x!=='string')||
  new Set(organizations).size!==organizations.length)return false;
 const hosts=DX_SOURCES.map(r=>sourcePins[r].endpointHost),
  tls=DX_SOURCES.map(r=>sourcePins[r].tlsPeerSpkiSha256);
 for(const role of DV_ROLES){
  hosts.push(dw.publicationCandidate?.comparisonPins?.[role]?.endpointHost);
  tls.push(dw.publicationCandidate?.comparisonPins?.[role]?.tlsPeerSpkiSha256);
 }
 if(new Set(hosts).size!==hosts.length||new Set(tls).size!==tls.length)
  return false;
 for(const e of dw.publicationCandidate?.history?.epochs??[])
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   const w=e.checkpointObservations?.[0]?.witnesses?.[role];
   if(!w||all.some(p=>p.keyId===w.keyId||
    p.spkiSha256===w.spkiSha256))return false;
  }
 return true;
}
/** Domain-separated, exact-schema candidate signed retrieval bytes. */
export function sourceSigningBytesDx(role,statement){
 if(!DX_SOURCES.includes(role)||!EXACT(statement,SOURCE_STATEMENT)||
  statement.role!==role||!bounded(statement,8192))
  throw Error('DX_SOURCE_STATEMENT_SCHEMA_INVALID');
 return Buffer.from(SRC_DOMAIN+canonical(statement),'utf8');
}
/** Domain-separated recovery-step digest. Every subsequent step binds it. */
export function recoveryStepDigestDx(step){
 if(!EXACT(step,STEP)||!bounded(step,8192))
  throw Error('DX_RECOVERY_STEP_SCHEMA_INVALID');
 return hash(STEP_DOMAIN+canonical(step));
}
/** Detached custodian signature is over the final linked rehearsal digest. */
export function recoverySigningBytesDx(role,statement){
 if(!DX_RECOVERY_ROLES.includes(role)||
  !EXACT(statement,RECOVERY_STATEMENT)||statement.role!==role||
  !bounded(statement,8192))throw Error('DX_RECOVERY_STATEMENT_SCHEMA_INVALID');
 return Buffer.from(REC_DOMAIN+canonical(statement),'utf8');
}
function hold(errors,flags={}){
 return Object.freeze({
  phase:'1DX',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_EXTERNAL_EVIDENCE_INTAKE_AND_RECOVERY_HARD_HOLD',
  repository:REPO,
  precedingDwSignatureHistoryReverifiedMathematicallyOnly:
   flags.dwVerified===true,
  threeCandidateSourceRetrievalSignaturesMathematicallyVerifiedOnly:
   flags.sourcesVerified??0,
  sourceByteHashesComparedToSubmittedSignedClaimsOnly:
   flags.sourceBytesMatch===true,
  frozenRecoverySequenceLinkedMathematicallyOnly:
   flags.recoveryLinked===true,
  twoRecoveryCustodianSignaturesMathematicallyVerifiedOnly:
   flags.recoveryVerified??0,
  candidateEvidenceAndFrozenRehearsalInternallyConsistentOnly:
   flags.consistent===true,
  allRetrievalTlsAndPublisherClaimsCallerSupplied:true,
  priorRecoveryAnchorAndTrustedClockNotExternallyAnchored:true,
  independentlyEnrolledObserverOrRecoveryKeysAuthenticated:false,
  actualExternalPublicationAndTlsRetrievalAuthenticated:false,
  independentlyAuthenticatedMcaLegalRegistryAndProviderAuthority:false,
  liveIssuerSignedCrLOrOcspAndCertificatePolicyAuthenticated:false,
  independentWormCasDurableHighwatermarkAndDrRestoreAuthenticated:false,
  independentGithubNonauthorStagingAndIncidentApprovalVerified:false,
  recoveryWasDryRunOnlyAndCannotThawRelease:true,
  noRawKeysSignaturesArchiveOrRevocationListsInOutput:true,
  productionMutationOrExternalEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
/**
 * An offline incident re-enactment cannot authenticate external provider
 * identity or grant GO. Fail closed even when every applicant signature passes.
 */
export function assessOfflineEvidenceIncidentRecoveryCandidate(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,1280*1024)){
  errors.add('DX_EXACT_BOUNDED_INPUT_REQUIRED');
  return hold(errors);
 }
 const {custodyCandidate:dw,sourceReceipts,sourcePins,sourceBytes,
  previousRecoveryAnchor,incident,recoverySteps,recoverySigners,
  recoveryPins,now}=args;
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('DX_EXPLICIT_UTC_CLOCK_REQUIRED');
 let dwOK=false;
 try{
  const result=assessOfflineObserverEnrollmentRevocationCandidate(dw);
  dwOK=dw?.now===now&&
   result.candidateEnrollmentAndRevocationClaimsCorrelatedMathematicallyOnly&&
   result.anomalyCodes.length===0;
 }catch{dwOK=false;}
 if(!dwOK)errors.add('DX_PRECEDING_DW_NOT_REVERIFIED');
 const expected=dw?.publicationCandidate?.expected;
 const diverse=sourcePinDiversity(sourcePins,recoveryPins,dw??{});
 if(!diverse)errors.add('DX_INDEPENDENT_SOURCE_RECOVERY_PINS_UNPROVEN');
 const packetShape=Array.isArray(sourceReceipts)&&sourceReceipts.length===3&&
  EXACT(sourcePins,DX_SOURCES)&&EXACT(sourceBytes,DX_SOURCES);
 if(!packetShape)errors.add('DX_THREE_EXACT_SOURCE_RECORDS_REQUIRED');
 const expectedRevocationBytes=dwOK?Buffer.from(canonical({
  previousAnchor:dw.previousAnchor,revocationState:dw.revocationState
 }),'utf8'):null;
 const packetByRole=new Map();
 let sourcesVerified=0,bytesOK=0;
 if(packetShape)for(const packet of sourceReceipts){
  const s=packet?.statement,role=s?.role;
  if(!DX_SOURCES.includes(role)||packetByRole.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,SOURCE_STATEMENT)||
   !bounded(packet,12288)){
   errors.add('DX_RETRIEVAL_ROLE_PACKET_INVALID');continue;
  }
  packetByRole.set(role,packet);
  const pin=sourcePins[role];
  if(!validPin(pin,true)||SOURCE_PIN.some(k=>pin[k]!==s[k]))
   errors.add('DX_RETRIEVAL_DETACHED_PIN_MISMATCH');
  if(s.schemaVersion!==1||s.kind!=='UNTRUSTED_OFFLINE_SOURCE_RETRIEVAL'||
   !scopeMatches(s,expected)||s.decision!=='HOLD'||
   s.httpStatus!==200||s.redirectCount!==0)
   errors.add('DX_SIGNED_RETRIEVAL_SCOPE_OR_HTTP_INVALID');
  if(!validClock(s.observedAt,s.expiresAt,clock))
   errors.add('DX_SIGNED_RETRIEVAL_STALE_OR_EXPIRED');
  const bytes=decodeBytes(sourceBytes[role]);
  let match=bytes!==null&&HEX.test(s.contentSha256??'')&&
   hash(bytes)===s.contentSha256;
  if(role==='REVOCATION_RETRIEVAL'){
   match=match&&expectedRevocationBytes!==null&&
    bytes.equals(expectedRevocationBytes);
  }else{
   match=match&&s.contentSha256===expected?.archiveSha256;
  }
  if(!match)errors.add('DX_CANDIDATE_RETRIEVED_BYTES_MISMATCH');
  else bytesOK++;
  if(!signatureValid(packet,role,sourceSigningBytesDx))
   errors.add('DX_RETRIEVAL_SIGNATURE_OR_SPKI_INVALID');
  else sourcesVerified++;
 }
 if(packetShape&&packetByRole.size!==3)
  errors.add('DX_INCOMPLETE_SOURCE_ROLE_QUORUM');
 const sourceOK=packetShape&&packetByRole.size===3&&
  sourcesVerified===3&&bytesOK===3&&
  !['DX_RETRIEVAL_DETACHED_PIN_MISMATCH',
   'DX_SIGNED_RETRIEVAL_SCOPE_OR_HTTP_INVALID',
   'DX_SIGNED_RETRIEVAL_STALE_OR_EXPIRED'].some(c=>errors.has(c));
 const sourceSetDigest=sourceOK?hash(SET_DOMAIN+canonical(
  DX_SOURCES.map(role=>packetByRole.get(role).statement))):null;
 const anchorOK=EXACT(previousRecoveryAnchor,ANCHOR)&&
  Number.isSafeInteger(previousRecoveryAnchor.sequence)&&
  previousRecoveryAnchor.sequence>=0&&
  previousRecoveryAnchor.sequence<=1_000_000_000&&
  HEX.test(previousRecoveryAnchor.digestSha256??'');
 const incidentOK=EXACT(incident,INCIDENT)&&
  incident.schemaVersion===1&&
  incident.kind==='UNTRUSTED_SOURCE_FORK_FREEZE_REHEARSAL'&&
  ID.test(incident.incidentId??'')&&incident.repository===REPO&&
  incident.decision==='FREEZE'&&
  scopeMatches(incident,expected)&&
  incident.evidenceSetDigestSha256===sourceSetDigest&&
  Number.isFinite(utc(incident.observedAt))&&
  Number.isFinite(clock)&&utc(incident.observedAt)<=clock+300000&&
  utc(incident.observedAt)>=clock-900000;
 if(!anchorOK||!incidentOK)errors.add('DX_INCIDENT_OR_PREVIOUS_RECOVERY_ANCHOR_INVALID');
 let stepsLinked=anchorOK&&incidentOK&&
  Array.isArray(recoverySteps)&&recoverySteps.length===3;
 let finalDigest=anchorOK?previousRecoveryAnchor.digestSha256:null;
 let sequence=anchorOK?previousRecoveryAnchor.sequence:null;
 let prevTime=incidentOK?utc(incident.observedAt):null;
 const nonces=new Set([expected?.challengeNonce,incident?.challengeNonce]);
 if(stepsLinked)for(let i=0;i<3;i++){
  const s=recoverySteps[i],t=utc(s?.observedAt);
  if(!EXACT(s,STEP)||!bounded(s,8192)||
   s.schemaVersion!==1||s.kind!=='UNTRUSTED_READ_ONLY_INCIDENT_STEP'||
   s.incidentId!==incident.incidentId||
   s.stage!==DX_STAGES[i]||s.decision!=='HOLD'||
   !Number.isSafeInteger(s.sequence)||s.sequence!==sequence+1||
   s.previousDigestSha256!==finalDigest||
   s.evidenceSetDigestSha256!==sourceSetDigest||
   !HEX.test(s.challengeNonce??'')||
   s.challengeNonce==='0'.repeat(64)||nonces.has(s.challengeNonce)||
   !Number.isFinite(t)||t<=prevTime||t>clock+300000||
   t<clock-900000){
   errors.add('DX_RECOVERY_STEP_REORDER_FORK_OR_UNFREEZE');
   stepsLinked=false;break;
  }
  nonces.add(s.challengeNonce);sequence=s.sequence;prevTime=t;
  finalDigest=recoveryStepDigestDx(s);
 }
 if(!stepsLinked)errors.add('DX_READ_ONLY_RECOVERY_CHAIN_INVALID');
 const recoveryPacketsOK=Array.isArray(recoverySigners)&&
  recoverySigners.length===2&&EXACT(recoveryPins,DX_RECOVERY_ROLES);
 if(!recoveryPacketsOK)
  errors.add('DX_TWO_EXACT_RECOVERY_CUSTODIANS_REQUIRED');
 let recoveryVerified=0;
 const recoverySeen=new Set();
 if(recoveryPacketsOK)for(const packet of recoverySigners){
  const s=packet?.statement,role=s?.role;
  if(!DX_RECOVERY_ROLES.includes(role)||recoverySeen.has(role)||
   !EXACT(packet,PACKET)||!EXACT(s,RECOVERY_STATEMENT)||
   !bounded(packet,12288)){
   errors.add('DX_RECOVERY_CUSTODIAN_ROLE_PACKET_INVALID');continue;
  }
  recoverySeen.add(role);
  const pin=recoveryPins[role];
  if(!validPin(pin,false)||RECOVERY_PIN.some(k=>s[k]!==pin[k]))
   errors.add('DX_RECOVERY_CUSTODIAN_PIN_MISMATCH');
  if(s.schemaVersion!==1||
   s.kind!=='UNTRUSTED_OFFLINE_RECOVERY_REHEARSAL_ATTESTATION'||
   s.decision!=='REHEARSAL_ONLY_HOLD'||s.repository!==REPO||
   !OWN(expected)||s.organizationId!==expected.organizationId||
   s.sourceHeadSha!==expected.sourceHeadSha||
   s.mainBaseSha!==expected.mainBaseSha||
   s.incidentId!==incident?.incidentId||
   s.evidenceSetDigestSha256!==sourceSetDigest||
   !stepsLinked||s.recoveryLedgerDigestSha256!==finalDigest||
   s.previousRecoveryDigestSha256!==previousRecoveryAnchor?.digestSha256||
   s.recoverySequence!==sequence||
   s.revocationDigestSha256!==expected?.revocationDigestSha256||
   s.challengeNonce!==expected?.challengeNonce)
   errors.add('DX_SIGNED_REHEARSAL_SCOPE_OR_FORBIDDEN_THAW');
  if(!validClock(s.observedAt,s.expiresAt,clock,prevTime))
   errors.add('DX_SIGNED_RECOVERY_STALE_OR_REORDERED');
  if(!signatureValid(packet,role,recoverySigningBytesDx))
   errors.add('DX_RECOVERY_SIGNATURE_OR_SPKI_INVALID');
  else recoveryVerified++;
 }
 if(recoveryPacketsOK&&recoverySeen.size!==2)
  errors.add('DX_RECOVERY_SIGNER_QUORUM_INCOMPLETE');
 const consistent=dwOK&&diverse&&sourceOK&&stepsLinked&&
  recoveryVerified===2&&errors.size===0;
 return hold(errors,{dwVerified:dwOK,sourcesVerified,
  sourceBytesMatch:bytesOK===3,recoveryLinked:stepsLinked,
  recoveryVerified,consistent});
}
