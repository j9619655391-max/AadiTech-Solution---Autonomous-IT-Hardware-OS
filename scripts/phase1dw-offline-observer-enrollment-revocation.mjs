import {Buffer} from 'node:buffer';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,REPO}
 from './phase1cx-pinned-external-source-highwatermark.mjs';
import {DV_ROLES,assessOfflineObserverPublicationCandidate}
 from './phase1dv-offline-observer-publication-candidate.mjs';

// Phase 1DW intentionally has no network, writable state, privileged identity
// or credential enrollment. ALL pins, revocation sources, operators, histories
// and clocks are supplied by the caller. Mathematical verification != authority.
export const DW_ENROLLMENT_ROLES=Object.freeze([
 'LEGAL_ENROLLMENT_CUSTODIAN','SECURITY_ENROLLMENT_CUSTODIAN'
]);
export const DW_REVOCATION_ROLES=Object.freeze([
 'CORPORATE_REGISTRY_REVOCATION','EXTERNAL_PROVIDER_REVOCATION'
]);
const ENROLL_DOMAIN='aaditech/phase1dw/observer-enrollment/v1\n';
const REV_DOMAIN='aaditech/phase1dw/revocation-snapshot/v1\n';
const STATUS_DOMAIN='aaditech/phase1dw/revocation-status/v1\n';
const PINS_DOMAIN='aaditech/phase1dw/detached-observer-pins/v1\n';
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const TOP=['publicationCandidate','enrollmentPackets','enrollmentPins',
 'revocationPackets','revocationPins','revocationState','previousAnchor','now'];
const PIN=['keyId','spkiSha256','operatorId','custodianOrganizationId'];
const PACKET=['statement','publicKeyPem','signature'];
const BASE=['schemaVersion','kind','role','repository','organizationId',
 'sourceHeadSha','mainBaseSha','checkpointSha256','archiveSha256',
 'legalMandateDigestSha256','revocationDigestSha256','challengeNonce',
 'keyId','operatorId','custodianOrganizationId','spkiSha256','observedAt','expiresAt','decision'];
const ENROLL=[...BASE,'observerPinDigestSha256'];
const REV=[...BASE,'currentVersion','previousVersion',
 'previousDigestSha256','revokedKeyIds'];
const STATE=['version','previousVersion','previousDigestSha256',
 'revokedKeyIds','observedAt'];
const ANCHOR=['version','digestSha256'];
const EXPECT=['organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','archiveSha256','legalMandateDigestSha256',
 'revocationDigestSha256','challengeNonce'];
const SPKI=/^[0-9a-f]{64}$/,ID=/^[a-z][a-z0-9._-]{5,79}$/,
 SIG=/^[A-Za-z0-9+/]{86}==$/;
const digest=x=>createHash('sha256').update(x).digest('hex');
const bounded=(x,max)=>{try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}};
function utc(x){
 if(typeof x!=='string'||!
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x))return NaN;
 const n=Date.parse(x);
 return Number.isFinite(n)&&new Date(n).toISOString()===x?n:NaN;
}
function validPin(p){
 return EXACT(p,PIN)&&ID.test(p.keyId??'')&&
  ID.test(p.operatorId??'')&&ID.test(p.custodianOrganizationId??'')&&
  SPKI.test(p.spkiSha256??'');
}
function validState(s){
 return EXACT(s,STATE)&&Number.isSafeInteger(s.version)&&
  s.version>0&&s.version<=1_000_000_000&&
  Number.isSafeInteger(s.previousVersion)&&s.previousVersion>=0&&
  s.previousVersion<s.version&&
  SPKI.test(s.previousDigestSha256??'')&&
  Number.isFinite(utc(s.observedAt))&&
  Array.isArray(s.revokedKeyIds)&&s.revokedKeyIds.length<=32&&
  s.revokedKeyIds.every(v=>ID.test(v??''))&&
  new Set(s.revokedKeyIds).size===s.revokedKeyIds.length&&
  s.revokedKeyIds.every((v,i)=>i===0||s.revokedKeyIds[i-1]<v);
}
function uniqueAuthority(pins,publication){
 const roles=[...DW_ENROLLMENT_ROLES,...DW_REVOCATION_ROLES];
 if(!EXACT(pins,roles)||!roles.every(role=>validPin(pins[role])))
  return false;
 const dv=publication?.comparisonPins;
 if(!EXACT(dv,DV_ROLES))return false;
 const values=[...roles.map(role=>pins[role]),
  ...DV_ROLES.map(role=>dv[role])];
 for(const field of ['keyId','spkiSha256','operatorId']){
  const list=values.map(x=>x?.[field]);
  if(list.some(x=>typeof x!=='string')||
    new Set(list).size!==list.length)return false;
 }
 const custodianOrgs=roles.map(role=>pins[role].custodianOrganizationId);
 if(new Set(custodianOrgs).size!==custodianOrgs.length)return false;
 const hist=publication?.history?.epochs;
 if(!Array.isArray(hist))return false;
 for(const epoch of hist){
  const w=epoch?.checkpointObservations?.[0]?.witnesses;
  if(!OWN(w))return false;
  for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS']){
   if(!OWN(w[role]))return false;
   if(values.some(p=>p.keyId===w[role].keyId||
       p.spkiSha256===w[role].spkiSha256))return false;
  }
 }
 return true;
}
/** Canonical digest of both UNTRUSTED, externally unverified DV observer pins. */
export function observerPinDigestDw(pins){
 if(!EXACT(pins,DV_ROLES)||!bounded(pins,8192))
  throw Error('DW_OBSERVER_PINS_REQUIRED');
 return digest(PINS_DOMAIN+canonical(pins));
}
/** Canonical digest of claimed common revocation state and DU/DV scope. */
export function revocationStatusDigestDw(expected,state){
 if(!OWN(expected)||!EXPECT.every(k=>Object.hasOwn(expected,k))||
  !validState(state)||!bounded({expected,state},8192))
  throw Error('DW_REVOCATION_STATE_INVALID');
 const common=Object.fromEntries(EXPECT.filter(k=>
  k!=='revocationDigestSha256').map(k=>[k,expected[k]]));
 return digest(STATUS_DOMAIN+canonical({scope:common,state}));
}
export function signingBytesDw(role,statement){
 const enroll=DW_ENROLLMENT_ROLES.includes(role);
 const rev=DW_REVOCATION_ROLES.includes(role);
 if((!enroll&&!rev)||!EXACT(statement,enroll?ENROLL:REV)||
    statement.role!==role||!bounded(statement,8192))
  throw Error('DW_SIGNING_SCOPE_INVALID');
 return Buffer.from((enroll?ENROLL_DOMAIN:REV_DOMAIN)+
  canonical(statement),'utf8');
}
function signed(packet,role){
 try{
  if(!EXACT(packet,PACKET)||typeof packet.publicKeyPem!=='string'||
    packet.publicKeyPem.length>4096||typeof packet.signature!=='string'||
    !SIG.test(packet.signature))return false;
  const pub=createPublicKey(packet.publicKeyPem);
  const sig=Buffer.from(packet.signature,'base64');
  return pub.asymmetricKeyType==='ed25519'&&sig.length===64&&
   sig.toString('base64')===packet.signature&&
   digest(pub.export({type:'spki',format:'der'}))===
    packet.statement.spkiSha256&&
   verify(null,signingBytesDw(role,packet.statement),pub,sig);
 }catch{return false;}
}
function verifyPackets({packets,roles,pins,expected,clock,
 extra,errors,code}){
 let count=0;
 const seen=new Set();
 if(!Array.isArray(packets)||packets.length!==2){
  errors.add('DW_TWO_'+code+'_SIGNATURES_REQUIRED');
  return count;
 }
 for(const packet of packets){
  const s=packet?.statement,role=s?.role;
  if(!roles.includes(role)||seen.has(role)||!EXACT(packet,PACKET)||
    !EXACT(s,roles===DW_ENROLLMENT_ROLES?ENROLL:REV)||
    !bounded(packet,12288)){
   errors.add('DW_'+code+'_ROLE_PACKET_INVALID');continue;
  }
  seen.add(role);
  const pin=OWN(pins)?pins[role]:null;
  if(!validPin(pin)||PIN.some(k=>s[k]!==pin[k]))
   errors.add('DW_'+code+'_DETACHED_SIGNER_PIN_MISMATCH');
  if(s.schemaVersion!==1||s.kind!==(roles===DW_ENROLLMENT_ROLES?
   'UNTRUSTED_OFFLINE_OBSERVER_ENROLLMENT_CANDIDATE':
   'UNTRUSTED_OFFLINE_REVOCATION_SOURCE_CANDIDATE')||
   s.repository!==REPO||s.decision!=='HOLD'||
   !OWN(expected)||EXPECT.some(k=>s[k]!==expected[k]))
   errors.add('DW_'+code+'_SOURCE_OR_HOLD_SCOPE_MISMATCH');
  if(!extra(s))
   errors.add('DW_'+code+'_SIGNED_STATE_OR_HISTORY_MISMATCH');
  const issued=utc(s.observedAt),expiry=utc(s.expiresAt);
  if(!(Number.isFinite(clock)&&Number.isFinite(issued)&&
   Number.isFinite(expiry)&&issued>=clock-900000&&
   issued<=clock+300000&&expiry>clock&&expiry>issued&&
   expiry<=issued+900000))
   errors.add('DW_'+code+'_STALE_OR_EXPIRED_SIGNATURE');
  if(!signed(packet,role)){
   errors.add('DW_'+code+'_ED25519_OR_SPKI_UNVERIFIED');continue;
  }
  count++;
 }
 if(seen.size!==2)errors.add('DW_'+code+'_SIGNER_QUORUM_INCOMPLETE');
 return count;
}
/** Only candidate correlation. No independent enrollment/retrieval/revocation. */
export function assessOfflineObserverEnrollmentRevocationCandidate(args={}){
 const errors=new Set();
 const inputOK=EXACT(args,TOP)&&bounded(args,1024*1024);
 if(!inputOK)errors.add('DW_EXACT_BOUNDED_INPUT_REQUIRED');
 const {publicationCandidate=null,enrollmentPackets=null,
  enrollmentPins=null,revocationPackets=null,revocationPins=null,
  revocationState=null,previousAnchor=null,now=null}=OWN(args)?args:{};
 const clock=utc(now);
 if(!Number.isFinite(clock))errors.add('DW_EXPLICIT_TRUSTED_CLOCK_ABSENT');
 let dvOK=false;
 if(OWN(publicationCandidate)&&publicationCandidate.now===now){
  try{
   const r=assessOfflineObserverPublicationCandidate(publicationCandidate);
   dvOK=r.candidateObserverPublicationCorroboratedMathematicallyOnly&&
    r.anomalyCodes.length===0;
  }catch{dvOK=false;}
 }
 if(!dvOK)errors.add('DW_DV_CANDIDATE_NOT_REVERIFIED');
 const expected=publicationCandidate?.expected;
 let digestPins=null,digestStatus=null;
 try{digestPins=observerPinDigestDw(publicationCandidate?.comparisonPins);}
 catch{errors.add('DW_OBSERVER_PIN_DIGEST_UNAVAILABLE');}
 const anchorOK=EXACT(previousAnchor,ANCHOR)&&
  Number.isSafeInteger(previousAnchor.version)&&
  previousAnchor.version>=0&&previousAnchor.version<1_000_000_000&&
  SPKI.test(previousAnchor.digestSha256??'');
 const stateOK=validState(revocationState)&&anchorOK&&
  revocationState.previousVersion===previousAnchor.version&&
  revocationState.version===previousAnchor.version+1&&
  revocationState.previousDigestSha256===previousAnchor.digestSha256&&
  Number.isFinite(clock)&&utc(revocationState.observedAt)>=clock-900000&&
  utc(revocationState.observedAt)<=clock+300000;
 if(!stateOK)errors.add('DW_REVOCATION_MONOTONIC_ANCHOR_OR_CLOCK_INVALID');
 if(stateOK)try{digestStatus=revocationStatusDigestDw(expected,revocationState);}
 catch{errors.add('DW_REVOCATION_DIGEST_UNAVAILABLE');}
 if(!digestStatus||expected?.revocationDigestSha256!==digestStatus)
  errors.add('DW_SIGNED_REVOCATION_DIGEST_NOT_BOUND_TO_DV');
 const combined=OWN(enrollmentPins)&&OWN(revocationPins)?
  {...enrollmentPins,...revocationPins}:null;
 const independent=uniqueAuthority(combined,publicationCandidate);
 if(!independent)errors.add('DW_INDEPENDENT_CUSTODY_REVOCATION_KEYS_UNPROVEN');
 const revoked=Array.isArray(revocationState?.revokedKeyIds)?
  revocationState.revokedKeyIds:[];
 if(dvOK&&revoked.length>0){
  const active=[
   ...DV_ROLES.map(role=>publicationCandidate.comparisonPins[role].keyId),
   ...DW_ENROLLMENT_ROLES.map(role=>enrollmentPins?.[role]?.keyId),
   ...DW_REVOCATION_ROLES.map(role=>revocationPins?.[role]?.keyId)];
  for(const epoch of publicationCandidate.history.epochs)
   for(const role of ['LEGAL_WITNESS','REGISTRY_WITNESS'])
    active.push(epoch.checkpointObservations[0].witnesses[role].keyId);
  if(active.some(id=>revoked.includes(id)))
   errors.add('DW_REVOKED_ACTIVE_SIGNER_OR_OBSERVER_KEY');
 }
 let enrollmentVerified=0,revocationVerified=0;
 if(inputOK){
  enrollmentVerified=verifyPackets({
   packets:enrollmentPackets,roles:DW_ENROLLMENT_ROLES,
   pins:enrollmentPins,expected,clock,errors,code:'ENROLLMENT',
   extra:s=>s.observerPinDigestSha256===digestPins
  });
  revocationVerified=verifyPackets({
   packets:revocationPackets,roles:DW_REVOCATION_ROLES,
   pins:revocationPins,expected,clock,errors,code:'REVOCATION',
   extra:s=>stateOK&&s.currentVersion===revocationState.version&&
    s.previousVersion===revocationState.previousVersion&&
    s.previousDigestSha256===revocationState.previousDigestSha256&&
    Array.isArray(s.revokedKeyIds)&&
    JSON.stringify(s.revokedKeyIds)===
     JSON.stringify(revocationState.revokedKeyIds)&&
    s.observedAt===revocationState.observedAt
  });
 }
 const consistent=inputOK&&dvOK&&independent&&
  enrollmentVerified===2&&revocationVerified===2&&errors.size===0;
 return Object.freeze({
  phase:'1DW',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_ENROLLMENT_REVOCATION_CONSENSUS_HARD_HOLD',
  repository:REPO,
  dvSignedHistoryAndDualObserverCandidateReverifiedOnly:dvOK,
  twoEnrollmentSignaturesMathematicallyVerifiedOnly:enrollmentVerified,
  twoRevocationSignaturesMathematicallyVerifiedOnly:revocationVerified,
  candidateEnrollmentAndRevocationClaimsCorrelatedMathematicallyOnly:consistent,
  applicantControlledKeysPinsMandatesClockAndRevocationSources:true,
  observerKeyEnrollmentExternallyAuthenticated:false,
  externalArchiveRetrievalAndTlsChainAuthenticated:false,
  corporateRegistryLegalMandateIndependentlyAuthenticated:false,
  approvedProviderTrustChainAndLiveCrlOcspAuthenticated:false,
  persistentExternalRevocationAnchorWormCasAndDrVerified:false,
  independentOperatorGitHubStagingAndProductionApprovalVerified:false,
  outputsNoRawKeysRevocationListsOrSignatures:true,
  productionMutationOrCredentialEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
