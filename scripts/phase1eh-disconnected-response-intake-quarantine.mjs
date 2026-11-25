import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES} from './phase1ec-offline-authority-handoff-custody.mjs';
import {EF_INDEPENDENT_AUTHORITY_ROLES}
 from './phase1ef-disconnected-quarantine-escalation.mjs';
import {manualRequestDigestEg,assessUnsentManualHandoffEg}
 from './phase1eg-unsent-manual-authority-handoff.mjs';

// Phase 1EH is purely disconnected applicant-controlled intake bookkeeping.
// An evidence hash is an untrusted CLAIM, never a reviewer identity, proof of
// dispatch, signed receipt, issuer authorization, real case closure or release.
const DOMAIN='aaditech/phase1eh/applicant-response-quarantine-v1\n';
const TOP=['previousHandoffCandidate','entries','now'];
const PREVIOUS=['previousQuarantineCandidate','requests','now'];
const RECORD=['schemaVersion','kind','repository','gate','sequence',
 'manualRequestSha256','previousIntakeSha256','claimedEvidenceSha256',
 'receiptState','requiredIndependentAuthorityRole',
 'reviewerAuthenticated','providerOrIssuerEvidenceVerified',
 'independentOffPlatformCustodyVerified','requestDispatched',
 'caseClosed','autoRetryAllowed','networkRequests','sideEffects',
 'releaseDecision'];
const SHA=/^[0-9a-f]{64}$/;
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||
  Object.getPrototypeOf(x)===null);
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k)&&
  Object.hasOwn(Object.getOwnPropertyDescriptor(x,k),'value'));
const hash=x=>createHash('sha256').update(x).digest('hex');
const validClaim=x=>x===null||(typeof x==='string'&&SHA.test(x));
function twelve(x){
 return Array.isArray(x)&&Object.getPrototypeOf(x)===Array.prototype&&
  x.length===12&&Object.keys(x).length===12&&
  Array.from({length:12},(_,i)=>
   Object.hasOwn(x,i)&&
   Object.hasOwn(Object.getOwnPropertyDescriptor(x,String(i)),'value'))
   .every(Boolean);
}
function bounded(x,max){
 try{const s=JSON.stringify(x);
  return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
 }catch{return false;}
}
function originalEg(eg,now){
 if(!EXACT(eg,PREVIOUS)||eg.now!==now||!bounded(eg,5300*1024))
  return false;
 try{
  const r=assessUnsentManualHandoffEg(eg);
  return r.fullOriginalEfToDuHistoryReverifiedMathematicallyOnly===true&&
   r.applicantControlledUnsentRequestsValidated===12&&
   r.actualRequestsSent===0&&r.actualIndependentReviewersAuthenticated===0&&
   r.manualHandoffCannotActivateOrCloseCases===true&&
   r.productionReleaseAuthorized===false&&r.productionReleaseBlocked===true&&
   r.releaseDecision==='HOLD'&&r.anomalyCodes.length===0;
 }catch{return false;}
}
function validEntry(e){
 return EXACT(e,RECORD)&&bounded(e,8192)&&
  e.schemaVersion===1&&
  e.kind==='UNTRUSTED_DISCONNECTED_RESPONSE_INTAKE_ONLY'&&
  e.repository===REPO&&Number.isInteger(e.sequence)&&
  e.sequence>=1&&e.sequence<=12&&
  e.gate===EC_AUTHORITY_GATES[e.sequence-1]&&
  e.requiredIndependentAuthorityRole===
   EF_INDEPENDENT_AUTHORITY_ROLES[e.gate]&&
  SHA.test(e.manualRequestSha256)&&SHA.test(e.previousIntakeSha256)&&
  validClaim(e.claimedEvidenceSha256)&&
  e.receiptState===(e.claimedEvidenceSha256===null?
   'NO_RESPONSE_OBSERVED':'APPLICANT_CLAIM_QUARANTINED')&&
  e.reviewerAuthenticated===false&&
  e.providerOrIssuerEvidenceVerified===false&&
  e.independentOffPlatformCustodyVerified===false&&
  e.requestDispatched===false&&e.caseClosed===false&&
  e.autoRetryAllowed===false&&e.networkRequests===0&&
  e.sideEffects===0&&e.releaseDecision==='HOLD';
}
export function applicantIntakeDigestEh(record){
 if(!validEntry(record))throw Error('EH_EXACT_QUARANTINED_ENTRY_REQUIRED');
 return hash(DOMAIN+canonical(record));
}
function derive(eg,claims){
 let predecessor=manualRequestDigestEg(eg.requests[11]);
 return Object.freeze(eg.requests.map((request,i)=>{
  const claim=claims[i],gate=EC_AUTHORITY_GATES[i];
  const entry={
   schemaVersion:1,kind:'UNTRUSTED_DISCONNECTED_RESPONSE_INTAKE_ONLY',
   repository:REPO,gate,sequence:i+1,
   manualRequestSha256:manualRequestDigestEg(request),
   previousIntakeSha256:predecessor,
   claimedEvidenceSha256:claim,
   receiptState:claim===null?'NO_RESPONSE_OBSERVED':
    'APPLICANT_CLAIM_QUARANTINED',
   requiredIndependentAuthorityRole:EF_INDEPENDENT_AUTHORITY_ROLES[gate],
   reviewerAuthenticated:false,providerOrIssuerEvidenceVerified:false,
   independentOffPlatformCustodyVerified:false,
   requestDispatched:false,caseClosed:false,autoRetryAllowed:false,
   networkRequests:0,sideEffects:0,releaseDecision:'HOLD'
  };
  predecessor=applicantIntakeDigestEh(entry);
  return Object.freeze(entry);
 }));
}
export function createQuarantinedManualIntakeEh(previousHandoffCandidate,
 claimedEvidenceDigests=Array(12).fill(null)){
 if(!originalEg(previousHandoffCandidate,previousHandoffCandidate?.now))
  throw Error('EH_ORIGINAL_EG_HISTORY_NOT_REVERIFIED');
 if(!twelve(claimedEvidenceDigests)||!claimedEvidenceDigests.every(validClaim))
  throw Error('EH_EXACT_TWELVE_CLAIMS_OR_ABSENCES_REQUIRED');
 return derive(previousHandoffCandidate,claimedEvidenceDigests);
}
function hold(errors,original=false,valid=0,claims=0){
 return Object.freeze({
  phase:'1EH',schemaVersion:1,
  kind:'DISCONNECTED_UNTRUSTED_RESPONSE_INTAKE_HARD_HOLD',
  repository:REPO,
  fullOriginalEgToDuHistoryReverifiedMathematicallyOnly:original,
  applicantControlledIntakeEntriesValidated:valid,
  applicantClaimedUnverifiedEvidenceHashes:claims,
  actualIndependentResponsesAuthenticated:0,
  requestsDispatched:0,realIssuerOrLegalAuthorityVerified:false,
  independentReviewerEnrollmentVerified:false,
  externalStorageOrTrustedTimeVerified:false,
  closureOrAutomaticRetryPermitted:false,
  noRawClaimedEvidenceHashesOrSourceIdentifiersReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessQuarantinedManualIntakeEh(input={}){
 const errors=new Set();
 if(!EXACT(input,TOP)||!bounded(input,5500*1024)){
  errors.add('EH_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {previousHandoffCandidate:eg,entries,now}=input;
 const original=originalEg(eg,now);
 if(!original)errors.add('EH_ORIGINAL_EG_HISTORY_NOT_REVERIFIED');
 if(!twelve(entries)){
  errors.add('EH_EXACT_TWELVE_INTAKE_ENTRIES_REQUIRED');
  return hold(errors,original);
 }
 const claims=entries.map(e=>EXACT(e,RECORD)?e.claimedEvidenceSha256:undefined);
 if(!claims.every(validClaim)){
  errors.add('EH_CLAIM_SCHEMA_OR_HASH_INVALID');
  return hold(errors,original);
 }
 let expected=null;
 if(original)try{expected=derive(eg,claims);}
 catch{errors.add('EH_SOURCE_OR_INTAKE_DERIVATION_FAILED');}
 if(!expected)return hold(errors,original);
 let valid=0,claimed=0;
 for(let i=0;i<12;i++){
  const actual=entries[i],want=expected[i];
  if(!validEntry(actual)||RECORD.some(k=>actual[k]!==want[k])){
   errors.add('EH_INTAKE_REPLAY_FALSE_AUTHORITY_OR_SOURCE_BINDING');
  }else{
   valid++;
   if(actual.claimedEvidenceSha256!==null)claimed++;
  }
 }
 return hold(errors,original,valid,claimed);
}
