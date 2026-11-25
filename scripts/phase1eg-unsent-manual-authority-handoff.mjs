import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES} from './phase1ec-offline-authority-handoff-custody.mjs';
import {EF_INDEPENDENT_AUTHORITY_ROLES,failureTranscriptDigestEf,
 quarantineCaseDigestEf,assessOfflineQuarantineEscalationEf}
 from './phase1ef-disconnected-quarantine-escalation.mjs';

// Phase 1EG: no network, transport, persistence, identity enrollment,
// third-party attestations, delegated authority or release action.
export const EG_MANUAL_EVIDENCE_REQUEST_TYPES=Object.freeze(Object.fromEntries([
 ['PROVIDER_WRITTEN_AGREEMENT','SIGNED_PROVIDER_LICENSE_REVIEW'],
 ['APPROVED_SANDBOX_CREDENTIAL_CUSTODY','SEPARATE_SECRETS_CUSTODY_REVIEW'],
 ['CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY','AUTHENTIC_ISSUER_POLICY_REVIEW'],
 ['LIVE_ISSUER_SIGNED_CRL_OCSP','AUTHENTIC_REVOCATION_REVIEW'],
 ['MCA_LEGAL_AND_SIGNATORY_MANDATE','MCA_SIGNATORY_MANDATE_REVIEW'],
 ['INDEPENDENT_KEY_ENROLLMENT','INDEPENDENT_KEY_REGISTRY_REVIEW'],
 ['AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES','SOURCE_TLS_SPKI_ARCHIVE_REVIEW'],
 ['WORM_CAS_SIGNED_ANTI_EQUIVOCATION','OFF_PLATFORM_WORM_CAS_REVIEW'],
 ['TRUSTED_TIMESTAMP_SOURCE','TRUSTED_TIME_SOURCE_REVIEW'],
 ['INDEPENDENT_DR_RESTORE_ACCEPTANCE','INDEPENDENT_RESTORE_REVIEW'],
 ['PROTECTED_MAIN_NONAUTHOR_REVIEWS','PROTECTED_MAIN_REVIEWER_QUORUM'],
 ['INDEPENDENT_STAGING_RELEASE_SIGNOFF','STAGING_INDEPENDENT_SIGNOFF']
]));
if(EC_AUTHORITY_GATES.length!==12||
 Object.keys(EG_MANUAL_EVIDENCE_REQUEST_TYPES).length!==12||
 EC_AUTHORITY_GATES.some(g=>!EG_MANUAL_EVIDENCE_REQUEST_TYPES[g]||
  !EF_INDEPENDENT_AUTHORITY_ROLES[g]))
 throw Error('EG_TWELVE_MANUAL_AUTHORITY_GATES_REQUIRED');
const DOMAIN='aaditech/phase1eg/unsent-manual-authority-request-v1\n';
const TOP=['previousQuarantineCandidate','requests','now'];
const EF_TOP=['previousFailureCandidate','cases','now'];
const REQUEST=['schemaVersion','kind','repository','gate','sequence',
 'failureTranscriptSha256','quarantineCaseSha256','previousRequestSha256',
 'requiredIndependentAuthorityRole','requestType','requestState',
 'manualIndependentAuthorityRequired','reviewerAuthenticated',
 'externalEvidenceVerified','requestDispatched','caseClosed',
 'autoRetryAllowed','networkRequests','sideEffects','releaseDecision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||
  Object.getPrototypeOf(x)===null);
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k)&&
  Object.hasOwn(Object.getOwnPropertyDescriptor(x,k),'value'));
const SHA=/^[0-9a-f]{64}$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,limit){
 try{
  const s=JSON.stringify(x);
  return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=limit;
 }catch{return false;}
}
function verifiedEf(ef,now){
 if(!EXACT(ef,EF_TOP)||ef.now!==now||!bounded(ef,4900*1024))
  return false;
 try{
  const report=assessOfflineQuarantineEscalationEf(ef);
  return report.fullOriginalEeToDuHistoryReverifiedMathematicallyOnly===true&&
   report.exactApplicantControlledQuarantineCases===12&&
   report.syntheticEscalationTranscriptConsistentOnly===true&&
   report.actualIndependentAuthorityCasesClosed===0&&
   report.productionReleaseBlocked===true&&
   report.productionReleaseAuthorized===false&&
   report.releaseDecision==='HOLD'&&report.anomalyCodes.length===0;
 }catch{return false;}
}
function validRequest(r){
 return EXACT(r,REQUEST)&&bounded(r,8192)&&
  r.schemaVersion===1&&r.kind==='UNSENT_MANUAL_AUTHORITY_HANDOFF_ONLY'&&
  r.repository===REPO&&Number.isInteger(r.sequence)&&
  r.sequence>=1&&r.sequence<=12&&
  r.gate===EC_AUTHORITY_GATES[r.sequence-1]&&
  r.requiredIndependentAuthorityRole===EF_INDEPENDENT_AUTHORITY_ROLES[r.gate]&&
  r.requestType===EG_MANUAL_EVIDENCE_REQUEST_TYPES[r.gate]&&
  SHA.test(r.failureTranscriptSha256)&&SHA.test(r.quarantineCaseSha256)&&
  SHA.test(r.previousRequestSha256)&&
  r.requestState==='NOT_SENT_NOT_APPROVED'&&
  r.manualIndependentAuthorityRequired===true&&
  r.reviewerAuthenticated===false&&r.externalEvidenceVerified===false&&
  r.requestDispatched===false&&r.caseClosed===false&&
  r.autoRetryAllowed===false&&r.networkRequests===0&&
  r.sideEffects===0&&r.releaseDecision==='HOLD';
}
export function manualRequestDigestEg(record){
 if(!validRequest(record))throw Error('EG_EXACT_UNSENT_REQUEST_REQUIRED');
 return hash(DOMAIN+canonical(record));
}
function deriveRequests(ef){
 const transcript=failureTranscriptDigestEf(ef.previousFailureCandidate);
 let predecessor=transcript;
 return Object.freeze(ef.cases.map((ticket,i)=>{
  const gate=EC_AUTHORITY_GATES[i];
  const request={
   schemaVersion:1,kind:'UNSENT_MANUAL_AUTHORITY_HANDOFF_ONLY',
   repository:REPO,gate,sequence:i+1,
   failureTranscriptSha256:transcript,
   quarantineCaseSha256:quarantineCaseDigestEf(ticket),
   previousRequestSha256:predecessor,
   requiredIndependentAuthorityRole:EF_INDEPENDENT_AUTHORITY_ROLES[gate],
   requestType:EG_MANUAL_EVIDENCE_REQUEST_TYPES[gate],
   requestState:'NOT_SENT_NOT_APPROVED',
   manualIndependentAuthorityRequired:true,
   reviewerAuthenticated:false,externalEvidenceVerified:false,
   requestDispatched:false,caseClosed:false,autoRetryAllowed:false,
   networkRequests:0,sideEffects:0,releaseDecision:'HOLD'
  };
  predecessor=manualRequestDigestEg(request);
  return Object.freeze(request);
 }));
}
export function createUnsentManualHandoffEg(previousQuarantineCandidate){
 if(!verifiedEf(previousQuarantineCandidate,previousQuarantineCandidate?.now))
  throw Error('EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED');
 return deriveRequests(previousQuarantineCandidate);
}
function hold(errors,original=false,count=0){
 return Object.freeze({
  phase:'1EG',schemaVersion:1,
  kind:'DISCONNECTED_UNSENT_MANUAL_AUTHORITY_HANDOFF_HARD_HOLD',
  repository:REPO,
  fullOriginalEfToDuHistoryReverifiedMathematicallyOnly:original,
  applicantControlledUnsentRequestsValidated:count,
  actualRequestsSent:0,
  actualIndependentReviewersAuthenticated:0,
  externalIssuerLegalOrProviderEvidenceVerified:false,
  independentRemoteCustodyOrAuditStorageVerified:false,
  autoRetryOrExternalIOPerformed:false,
  manualHandoffCannotActivateOrCloseCases:true,
  noRawSourceHashesOrSecretsReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessUnsentManualHandoffEg(input={}){
 const errors=new Set();
 if(!EXACT(input,TOP)||!bounded(input,5000*1024)){
  errors.add('EG_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {previousQuarantineCandidate:ef,requests,now}=input;
 const original=verifiedEf(ef,now);
 if(!original)errors.add('EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED');
 let expected=null;
 if(original)try{expected=deriveRequests(ef);}
 catch{errors.add('EG_ORIGINAL_EF_DERIVATION_FAILED');}
 if(!expected||!Array.isArray(requests)||requests.length!==12){
  errors.add('EG_EXACT_TWELVE_UNSENT_REQUESTS_REQUIRED');
  return hold(errors,original);
 }
 let count=0;
 for(let i=0;i<12;i++){
  const actual=requests[i],want=expected[i];
  if(!validRequest(actual)||
   REQUEST.some(key=>actual[key]!==want[key])){
   errors.add('EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
  }else count++;
 }
 return hold(errors,original,count);
}
