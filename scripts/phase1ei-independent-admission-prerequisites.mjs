import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES} from './phase1ec-offline-authority-handoff-custody.mjs';
import {EF_INDEPENDENT_AUTHORITY_ROLES}
 from './phase1ef-disconnected-quarantine-escalation.mjs';
import {applicantIntakeDigestEh,assessQuarantinedManualIntakeEh}
 from './phase1eh-disconnected-response-intake-quarantine.mjs';

// Phase 1EI specifies future independently authenticated admission checks.
// It DOES NOT implement any live connector, signed approval, network call,
// actual admission, case closure, legal finding, release or source unfreeze.
const REQUIREMENTS=[
 ['PROVIDER_WRITTEN_AGREEMENT',
  'PROVIDER_EXECUTED_SANDBOX_LICENSE',
  'INDEPENDENT_PROVIDER_OFFICER_CONTRACT_CONFIRMATION',
  'SEPARATE_LEGAL_ARCHIVE_AND_LICENSE_SCOPE'],
 ['APPROVED_SANDBOX_CREDENTIAL_CUSTODY',
  'AUTHORIZED_SECRET_MANAGER_ENROLLMENT',
  'INDEPENDENT_SECURITY_CUSTODIAN_ATTESTATION',
  'APPROVED_SECRET_MANAGER_NO_CHAT_OR_GIT'],
 ['CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY',
  'AUTHENTIC_CCA_CA_CHAIN_AND_ISSUER_CPS',
  'EXTERNALLY_ANCHORED_POLICY_EKU_PATH_VALIDATION',
  'PINNED_ISSUER_CHAIN_AND_TRUST_POLICY_ARCHIVE'],
 ['LIVE_ISSUER_SIGNED_CRL_OCSP',
  'CURRENT_ISSUER_SIGNED_SERIAL_STATUS',
  'CRL_OCSP_SIGNATURE_NONCE_SERIAL_FRESHNESS_CHECK',
  'INDEPENDENT_STATUS_EVIDENCE_AND_TIME_ARCHIVE'],
 ['MCA_LEGAL_AND_SIGNATORY_MANDATE',
  'MCA_COMPANY_RECORD_AND_SIGNATORY_MANDATE',
  'INDEPENDENT_MCA_AND_AUTHORIZED_SIGNER_CHECK',
  'SEPARATE_LEGAL_RECORD_AND_BOARD_AUTHORITY'],
 ['INDEPENDENT_KEY_ENROLLMENT',
  'REVIEWER_WITNESS_KEY_APPOINTMENT_RECORD',
  'OUT_OF_BAND_KEY_OWNER_ROLE_REVOCATION_CHECK',
  'INDEPENDENT_WITNESS_REGISTRY_AND_REVOCATION'],
 ['AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES',
  'INDEPENDENT_SOURCE_TLS_ARCHIVE_RECEIPT',
  'ALLOWLIST_TLS_SPKI_ORIGIN_AND_BYTES_CHECK',
  'OFF_PLATFORM_CONTENT_ADDRESSED_SOURCE_ARCHIVE'],
 ['WORM_CAS_SIGNED_ANTI_EQUIVOCATION',
  'IMMUTABLE_STORAGE_CAS_GOSSIP_RECEIPT',
  'INDEPENDENT_OBJECT_LOCK_AND_FORK_DETECTION',
  'OFF_PLATFORM_WORM_CAS_RETENTION_PROOF'],
 ['TRUSTED_TIMESTAMP_SOURCE',
  'TRUSTED_TIMESTAMP_ATTESTATION',
  'EXTERNAL_TIMESTAMP_CHAIN_FRESHNESS_CHECK',
  'INDEPENDENT_TRUSTED_TIME_SOURCE_ARCHIVE'],
 ['INDEPENDENT_DR_RESTORE_ACCEPTANCE',
  'ISOLATED_DISPOSABLE_RESTORE_ACCEPTANCE',
  'INDEPENDENT_OPERATOR_RTO_RPO_RESTORE_CHECK',
  'OFF_PLATFORM_RESTORE_LOG_AND_OPERATOR_SIGNOFF'],
 ['PROTECTED_MAIN_NONAUTHOR_REVIEWS',
  'PROTECTED_MAIN_EXACT_HEAD_REVIEW_RECORDS',
  'RULESET_NO_BYPASS_AND_TWO_NONAUTHOR_REVIEWS',
  'INDEPENDENT_GITHUB_CHECKS_REVIEWS_SNAPSHOT'],
 ['INDEPENDENT_STAGING_RELEASE_SIGNOFF',
  'STAGING_SECURITY_BUSINESS_OPERATIONS_APPROVALS',
  'INDEPENDENT_SOURCE_BUILD_ENVIRONMENT_ACCEPTANCE',
  'SIGNED_STAGING_RELEASE_AND_ROLLBACK_ARCHIVE']
];
export const EI_GATE_REQUIREMENTS=Object.freeze(Object.fromEntries(
 REQUIREMENTS.map(([gate,requiredArtifact,verificationMethod,custodyRequirement])=>
  [gate,Object.freeze({requiredArtifact,verificationMethod,custodyRequirement})])
));
if(EC_AUTHORITY_GATES.length!==12||
 Object.keys(EI_GATE_REQUIREMENTS).length!==12||
 EC_AUTHORITY_GATES.some(g=>!EI_GATE_REQUIREMENTS[g]||
  !EF_INDEPENDENT_AUTHORITY_ROLES[g]))
 throw Error('EI_EXACT_TWELVE_INDEPENDENT_GATES_REQUIRED');

const DOMAIN='aaditech/phase1ei/independent-admission-prerequisites-v1\n';
const TOP=['previousIntakeCandidate','prerequisites','now'];
const EH_TOP=['previousHandoffCandidate','entries','now'];
const RECORD=['schemaVersion','kind','repository','gate','sequence',
 'quarantinedIntakeSha256','previousPrerequisiteSha256',
 'requiredIndependentAuthorityRole','requiredArtifact',
 'verificationMethod','custodyRequirement','applicantClaimState',
 'admissionStatus','independentReviewerAuthenticated',
 'independentSourceBytesRetrieved','externalSignatureOrMandateVerified',
 'freshRevocationAndTrustedTimeVerified','offPlatformCustodyVerified',
 'requestDispatched','caseClosed','autoRetryAllowed','networkRequests',
 'sideEffects','releaseDecision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||
  Object.getPrototypeOf(x)===null);
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k)&&
  Object.hasOwn(Object.getOwnPropertyDescriptor(x,k),'value'));
function twelve(x){
 return Array.isArray(x)&&Object.getPrototypeOf(x)===Array.prototype&&
  x.length===12&&Object.keys(x).length===12&&
  Array.from({length:12},(_,i)=>
   Object.hasOwn(x,i)&&
   Object.hasOwn(Object.getOwnPropertyDescriptor(x,String(i)),'value'))
   .every(Boolean);
}
const SHA=/^[a-f0-9]{64}$/;
const hash=s=>createHash('sha256').update(s).digest('hex');
function bounded(x,max){
 try{
  const data=JSON.stringify(x);
  return typeof data==='string'&&Buffer.byteLength(data,'utf8')<=max;
 }catch{return false;}
}
function originalEh(eh,now){
 if(!EXACT(eh,EH_TOP)||eh.now!==now||!bounded(eh,5600*1024))
  return false;
 try{
  const r=assessQuarantinedManualIntakeEh(eh);
  return r.fullOriginalEgToDuHistoryReverifiedMathematicallyOnly===true&&
   r.applicantControlledIntakeEntriesValidated===12&&
   r.actualIndependentResponsesAuthenticated===0&&
   r.requestsDispatched===0&&
   r.closureOrAutomaticRetryPermitted===false&&
   r.productionReleaseAuthorized===false&&
   r.productionReleaseBlocked===true&&
   r.releaseDecision==='HOLD'&&r.anomalyCodes.length===0;
 }catch{return false;}
}
function validRecord(e){
 if(!EXACT(e,RECORD)||!bounded(e,8192))return false;
 const requirement=EI_GATE_REQUIREMENTS[e.gate];
 return e.schemaVersion===1&&
  e.kind==='OFFLINE_UNFILLED_EXTERNAL_EVIDENCE_PREREQUISITE'&&
  e.repository===REPO&&Number.isInteger(e.sequence)&&
  e.sequence>=1&&e.sequence<=12&&
  e.gate===EC_AUTHORITY_GATES[e.sequence-1]&&
  !!requirement&&SHA.test(e.quarantinedIntakeSha256)&&
  SHA.test(e.previousPrerequisiteSha256)&&
  e.requiredIndependentAuthorityRole===
   EF_INDEPENDENT_AUTHORITY_ROLES[e.gate]&&
  e.requiredArtifact===requirement.requiredArtifact&&
  e.verificationMethod===requirement.verificationMethod&&
  e.custodyRequirement===requirement.custodyRequirement&&
  ['NO_RESPONSE_OBSERVED','APPLICANT_CLAIM_QUARANTINED'].includes(
   e.applicantClaimState)&&
  e.admissionStatus==='NOT_ADMITTED_EXTERNAL_PROOF_REQUIRED'&&
  e.independentReviewerAuthenticated===false&&
  e.independentSourceBytesRetrieved===false&&
  e.externalSignatureOrMandateVerified===false&&
  e.freshRevocationAndTrustedTimeVerified===false&&
  e.offPlatformCustodyVerified===false&&
  e.requestDispatched===false&&e.caseClosed===false&&
  e.autoRetryAllowed===false&&e.networkRequests===0&&
  e.sideEffects===0&&e.releaseDecision==='HOLD';
}
export function prerequisiteDigestEi(entry){
 if(!validRecord(entry))throw Error('EI_EXACT_UNFILLED_PREREQUISITE_REQUIRED');
 return hash(DOMAIN+canonical(entry));
}
function derive(eh){
 let predecessor=applicantIntakeDigestEh(eh.entries[11]);
 return Object.freeze(eh.entries.map((intake,i)=>{
  const gate=EC_AUTHORITY_GATES[i],req=EI_GATE_REQUIREMENTS[gate];
  const entry={
   schemaVersion:1,kind:'OFFLINE_UNFILLED_EXTERNAL_EVIDENCE_PREREQUISITE',
   repository:REPO,gate,sequence:i+1,
   quarantinedIntakeSha256:applicantIntakeDigestEh(intake),
   previousPrerequisiteSha256:predecessor,
   requiredIndependentAuthorityRole:EF_INDEPENDENT_AUTHORITY_ROLES[gate],
   requiredArtifact:req.requiredArtifact,
   verificationMethod:req.verificationMethod,
   custodyRequirement:req.custodyRequirement,
   applicantClaimState:intake.receiptState,
   admissionStatus:'NOT_ADMITTED_EXTERNAL_PROOF_REQUIRED',
   independentReviewerAuthenticated:false,
   independentSourceBytesRetrieved:false,
   externalSignatureOrMandateVerified:false,
   freshRevocationAndTrustedTimeVerified:false,
   offPlatformCustodyVerified:false,
   requestDispatched:false,caseClosed:false,autoRetryAllowed:false,
   networkRequests:0,sideEffects:0,releaseDecision:'HOLD'
  };
  predecessor=prerequisiteDigestEi(entry);
  return Object.freeze(entry);
 }));
}
export function createIndependentAdmissionPrerequisitesEi(previousIntakeCandidate){
 if(!originalEh(previousIntakeCandidate,previousIntakeCandidate?.now))
  throw Error('EI_ORIGINAL_EH_HISTORY_NOT_REVERIFIED');
 return derive(previousIntakeCandidate);
}
function hold(errors,sourceVerified=false,validCount=0){
 return Object.freeze({
  phase:'1EI',schemaVersion:1,
  kind:'OFFLINE_EXTERNAL_EVIDENCE_ADMISSION_PREREQUISITES_HARD_HOLD',
  repository:REPO,
  fullOriginalEhToDuHistoryReverifiedMathematicallyOnly:sourceVerified,
  exactApplicantControlledPrerequisitesValidated:validCount,
  independentExternalEvidenceGatesStillUnfilled:12,
  claimedApplicantDigestsNeverAdmitted:true,
  actualIndependentEvidenceAuthenticated:0,
  independentApprovalOrCaseClosurePossible:false,
  dispatchNetworkProviderOrCredentialsActivated:false,
  offPlatformWormTrustedTimeDrStagingAccepted:false,
  noRawEvidenceHashesOrSourceIdentifiersReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessIndependentAdmissionPrerequisitesEi(input={}){
 const errors=new Set();
 if(!EXACT(input,TOP)||!bounded(input,5900*1024)){
  errors.add('EI_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {previousIntakeCandidate:eh,prerequisites,now}=input;
 const original=originalEh(eh,now);
 if(!original)errors.add('EI_ORIGINAL_EH_HISTORY_NOT_REVERIFIED');
 if(!twelve(prerequisites)){
  errors.add('EI_EXACT_TWELVE_PREREQUISITES_REQUIRED');
  return hold(errors,original);
 }
 let expected=null;
 if(original)try{expected=derive(eh);}
 catch{errors.add('EI_PRIOR_INTAKE_DERIVATION_FAILED');}
 if(!expected)return hold(errors,original);
 let count=0;
 for(let i=0;i<12;i++){
  const actual=prerequisites[i],want=expected[i];
  if(!validRecord(actual)||RECORD.some(k=>actual[k]!==want[k]))
   errors.add('EI_PREREQUISITE_SOURCE_REPLAY_OR_FALSE_EXTERNAL_AUTHORITY');
  else count++;
 }
 return hold(errors,original,count);
}
