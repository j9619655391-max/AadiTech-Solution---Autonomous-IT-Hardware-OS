import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {canonical,REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';
import {EC_AUTHORITY_GATES} from './phase1ec-offline-authority-handoff-custody.mjs';
import {EE_PORT_FAILURE_CLASSES,sourceBundleDigestEe,planDigestEe,
 failureDigestEe,assessDisconnectedVersionFailureTaxonomyEe}
 from './phase1ee-disconnected-version-failure-taxonomy.mjs';

// Phase 1EF deliberately has no external IO, storage, credentials or release API.
// "Authority roles" below are unmet requirements, not enrolled reviewers.
export const EF_INDEPENDENT_AUTHORITY_ROLES=Object.freeze(Object.fromEntries([
 ['PROVIDER_WRITTEN_AGREEMENT','PROVIDER_CONTRACT_OFFICER'],
 ['APPROVED_SANDBOX_CREDENTIAL_CUSTODY','INDEPENDENT_SECRETS_CUSTODIAN'],
 ['CCA_RCAI_EMUDHRA_CHAIN_AND_POLICY','INDEPENDENT_CERTIFICATE_POLICY_REVIEWER'],
 ['LIVE_ISSUER_SIGNED_CRL_OCSP','INDEPENDENT_ISSUER_STATUS_REVIEWER'],
 ['MCA_LEGAL_AND_SIGNATORY_MANDATE','INDEPENDENT_CORPORATE_LEGAL_REVIEWER'],
 ['INDEPENDENT_KEY_ENROLLMENT','INDEPENDENT_SIGNER_CUSTODIAN'],
 ['AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES','INDEPENDENT_TLS_SOURCE_REVIEWER'],
 ['WORM_CAS_SIGNED_ANTI_EQUIVOCATION','INDEPENDENT_EXTERNAL_STORAGE_WITNESS'],
 ['TRUSTED_TIMESTAMP_SOURCE','INDEPENDENT_TRUSTED_TIME_REVIEWER'],
 ['INDEPENDENT_DR_RESTORE_ACCEPTANCE','INDEPENDENT_RECOVERY_OPERATOR'],
 ['PROTECTED_MAIN_NONAUTHOR_REVIEWS','INDEPENDENT_CODEOWNER_REVIEWERS'],
 ['INDEPENDENT_STAGING_RELEASE_SIGNOFF','INDEPENDENT_STAGING_APPROVERS']
]));
if(EC_AUTHORITY_GATES.length!==12||
 Object.keys(EF_INDEPENDENT_AUTHORITY_ROLES).length!==12||
 EC_AUTHORITY_GATES.some(g=>!EF_INDEPENDENT_AUTHORITY_ROLES[g]))
 throw Error('EF_TWELVE_INDEPENDENT_ROLE_REQUIREMENTS_REQUIRED');
const ROOT_DOMAIN='aaditech/phase1ef/local-fault-transcript-root-v1\n';
const CASE_DOMAIN='aaditech/phase1ef/applicant-quarantine-case-v1\n';
const TOP=['previousFailureCandidate','cases','now'];
const CASE=['schemaVersion','kind','repository','gate','sequence',
 'sourceBundleSha256','failureTranscriptSha256','versionPlanSha256',
 'faultEventSha256','previousCaseSha256','faultCode',
 'classification','requiredIndependentAuthorityRole','reviewerAuthenticated',
 'remoteEvidenceVerified','issuerOrLegalApprovalVerified',
 'caseStatus','retryPolicy','networkRequests','sideEffects',
 'closurePolicy','releaseDecision'];
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 (Object.getPrototypeOf(x)===Object.prototype||
  Object.getPrototypeOf(x)===null);
const EXACT=(x,keys)=>OWN(x)&&Object.keys(x).length===keys.length&&
 keys.every(k=>Object.hasOwn(x,k));
const HASH=x=>createHash('sha256').update(x).digest('hex');
function bounded(x,limit){
 try{return Buffer.byteLength(JSON.stringify(x),'utf8')<=limit;}
 catch{return false;}
}
function verifiedPrevious(ee,now){
 if(!OWN(ee)||!bounded(ee,4608*1024)||ee.now!==now)return false;
 try{
  const r=assessDisconnectedVersionFailureTaxonomyEe(ee);
  return r.syntheticVersionAndFailureTranscriptConsistentOnly===true&&
   r.precedingEdToDuOriginalHistoryReverifiedMathematicallyOnly===true&&
   r.exactlyPinnedV1ProtocolPlans===12&&
   r.linkedMockFailureEventsMathematicallyConsistentOnly===12&&
   r.productionReleaseBlocked===true&&
   r.productionReleaseAuthorized===false&&
   r.releaseDecision==='HOLD'&&r.anomalyCodes.length===0;
 }catch{return false;}
}
export function failureTranscriptDigestEf(ee){
 if(!OWN(ee)||!Array.isArray(ee.failureEvents)||
  ee.failureEvents.length!==12||!bounded(ee.failureEvents,120000))
  throw Error('EF_EXACT_TWELVE_LOCAL_FAILURES_REQUIRED');
 return HASH(ROOT_DOMAIN+canonical({
  repository:REPO,sourceBundleSha256:sourceBundleDigestEe(
   ee.previousPortCandidate),
  versionPlanSha256:ee.plans.map(planDigestEe),
  failureEventSha256:ee.failureEvents.map(failureDigestEe)
 }));
}
export function quarantineCaseDigestEf(record){
 if(!EXACT(record,CASE)||!bounded(record,8192))
  throw Error('EF_EXACT_QUARANTINE_CASE_REQUIRED');
 return HASH(CASE_DOMAIN+canonical(record));
}
function buildCases(ee){
 const source=sourceBundleDigestEe(ee.previousPortCandidate);
 const transcript=failureTranscriptDigestEf(ee);
 let preceding=transcript;
 return Object.freeze(EC_AUTHORITY_GATES.map((gate,i)=>{
  const event=ee.failureEvents[i],plan=ee.plans[i];
  const record={
   schemaVersion:1,kind:'APPLICANT_ONLY_OFFLINE_QUARANTINE_ESCALATION',
   repository:REPO,gate,sequence:i+1,
   sourceBundleSha256:source,failureTranscriptSha256:transcript,
   versionPlanSha256:planDigestEe(plan),
   faultEventSha256:failureDigestEe(event),
   previousCaseSha256:preceding,faultCode:event.faultCode,
   classification:event.faultCode==='NOT_ATTEMPTED'?
    'AWAITING_INDEPENDENT_AUTHORITY':
    'INJECTED_SIMULATED_FAULT_NOT_AUTHORITY',
   requiredIndependentAuthorityRole:EF_INDEPENDENT_AUTHORITY_ROLES[gate],
   reviewerAuthenticated:false,remoteEvidenceVerified:false,
   issuerOrLegalApprovalVerified:false,caseStatus:'OPEN_UNVERIFIED',
   retryPolicy:'MANUAL_REVIEW_ONLY_NO_AUTO_RETRY',
   networkRequests:0,sideEffects:0,
   closurePolicy:'NO_LOCAL_CASE_CLOSURE_OR_RELEASE',
   releaseDecision:'HOLD'
  };
  preceding=quarantineCaseDigestEf(record);
  return Object.freeze(record);
 }));
}
export function createOfflineQuarantineCasesEf(previousFailureCandidate){
 if(!verifiedPrevious(previousFailureCandidate,previousFailureCandidate?.now))
  throw Error('EF_FULL_ORIGINAL_EE_HISTORY_NOT_REVERIFIED');
 return buildCases(previousFailureCandidate);
}
function hold(errors,details={}){
 return Object.freeze({
  phase:'1EF',schemaVersion:1,
  kind:'DISCONNECTED_INDEPENDENT_AUTHORITY_ESCALATION_HARD_HOLD',
  repository:REPO,
  fullOriginalEeToDuHistoryReverifiedMathematicallyOnly:
   details.previous===true,
  exactApplicantControlledQuarantineCases:details.valid??0,
  notAttemptedAuthorityGates:details.pending??0,
  injectedSimulatedFaultCases:details.simulated??0,
  syntheticEscalationTranscriptConsistentOnly:details.consistent===true,
  actualIndependentAuthorityCasesClosed:0,
  independentReviewerOrProviderAuthenticated:false,
  externalIssuerOrLegalEvidenceVerified:false,
  externalNetworkOrAdapterExecutionPerformed:false,
  durableOffPlatformCaseOrAuditLogWritten:false,
  externalAuthorityGatesStillUnmet:true,
  localCasesCannotCloseOrUnfreezeProduction:true,
  noRawSignerSourceHashCaseIdOrEvidenceReturned:true,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessOfflineQuarantineEscalationEf(args={}){
 const errors=new Set();
 if(!EXACT(args,TOP)||!bounded(args,4800*1024)){
  errors.add('EF_EXACT_BOUNDED_INPUT_REQUIRED');return hold(errors);
 }
 const {previousFailureCandidate:ee,cases,now}=args;
 const prior=verifiedPrevious(ee,now);
 if(!prior)errors.add('EF_ORIGINAL_EE_HISTORY_NOT_REVERIFIED');
 let expected=null;
 if(prior)try{expected=buildCases(ee);}
 catch{errors.add('EF_SOURCE_OR_CASE_GENERATION_FAILED');}
 const shaped=Array.isArray(cases)&&cases.length===12&&!!expected;
 if(!shaped)errors.add('EF_EXACT_TWELVE_QUARANTINE_CASES_REQUIRED');
 let valid=0,pending=0,simulated=0;
 if(shaped)for(let i=0;i<12;i++){
  const record=cases[i],original=expected[i];
  if(!EXACT(record,CASE)||!bounded(record,8192)||
   canonical(record)!==canonical(original)||
   record.caseStatus!=='OPEN_UNVERIFIED'||
   record.reviewerAuthenticated!==false||
   record.remoteEvidenceVerified!==false||
   record.issuerOrLegalApprovalVerified!==false||
   record.releaseDecision!=='HOLD'||
   record.networkRequests!==0||record.sideEffects!==0||
   !EE_PORT_FAILURE_CLASSES[original.gate].includes(record.faultCode)){
   errors.add('EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');
   continue;
  }
  valid++;
  if(record.faultCode==='NOT_ATTEMPTED')pending++;
  else simulated++;
 }
 return hold(errors,{previous:prior,valid,pending,simulated,
  consistent:prior&&shaped&&valid===12&&errors.size===0});
}
