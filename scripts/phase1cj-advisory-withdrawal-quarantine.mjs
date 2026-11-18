import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock} from './phase1bt-production-scope.mjs';

// Phase 1CJ: recognize the independent-adjudication requirement after a
// withdrawn/disputed GitHub advisory, without interpreting withdrawal as a
// vendor patch, zero-risk finding, global audit pass or production approval.
// This bridge only uses locally recorded public read-only CB/CH observations.
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const ADVISORY='GHSA-fc5q-39xc-vjpf';
const CVE='CVE-2026-112366';
const SHA=/^[0-9a-f]{40}$/;
const HEX=/^[0-9a-f]{64}$/;
const STATUSES=Object.freeze(['active','withdrawn','unavailable','invalid']);
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function timestamp(x){
 if(typeof x!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(x))
  return false;
 const n=Date.parse(x);
 return Number.isFinite(n)&&
  n>=Date.parse('2026-10-19T00:00:00Z')&&
  n<=Date.now()+300000;
}
function denial(errors,data={}){
 return Object.freeze({
  phase:'1CJ',schemaVersion:1,kind:'WITHDRAWN_ADVISORY_DISPUTE_INDEPENDENT_ADJUDICATION_HOLD',
  repository:REPO,advisoryId:ADVISORY,cveId:CVE,
  observedGithubLifecycle:data.github??'unavailable',
  observedOsvLifecycle:data.osv??'unavailable',
  officialPublicSourcesAvailable:data.publicSourcesAvailable??false,
  conflictingPublicLifecycleObserved:data.conflict??false,
  publiclyWithdrawnAdvisoryObserved:data.withdrawn??false,
  withdrawalQuarantinedForIndependentAdjudication:data.withdrawn??false,
  officialNpmStillSameUnpatchedLockedVersion:data.npmSame??false,
  localObserverReportsStructurallyConsistent:errors.size===0,
  anomalyCodes:Object.freeze([...errors].sort()),
  independentlyAuthenticatedVendorRebuttalOrTechnicalAdjudicationVerified:false,
  securityFindingReversedByIndependentAuthorizedReview:false,
  genuineSafeUpstreamPatchAndPublisherProvenanceVerified:false,
  globalZeroCriticalHighAuditIndependentlyPassed:false,
  effectiveProtectedMainSecurityAndBusinessReviewsVerified:false,
  externalProviderTrustAndMcaSignatoryAuthenticated:false,
  externallySignedWorkloadAndImmutableWormDrEvidenceVerified:false,
  advisoryWithdrawalAloneAuthorizesRiskAcceptance:false,
  auditSuppressionOrExceptionApplied:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function assessAdvisoryWithdrawalQuarantine({
 cbReport=null,chReport=null,lock=null,baseline=null,environment={}
}={}){
 const errors=new Set();
 const cb=cbReport?.assessment,ch=chReport?.assessment;
 const github=cb?.githubLifecycleState,osv=cb?.osvLifecycleState;
 const knownState=v=>STATUSES.includes(v);
 if(!obj(cbReport)||!obj(cb)||
   cb.phase!=='1CB'||cb.schemaVersion!==1||
   cb.kind!=='UNSIGNED_PUBLIC_ADVISORY_OBSERVATION_HOLD'||
   cb.githubEndpoint!=='https://api.github.com/advisories/'+ADVISORY||
   cb.osvEndpoint!=='https://api.osv.dev/v1/vulns/'+ADVISORY||
   !knownState(github)||!knownState(osv)||
   cb.withdrawnAdvisoryNotEquivalentToFixedVersion!==true||
   cb.productionReleaseAuthorized!==false||
   cb.productionReleaseBlocked!==true||cb.releaseDecision!=='HOLD'||
   !Array.isArray(cb.anomalyCodes))
  errors.add('CJ_CANNOT_TRUST_PRECEDING_PUBLIC_ADVISORY_OBSERVER');
 const fetched=cbReport?.fetchOutcome,hashes={
  github:cb?.githubSourceContentSha256,osv:cb?.osvSourceContentSha256
 };
 for(const [key,state] of [['github',github],['osv',osv]]){
  const outcome=fetched?.[key];
  if(!['SUCCESS','UNAVAILABLE_OR_REJECTED'].includes(outcome)||
    (outcome==='SUCCESS'&&!HEX.test(hashes[key]??''))||
    (outcome==='UNAVAILABLE_OR_REJECTED'&&hashes[key]!==null)||
    (outcome==='UNAVAILABLE_OR_REJECTED'&&state!=='unavailable')||
    (outcome==='SUCCESS'&&state==='unavailable'))
   errors.add('CJ_PUBLIC_'+key.toUpperCase()+'_FETCH_OR_DIGEST_DISAGREEMENT');
 }
 for(const [key,state,value] of [
  ['GITHUB',github,cb?.githubWithdrawnAt],['OSV',osv,cb?.osvWithdrawnAt]]){
  if(state==='withdrawn'&&!timestamp(value))
   errors.add('CJ_'+key+'_WITHDRAWAL_TIME_MISSING_OR_INVALID');
  if(state!=='withdrawn'&&value!==null)
   errors.add('CJ_'+key+'_WITHDRAWAL_STATE_INCONSISTENT');
 }
 const withdrawn=github==='withdrawn'||osv==='withdrawn';
 const lifecycleConflict=(github==='withdrawn'&&osv==='active')||
   (github==='active'&&osv==='withdrawn');
 if(lifecycleConflict&&!cb?.anomalyCodes?.includes('CB_PUBLIC_ADVISORY_LIFECYCLE_DISAGREEMENT'))
  errors.add('CJ_WITHDRAWAL_CONFLICT_MISSING_UPSTREAM_ANOMALY');
 if(github==='withdrawn'&&!cb?.anomalyCodes?.includes('CB_GITHUB_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION'))
  errors.add('CJ_WITHDRAWAL_NOT_ACKNOWLEDGED_BY_GITHUB_OBSERVER');
 if(osv==='withdrawn'&&!cb?.anomalyCodes?.includes('CB_OSV_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION'))
  errors.add('CJ_WITHDRAWAL_NOT_ACKNOWLEDGED_BY_OSV_OBSERVER');
 if(withdrawn&&cb?.twoPublicFeedsDescribeCurrentUnpatchedRange!==false)
  errors.add('CJ_WITHDRAWAL_FALSIFIED_AS_TWO_ACTIVE_UNPATCHED_FEEDS');
 if(!withdrawn&&github==='active'&&osv==='active'&&
    cb?.twoPublicFeedsDescribeCurrentUnpatchedRange===true&&
    cb?.anomalyCodes?.length!==0)
  errors.add('CJ_ACTIVE_TWO_FEEDS_CLAIM_CONTRADICTS_ANOMALIES');
 if(!obj(chReport)||!obj(ch)||
    ch.phase!=='1CH'||ch.schemaVersion!==1||
    ch.kind!=='PUBLIC_NPM_UPSTREAM_GHSA_OSV_UNPATCHED_OBSERVER_HOLD'||
    ch.productionReleaseAuthorized!==false||
    ch.productionReleaseBlocked!==true||
    ch.releaseDecision!=='HOLD'||
    ch.actualPatchedPicomatchReleaseVerified!==false||
    ch.globalZeroCriticalHighAuditPassed!==false||
    !Array.isArray(ch.anomalyCodes)||
    !['SUCCESS','UNAVAILABLE_OR_REJECTED'].includes(chReport?.fetchOutcome?.npm)||
    !['SUCCESS','UNAVAILABLE_OR_REJECTED'].includes(chReport?.fetchOutcome?.release))
  errors.add('CJ_UPSTREAM_VENDOR_PUBLICATION_REPORT_INVALID');
 if(ch?.exactPublicAdvisoriesReportUnpatchedRange===true&&
    cb?.twoPublicFeedsDescribeCurrentUnpatchedRange!==true)
  errors.add('CJ_VENDOR_SOURCE_MISREPRESENTED_WITHDRAWN_ADVISORY_AS_ACTIVE');
 if(ch?.latestNpmVersion!==null&&ch?.latestNpmVersion!=='4.0.7')
  errors.add('CJ_UPSTREAM_VERSION_CHANGED_REQUIRES_REAL_INDEPENDENT_PATCH_REVIEW');
 if(ch?.lockedPicomatchVersion!=='picomatch@4.0.7'||
    ch?.latestNpmVersion==='4.0.7'&&
    ch?.lockedArtifactIntegrityAgreesWithRegistry!==true)
  errors.add('CJ_FROZEN_LOCK_PUBLISHER_SOURCE_MISMATCH');
 const locked=lock?.packages?.picomatch;
 if(!Array.isArray(locked)||locked[0]!=='picomatch@4.0.7'||
    !/^sha512-[A-Za-z0-9+/]{86}==$/.test(locked[3]??''))
  errors.add('CJ_FROZEN_LOCK_VULNERABILITY_SOURCE_CHANGED');
 const entry=baseline?.advisories?.find?.(x=>x?.id===ADVISORY);
 if(!obj(baseline)||baseline.schemaVersion!==1||
    baseline.kind!=='known-unresolved-development-only'||
    !Array.isArray(baseline.advisories)||
    baseline.advisories.filter(x=>x?.id===ADVISORY).length!==1||
    entry?.packageName!=='picomatch'||entry?.severity!=='high'||
    entry?.independentSecurityApproval!=='PENDING')
  errors.add('CJ_RISK_BASELINE_SEVERITY_OR_AUTHORIZATION_WEAKENED');
 if(!obj(environment)||environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_JOB!=='review-vendor-intake-hold'||
    environment.GITHUB_REPOSITORY!==REPO||
    !SHA.test(environment.GITHUB_SHA??'')||
    !/^(?:refs\/pull\/1\/merge|refs\/heads\/chore\/phase0-foundation-20261106)$/.test(environment.GITHUB_REF??''))
  errors.add('CJ_UNVERIFIED_GITHUB_ACTIONS_RUN_CONTEXT');
 return denial(errors,{
  github:knownState(github)?github:'invalid',
  osv:knownState(osv)?osv:'invalid',
  publicSourcesAvailable:
   fetched?.github==='SUCCESS'&&fetched?.osv==='SUCCESS',
  conflict:lifecycleConflict,
  withdrawn,
  npmSame:ch?.latestNpmVersion==='4.0.7'&&
    ch?.lockedArtifactIntegrityAgreesWithRegistry===true
 });
}
function read(path,max){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>max)
  throw Error('CJ unsafe or missing local public hold source');
 return JSON.parse(readFileSync(path,'utf8'));
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CJ only supports zero-secret read-only --ci-hold');
 const verdict=assessAdvisoryWithdrawalQuarantine({
  cbReport:read('phase1cb-public-advisory-hold.json',262144),
  chReport:read('phase1ch-publisher-remediation-hold.json',262144),
  lock:readBunLock(readFileSync('bun.lock','utf8')),
  baseline:read('docs/security/dependency-advisory-baseline.json',65536),
  environment:process.env
 });
 writeFileSync('phase1cj-withdrawn-advisory-quarantine-hold.json',
  JSON.stringify(verdict,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(verdict,null,2));
 // A malformed local observer chain should fail the intake job, but a real
 // public 404, withdrawal or conflicting feed is an observed HOLD, not
 // something that can be waived by switching sources or returning green.
 if(!verdict.localObserverReportsStructurallyConsistent||
    verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||verdict.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('CJ public advisory withdrawal quarantine invalid:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
