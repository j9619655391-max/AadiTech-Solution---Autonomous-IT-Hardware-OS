import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {assessUpstreamAdvisory}
 from '../scripts/phase1cb-public-advisory-observer.mjs';
import {assessPublisherRemediation}
 from '../scripts/phase1ch-upstream-patch-publication-preflight.mjs';
import {assessAdvisoryWithdrawalQuarantine}
 from '../scripts/phase1cj-advisory-withdrawal-quarantine.mjs';

const lock=readBunLock(readFileSync('bun.lock','utf8'));
const baseline=JSON.parse(readFileSync('docs/security/dependency-advisory-baseline.json','utf8'));
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DATE='2026-11-18T10:00:00.000Z';
const env={GITHUB_ACTIONS:'true',GITHUB_JOB:'review-vendor-intake-hold',
 GITHUB_REPOSITORY:REPO,GITHUB_SHA:'a'.repeat(40),
 GITHUB_REF:'refs/pull/1/merge',CI:'true'};
const gh={
 ghsa_id:'GHSA-fc5q-39xc-vjpf',cve_id:'CVE-2026-112366',
 severity:'high',updated_at:'2026-11-18T10:30:00.000Z',
 vulnerabilities:[{package:{ecosystem:'npm',name:'picomatch'},
  vulnerable_version_range:'<= 4.0.7',first_patched_version:null}]
};
const os={
 id:'GHSA-fc5q-39xc-vjpf',aliases:['CVE-2026-112366'],
 modified:'2026-11-18T10:30:00.000Z',
 database_specific:{severity:'HIGH'},
 affected:[{package:{ecosystem:'npm',name:'picomatch'},
  ranges:[{type:'SEMVER',events:[{introduced:'0'},{last_affected:'4.0.7'}]}]}]
};
function fixture({github=gh,osv=os}={}){
 const cbReport={
  assessment:assessUpstreamAdvisory({github,osv,lock,environment:env}),
  fetchOutcome:{
   github:github===null?'UNAVAILABLE_OR_REJECTED':'SUCCESS',
   osv:osv===null?'UNAVAILABLE_OR_REJECTED':'SUCCESS'
  }
 };
 const chReport={assessment:assessPublisherRemediation({
  cbReport,lock,environment:env,
  npmLatest:{name:'picomatch',version:'4.0.7',dist:{
   tarball:'https://registry.npmjs.org/picomatch/-/picomatch-4.0.7.tgz',
   integrity:lock.packages.picomatch[3]}},
  upstreamRelease:{tag_name:'v4.0.7',draft:false,prerelease:false,
   published_at:'2026-08-24T00:00:00Z',
   html_url:'https://github.com/micromatch/picomatch/releases/tag/v4.0.7'}
 }),fetchOutcome:{npm:'SUCCESS',release:'SUCCESS'}};
 return {cbReport,chReport,lock,baseline,environment:env};
}
const verdict=x=>assessAdvisoryWithdrawalQuarantine(x);
const check=(r,c)=>assert.ok(r.anomalyCodes.includes(c),r.anomalyCodes.join(','));
test('CJ: two historically active public feeds are still NOT production/security GO',()=>{
 const r=verdict(fixture());
 assert.equal(r.localObserverReportsStructurallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.observedGithubLifecycle,'active');
 assert.equal(r.observedOsvLifecycle,'active');
 assert.equal(r.publiclyWithdrawnAdvisoryObserved,false);
 assert.equal(r.officialNpmStillSameUnpatchedLockedVersion,true);
 for(const name of ['independentlyAuthenticatedVendorRebuttalOrTechnicalAdjudicationVerified',
  'securityFindingReversedByIndependentAuthorizedReview',
  'genuineSafeUpstreamPatchAndPublisherProvenanceVerified',
  'globalZeroCriticalHighAuditIndependentlyPassed',
  'effectiveProtectedMainSecurityAndBusinessReviewsVerified',
  'externalProviderTrustAndMcaSignatoryAuthenticated',
  'externallySignedWorkloadAndImmutableWormDrEvidenceVerified',
  'advisoryWithdrawalAloneAuthorizesRiskAcceptance',
  'auditSuppressionOrExceptionApplied','productionReleaseAuthorized'])
  assert.equal(r[name],false,name);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CJ: GitHub advisory withdrawn Nov 18 while OSV active => quarantine source disagreement',()=>{
 const r=verdict(fixture({github:{...gh,withdrawn_at:DATE}}));
 assert.equal(r.localObserverReportsStructurallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.publiclyWithdrawnAdvisoryObserved,true);
 assert.equal(r.conflictingPublicLifecycleObserved,true);
 assert.equal(r.withdrawalQuarantinedForIndependentAdjudication,true);
 assert.equal(r.observedOsvLifecycle,'active');
 assert.equal(r.globalZeroCriticalHighAuditIndependentlyPassed,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CJ: both upstream feeds withdrawn STILL do not certify a safe patched package',()=>{
 const r=verdict(fixture({github:{...gh,withdrawn_at:DATE},
  osv:{...os,withdrawn:DATE}}));
 assert.equal(r.localObserverReportsStructurallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.conflictingPublicLifecycleObserved,false);
 assert.equal(r.publiclyWithdrawnAdvisoryObserved,true);
 assert.equal(r.independentlyAuthenticatedVendorRebuttalOrTechnicalAdjudicationVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CJ: missing GHSA, OSV and both public feeds produce UNKNOWN, not green release',()=>{
 for(const variant of [
  {github:null},{osv:null},{github:null,osv:null}]){
  const r=verdict(fixture(variant));
  assert.equal(r.localObserverReportsStructurallyConsistent,true,r.anomalyCodes.join(','));
  assert.equal(r.officialPublicSourcesAvailable,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CJ: forged withdrawal without source CB anomaly is rejected as corrupted custody',()=>{
 const x=fixture({github:{...gh,withdrawn_at:DATE}});
 x.cbReport.assessment={...x.cbReport.assessment,anomalyCodes:[]};
 check(verdict(x),'CJ_WITHDRAWAL_CONFLICT_MISSING_UPSTREAM_ANOMALY');
 check(verdict(x),'CJ_WITHDRAWAL_NOT_ACKNOWLEDGED_BY_GITHUB_OBSERVER');
});
test('CJ: withdrawn advisory cannot simultaneously claim both active unpatched feeds',()=>{
 const x=fixture({github:{...gh,withdrawn_at:DATE}});
 x.cbReport.assessment={...x.cbReport.assessment,
  twoPublicFeedsDescribeCurrentUnpatchedRange:true};
 check(verdict(x),'CJ_WITHDRAWAL_FALSIFIED_AS_TWO_ACTIVE_UNPATCHED_FEEDS');
});
test('CJ: vendor CH report cannot override GHSA/OSV discrepancy or claim active range',()=>{
 const x=fixture({github:{...gh,withdrawn_at:DATE}});
 x.chReport.assessment={...x.chReport.assessment,
  exactPublicAdvisoriesReportUnpatchedRange:true};
 check(verdict(x),'CJ_VENDOR_SOURCE_MISREPRESENTED_WITHDRAWN_ADVISORY_AS_ACTIVE');
});
test('CJ: fake vendor fix, bypassed global audit, or released production status is rejected',()=>{
 for(const fields of [
  {actualPatchedPicomatchReleaseVerified:true},
  {globalZeroCriticalHighAuditPassed:true},
  {productionReleaseAuthorized:true},
  {productionReleaseBlocked:false},
  {releaseDecision:'GO'}
 ]){
  const x=fixture();x.chReport.assessment={...x.chReport.assessment,...fields};
  check(verdict(x),'CJ_UPSTREAM_VENDOR_PUBLICATION_REPORT_INVALID');
  assert.equal(verdict(x).productionReleaseAuthorized,false);
 }
});
test('CJ: missing or forged SHA-256 upstream public content hash is rejected',()=>{
 for(const key of ['github','osv']){
  const x=fixture();x.cbReport.assessment={...x.cbReport.assessment,
   [key==='github'?'githubSourceContentSha256':'osvSourceContentSha256']:'invalid'};
  check(verdict(x),'CJ_PUBLIC_'+key.toUpperCase()+'_FETCH_OR_DIGEST_DISAGREEMENT');
 }
});
test('CJ: unavailable feed status with fake successful checksum or lifecycle state is rejected',()=>{
 const x=fixture({github:null});
 x.cbReport.fetchOutcome.github='UNAVAILABLE_OR_REJECTED';
 x.cbReport.assessment={...x.cbReport.assessment,
  githubLifecycleState:'withdrawn',githubWithdrawnAt:DATE};
 check(verdict(x),'CJ_PUBLIC_GITHUB_FETCH_OR_DIGEST_DISAGREEMENT');
});
test('CJ: fake withdrawal dates and inconsistent state are not accepted',()=>{
 for(const changes of [
  {githubLifecycleState:'withdrawn',githubWithdrawnAt:'2001-01-01T00:00:00Z'},
  {githubLifecycleState:'active',githubWithdrawnAt:DATE},
  {osvLifecycleState:'withdrawn',osvWithdrawnAt:'never'},
  {osvLifecycleState:'active',osvWithdrawnAt:DATE}
 ]){
  const x=fixture();x.cbReport.assessment={...x.cbReport.assessment,...changes};
  const r=verdict(x);
  assert.equal(r.localObserverReportsStructurallyConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CJ: forged active CB with unrecognized schema or claimed release GO rejected',()=>{
 for(const fields of [
  {phase:'OTHER'},{schemaVersion:2},{releaseDecision:'GO'},
  {productionReleaseAuthorized:true},{productionReleaseBlocked:false},
  {withdrawnAdvisoryNotEquivalentToFixedVersion:false}
 ]){
  const x=fixture();x.cbReport.assessment={...x.cbReport.assessment,...fields};
  check(verdict(x),'CJ_CANNOT_TRUST_PRECEDING_PUBLIC_ADVISORY_OBSERVER');
 }
});
test('CJ: verified locked picomatch version and npm integrity must match upstream reports',()=>{
 const x=fixture();x.chReport.assessment={...x.chReport.assessment,
  latestNpmVersion:'4.0.8'};
 check(verdict(x),'CJ_UPSTREAM_VERSION_CHANGED_REQUIRES_REAL_INDEPENDENT_PATCH_REVIEW');
 const y=fixture();const locked=structuredClone(lock);
 locked.packages.picomatch[0]='picomatch@4.0.8';y.lock=locked;
 check(verdict(y),'CJ_FROZEN_LOCK_VULNERABILITY_SOURCE_CHANGED');
});
test('CJ: known-high advisory baseline cannot be deleted, lowered or signed off by claimant',()=>{
 for(const change of [
  x=>x.advisories=x.advisories.filter(a=>a.id!=='GHSA-fc5q-39xc-vjpf'),
  x=>x.advisories.find(a=>a.id==='GHSA-fc5q-39xc-vjpf').severity='low',
  x=>x.advisories.find(a=>a.id==='GHSA-fc5q-39xc-vjpf').independentSecurityApproval='APPROVED'
 ]){
  const x=fixture();x.baseline=structuredClone(baseline);change(x.baseline);
  check(verdict(x),'CJ_RISK_BASELINE_SEVERITY_OR_AUTHORIZATION_WEAKENED');
 }
});
test('CJ: repo, PR ref, job and runner SHA spoofing denied, Node env null-prototype valid',()=>{
 const x=fixture();
 const o=Object.assign(Object.create(null),env);
 assert.equal(verdict({...x,environment:o}).localObserverReportsStructurallyConsistent,true);
 for(const fields of [
  {GITHUB_JOB:'baseline'},{GITHUB_REPOSITORY:'attacker/fork'},
  {GITHUB_SHA:'not-a-sha'},{GITHUB_REF:'refs/heads/main'},
  {GITHUB_ACTIONS:'false'}
 ]){
  const r=verdict({...x,environment:{...env,...fields}});
  check(r,'CJ_UNVERIFIED_GITHUB_ACTIONS_RUN_CONTEXT');
  assert.equal(r.productionReleaseAuthorized,false);
 }
});

test('CJ: GitHub API unavailable while OSV withdrawal schema invalid is quarantined as UNKNOWN',()=>{
 const x=fixture({github:null,osv:{...os,withdrawn:'not-valid'}});
 const r=verdict(x);
 assert.equal(r.observedGithubLifecycle,'unavailable');
 assert.equal(r.observedOsvLifecycle,'invalid');
 assert.equal(r.incompleteOrInvalidPublicLifecycleQuarantined,true);
 assert.equal(r.independentCveGhsaOsvTechnicalAdjudicationRequired,true);
 assert.equal(r.publiclyWithdrawnAdvisoryObserved,false);
 assert.equal(r.withdrawalQuarantinedForIndependentAdjudication,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
