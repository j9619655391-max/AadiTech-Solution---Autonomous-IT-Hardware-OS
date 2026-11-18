import test from 'node:test';
import assert from 'node:assert/strict';
import {
 readOfficialGithubEndpoint,collectReadonlyGithubSnapshot,
 assessObservedGithubGovernance
} from '../scripts/phase1by-github-governance-observer.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const ENV=Object.freeze({
 GITHUB_REPOSITORY:REPO,GITHUB_REF:'refs/pull/1/merge',
 GITHUB_SHA:MERGE,GITHUB_HEAD_REF:DEV,GITHUB_BASE_REF:'main',
 GITHUB_EVENT_NAME:'pull_request'
});
const ROOT='/repos/'+REPO;
const paths={
 pr:ROOT+'/pulls/1',
 reviews:ROOT+'/pulls/1/reviews?per_page=100',
 rules:ROOT+'/rules/branches/main',
 protection:ROOT+'/branches/main/protection'
};
const requiredChecks=[
 'baseline','mysql-integration','production-runtime-scope',
 'build-input-provenance','review-vendor-intake-hold',
 'independent-evidence-hold','live-github-governance-hold'
];
const examplePR={
 number:1,state:'open',draft:true,merged:false,merge_commit_sha:MERGE,
 user:{login:'j9619655391-max'},
 head:{ref:DEV,sha:HEAD,repo:{full_name:REPO}},
 base:{ref:'main',sha:BASE,repo:{full_name:REPO}}
};
const exampleRules=[
 {type:'pull_request',parameters:{required_approving_review_count:2,
  require_code_owner_review:true,require_last_push_approval:true}},
 {type:'non_fast_forward'},{type:'deletion'},
 {type:'required_status_checks',parameters:{
  required_status_checks:requiredChecks.map(context=>({context}))}}
];
const exampleLegacy={
 required_pull_request_reviews:{required_approving_review_count:2,
  dismiss_stale_reviews:true,require_code_owner_reviews:true,
  require_last_push_approval:true},
 enforce_admins:{enabled:true}
};
const exampleReviews=[
 {id:5,state:'APPROVED',commit_id:HEAD,
  user:{login:'reviewer-security-example'},submitted_at:'2026-11-18T09:01:00Z'},
 {id:6,state:'APPROVED',commit_id:HEAD,
  user:{login:'reviewer-business-example'},submitted_at:'2026-11-18T09:02:00Z'}
];
const clone=x=>structuredClone(x);
function fixture(){
 return {observedAt:'2026-11-18T09:00:00.000Z',
  repository:ENV.GITHUB_REPOSITORY,githubRef:ENV.GITHUB_REF,
  githubSha:ENV.GITHUB_SHA,githubHeadRef:ENV.GITHUB_HEAD_REF,
  githubBaseRef:ENV.GITHUB_BASE_REF,eventName:ENV.GITHUB_EVENT_NAME,
  endpoints:{
   pr:{status:'read',data:clone(examplePR)},
   reviews:{status:'read',data:clone(exampleReviews)},
   rules:{status:'read',data:clone(exampleRules)},
   protection:{status:'read',data:clone(exampleLegacy)}
  }};
}
const assess=(mutate=()=>{})=>{
 const f=fixture();mutate(f);return assessObservedGithubGovernance(f);
};
const mockedApi=(routes)=>async(url,config)=>{
 assert.equal(config.method,'GET');
 assert.equal(config.redirect,'error');
 assert.equal(new URL(url).origin,'https://api.github.com');
 assert.match(config.headers.Authorization,/^Bearer test-token$/);
 const path=new URL(url).pathname+new URL(url).search;
 const entry=routes[path]??{status:404,data:{}};
 return {
  status:entry.status??200,
  headers:{get:key=>key==='content-length'?
    String(entry.length??JSON.stringify(entry.data??null).length):null},
  text:async()=>JSON.stringify(entry.data??null)
 };
};

test('BY read-only payload observation never authorizes reviewer roles, CI signatures or production',()=>{
 const result=assess();
 assert.equal(result.githubRepoContextMatched,true);
 assert.equal(result.observedPrDraftAndUnmerged,true);
 assert.equal(result.ciMergeMatchesPrApi,true);
 assert.equal(result.reviews.distinctLatestHeadApprovalCount,2);
 assert.equal(result.observableRequiredBranchRulesPresent,true);
 assert.equal(result.currentBranchProtectionReadProven,true);
 assert.equal(result.independentReviewerSecurityAndBusinessRolesVerified,false);
 assert.equal(result.externallyEnrolledReviewerKeysVerified,false);
 assert.equal(result.signedCIProvenanceVerified,false);
 assert.equal(result.externallyWitnessedWormProvenanceVerified,false);
 assert.equal(result.protectedBranchAdminBypassIndependentlyReviewed,false);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.releaseDecision,'HOLD');
 assert.ok(result.anomalyCodes.includes('BY_RULESET_BYPASS_CONTROL_NOT_INDEPENDENTLY_PROVEN'));
});
test('BY source branch, PR identity, merge SHA, base, author and repo substitution denied',()=>{
 const changes=[
  f=>f.endpoints.pr.data.head.sha='d'.repeat(40),
  f=>f.endpoints.pr.data.base.ref='evil',
  f=>f.endpoints.pr.data.user.login='attacker',
  f=>f.endpoints.pr.data.draft=false,
  f=>f.endpoints.pr.data.merged=true,
  f=>f.endpoints.pr.data.head.repo.full_name='attacker/fork',
  f=>f.repository='attacker/fork',
  f=>f.githubRef='refs/pull/99/merge',
  f=>f.githubSha='e'.repeat(40),
  f=>f.endpoints.pr.data.merge_commit_sha=null
 ];
 for(const change of changes){
  const r=assess(change);
  assert.ok(r.anomalyCodes.some(x=>x==='BY_PR_REPO_OR_DRAFT_IDENTITY_MISMATCH'||
   x==='BY_CI_REF_OR_MERGE_SHA_INVALID'||
   x==='BY_PR_TEST_MERGE_SHA_UNCORRELATED'),r.anomalyCodes.join(','));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BY GitHub latest review state wins: self, old head, withdrawal and change request denied',()=>{
 for(const mutation of [
  f=>f.endpoints.reviews.data[0].user.login='j9619655391-max',
  f=>f.endpoints.reviews.data[0].commit_id='0'.repeat(40),
  f=>f.endpoints.reviews.data[0].state='CHANGES_REQUESTED',
  f=>f.endpoints.reviews.data.push({id:7,state:'DISMISSED',commit_id:HEAD,
   user:{login:'reviewer-security-example'},submitted_at:'2026-11-18T09:05:00Z'}),
  f=>f.endpoints.reviews.data.push({id:7,state:'COMMENTED',commit_id:HEAD,
   user:{login:'reviewer-security-example'},submitted_at:'2026-11-18T09:05:00Z'})
 ]){
  const r=assess(mutation);
  assert.equal(r.reviews.distinctLatestHeadApprovalCount,1);
  assert.ok(r.anomalyCodes.includes('BY_INSUFFICIENT_EXACT_HEAD_NONAUTHOR_REVIEWS'));
  assert.equal(r.independentReviewerSecurityAndBusinessRolesVerified,false);
 }
});
test('BY weakened GitHub PR, two approvals, owner, latest push, checks, force/delete denied',()=>{
 for(const mutation of [
  f=>f.endpoints.rules.data=f.endpoints.rules.data.filter(x=>x.type!=='pull_request'),
  f=>f.endpoints.rules.data[0].parameters.required_approving_review_count=1,
  f=>f.endpoints.rules.data[0].parameters.require_code_owner_review=false,
  f=>f.endpoints.rules.data[0].parameters.require_last_push_approval=false,
  f=>f.endpoints.rules.data=f.endpoints.rules.data.filter(x=>x.type!=='non_fast_forward'),
  f=>f.endpoints.rules.data=f.endpoints.rules.data.filter(x=>x.type!=='deletion'),
  f=>f.endpoints.rules.data[3].parameters.required_status_checks.pop()
 ]){
  const r=assess(f=>{mutation(f);f.endpoints.protection.status='access_denied';f.endpoints.protection.data=null;});
  assert.equal(r.observableRequiredBranchRulesPresent,false,r.anomalyCodes.join(','));
  assert.ok(r.anomalyCodes.includes('BY_BRANCH_PROTECTION_REQUIREMENTS_NOT_ESTABLISHED'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('BY legacy protection read may supply review minimum, never independent admin-bypass authority',()=>{
 const r=assess(f=>{f.endpoints.rules.data=[];});
 assert.equal(r.legacy.available,true);
 assert.equal(r.observableRequiredBranchRulesPresent,true);
 assert.equal(r.protectedBranchAdminBypassIndependentlyReviewed,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('BY denied, missing token, incomplete review pagination are UNVERIFIED not approvals',()=>{
 for(const name of ['pr','reviews','rules','protection']){
  const r=assess(f=>{f.endpoints[name]={status:'access_denied',data:null};});
  assert.equal(r.endpointStatuses[name],'access_denied');
  assert.ok(r.anomalyCodes.includes('BY_GITHUB_'+name.toUpperCase()+'_NOT_READ'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
 const r=assess(f=>{f.endpoints.reviews={status:'incomplete_pagination',data:null};});
 assert.equal(r.reviews.distinctLatestHeadApprovalCount,0);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('BY network collector uses fixed official GitHub GET paths, no redirect, no leaks',async()=>{
 const routes={
  [paths.pr]:{data:examplePR},[paths.reviews]:{data:exampleReviews},
  [paths.rules]:{data:exampleRules},[paths.protection]:{data:exampleLegacy}
 };
 const snapshot=await collectReadonlyGithubSnapshot({
  token:'test-token',fetchImpl:mockedApi(routes),environment:ENV
 });
 assert.equal(snapshot.endpoints.pr.status,'read');
 assert.equal(snapshot.endpoints.reviews.data.length,2);
 assert.equal(snapshot.endpoints.rules.status,'read');
 assert.equal(snapshot.endpoints.protection.status,'read');
 assert.equal(assessObservedGithubGovernance(snapshot).productionReleaseAuthorized,false);
 assert.equal(JSON.stringify(snapshot).includes('test-token'),false);
});
test('BY bounded pagination uses only fixed URLs, never attacker-supplied Link header',async()=>{
 const reviews=Array.from({length:100},(_,i)=>({
  ...exampleReviews[0],id:i+1,user:{login:'name-'+i}}));
 const routes={
  [paths.pr]:{data:examplePR},[paths.reviews]:{data:reviews},
  [paths.reviews+'&page=2']:{data:[exampleReviews[1]]},
  [paths.rules]:{data:exampleRules},[paths.protection]:{data:exampleLegacy}
 };
 const s=await collectReadonlyGithubSnapshot({
  token:'test-token',fetchImpl:mockedApi(routes),environment:ENV
 });
 assert.equal(s.endpoints.reviews.data.length,101);
 assert.equal(s.endpoints.reviews.status,'read');
 const r=assessObservedGithubGovernance(s);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.reviews.submittedReviewCount,101);
});
test('BY origin allowlist refuses arbitrary path, reflected hosts and oversized API input',async()=>{
 const fake=mockedApi({});
 await assert.rejects(readOfficialGithubEndpoint(
  '/repos/attacker/fork/pulls/1','test-token',{fetchImpl:fake}),/untrusted API path/);
 await assert.rejects(readOfficialGithubEndpoint(
  paths.reviews+'&page=999','test-token',{fetchImpl:fake}),/untrusted API path/);
 const oversized=await readOfficialGithubEndpoint(paths.pr,'test-token',{
  fetchImpl:async()=>({status:200,headers:{get:()=>String(196609)}})
 });
 assert.equal(oversized.status,'oversize');
 const denied=await readOfficialGithubEndpoint(paths.pr,'test-token',{
  fetchImpl:async()=>({status:403,headers:{get:()=>null}})
 });
 assert.equal(denied.status,'access_denied');
 const unavailable=await readOfficialGithubEndpoint(paths.pr,'test-token',{
  fetchImpl:async()=>{throw Error('private-token-do-not-log')}
 });
 assert.equal(unavailable.status,'unavailable');
 assert.equal(JSON.stringify(unavailable).includes('private-token'),false);
});
test('BY zero credential CI emits missing token observations without network calls',async()=>{
 const snapshot=await collectReadonlyGithubSnapshot({
  token:'',fetchImpl:async()=>{throw Error('must never be called')},
  environment:ENV
 });
 assert.equal(snapshot.endpoints.rules.status,'missing_token');
 const r=assessObservedGithubGovernance(snapshot);
 assert.equal(r.currentBranchProtectionReadProven,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
