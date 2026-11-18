import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {ENDPOINTS,REPO,fetchReadOnlyGithubGovernance,
 assessLiveCodeownerOnboarding} from '../scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const env={GITHUB_ACTIONS:'true',GITHUB_JOB:'live-github-governance-hold',
 GITHUB_REPOSITORY:REPO,GITHUB_REF:'refs/pull/1/merge',
 GITHUB_SHA:MERGE,GITHUB_EXPECTED_PR_HEAD_SHA:HEAD};
const priorBy={
 kind:'LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD',
 sourceBundleSha256:'c'.repeat(64),
 externallySigned:false,independentWorm:false,
 productionReleaseAuthorized:false,releaseDecision:'HOLD',
 snapshotDerived:{
  phase:'1BY',kind:'READ_ONLY_GITHUB_GOVERNANCE_OBSERVATION',
  observedPrDraftAndUnmerged:true,
  eventSourceHeadAndBaseMatch:true,ciMergeMatchesPrApi:true,
  observedDevHeadSha:HEAD,observedBaseSha:BASE,
  rules:{observedRuleCount:0},
  reviews:{submittedReviewCount:0,distinctLatestHeadApprovalCount:0},
  observableRequiredBranchRulesPresent:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const requested={status:'read',httpStatus:200,data:{users:[],teams:[]}};
function fixture(){
 return {observations:{
  codeownersGithub:{status:'absent_or_hidden',httpStatus:404,data:null},
  codeownersRoot:{status:'absent_or_hidden',httpStatus:404,data:null},
  codeownersDocs:{status:'absent_or_hidden',httpStatus:404,data:null},
  requestedReviewers:structuredClone(requested)
 },priorBy:structuredClone(priorBy),environment:{...env}};
}
const decision=x=>assessLiveCodeownerOnboarding(x);
const check=(x,code)=>assert.ok(x.anomalyCodes.includes(code),x.anomalyCodes.join(','));
const codeowners=(path,text)=>{
 const bytes=Buffer.from(text,'utf8');
 return {status:'read',httpStatus:200,data:{
  type:'file',path,encoding:'base64',content:bytes.toString('base64'),
  size:bytes.length,sha:'d'.repeat(40)
 }};
};
const response=(url,body,{status=200,mime='application/json',contentLength}={})=>{
 const headers={'content-type':mime};
 if(contentLength!==undefined)headers['content-length']=String(contentLength);
 const out=new Response(body,{status,headers});
 Object.defineProperty(out,'url',{value:url});
 return out;
};
test('CL: real missing main CODEOWNERS paths and zero reviewers are missing authority not CI failure',()=>{
 const r=decision(fixture());
 assert.equal(r.officialPublicObservationStructurallyValid,true,r.anomalyCodes.join(','));
 assert.equal(r.codeownersSelectionKnown,true);
 assert.equal(r.selectedCodeownersLocation,null);
 assert.equal(r.priorRealMainAppliedRuleCount,0);
 assert.equal(r.priorRealLatestHeadNonauthorApprovalCount,0);
 check(r,'CL_NO_CODEOWNERS_FILE_FOUND_ON_MAIN');
 check(r,'CL_NO_GENUINE_TWO_APPROVAL_QUORUM');
 check(r,'CL_EFFECTIVE_REQUIRED_MAIN_BRANCH_RULES_NOT_VERIFIED');
 check(r,'CL_NO_INDEPENDENT_REVIEWER_REQUEST_VISIBLE');
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CL: syntactically valid main CODEOWNERS does not authenticate real owner or protections',()=>{
 const f=fixture();
 f.observations.codeownersGithub=codeowners('.github/CODEOWNERS',
  '* @security-owner\n/.github/CODEOWNERS @security-owner\n');
 f.observations.requestedReviewers.data.users=[
  {login:'alice-independent',id:50},{login:'bob-independent',id:51}];
 const r=decision(f);
 assert.equal(r.selectedCodeownersLocation,'.github/CODEOWNERS');
 assert.equal(r.observedCodeownersSummary.patternRows,2);
 assert.equal(r.observedCodeownersSummary.explicitlyProtectsCodeowners,true);
 assert.equal(r.requestedReviewerSummary.nonAuthorRequestedUsers,2);
 for(const flag of ['independentSecurityAndBusinessRoleEnrollmentVerified',
  'genuineTwoLatestHeadReviewsApproved',
  'effectiveMainRulesAndNoBypassIndependentlyVerified',
  'actualMainCodeownerPolicySafelyInstalledAndEnforced',
  'externalCcaEmudhraMcaWormDrAuthorityVerified','productionReleaseAuthorized'])
  assert.equal(r[flag],false,flag);
});
test('CL: GitHub CODEOWNERS selection .github, root, docs order respects base branch',()=>{
 const f=fixture();
 f.observations.codeownersGithub=codeowners('.github/CODEOWNERS','* @first\n');
 f.observations.codeownersRoot=codeowners('CODEOWNERS','* @second\n');
 f.observations.codeownersDocs=codeowners('docs/CODEOWNERS','* @third\n');
 assert.equal(decision(f).selectedCodeownersLocation,'.github/CODEOWNERS');
 f.observations.codeownersGithub={status:'absent_or_hidden',data:null};
 assert.equal(decision(f).selectedCodeownersLocation,'CODEOWNERS');
 f.observations.codeownersRoot={status:'absent_or_hidden',data:null};
 assert.equal(decision(f).selectedCodeownersLocation,'docs/CODEOWNERS');
});
test('CL: denied read of higher-precedence path makes selected CODEOWNERS UNKNOWN',()=>{
 const f=fixture();
 f.observations.codeownersGithub={status:'access_denied',data:null};
 f.observations.codeownersRoot=codeowners('CODEOWNERS','* @reviewer\n');
 const r=decision(f);
 assert.equal(r.codeownersSelectionKnown,false);
 assert.equal(r.observedCodeownersSummary,null);
 check(r,'CL_MAIN_CODEOWNERS_SOURCE_UNKNOWN');
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CL: empty/comment-only CODEOWNERS has no review owner, and needs own file protection',()=>{
 for(const txt of ['# empty\n','\n# comment\n/README.md @reviewer\n']){
  const f=fixture();
  f.observations.codeownersGithub=codeowners('.github/CODEOWNERS',txt);
  const r=decision(f);
  if(!txt.includes('/README.md'))check(r,'CL_MAIN_CODEOWNERS_OWNER_MAPPING_EMPTY');
  check(r,'CL_CODEOWNERS_FILE_NOT_EXPLICITLY_OWNER_PROTECTED');
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CL: malicious/incomplete CODEOWNERS ownership mappings are not accepted as valid owners',()=>{
 for(const content of ['* @valid\n/etc [weird] @attacker\n','* nobody\n',
  '* @someone\n!/override @else\n']){
  const f=fixture();
  f.observations.codeownersGithub=codeowners('.github/CODEOWNERS',content);
  const r=decision(f);
  check(r,'CL_CODEOWNERS_MALFORMED_ROWS');
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CL: forged, incorrect path or incompatible GitHub blob encoding stays UNKNOWN',()=>{
 for(const modify of [
  d=>d.path='CODEOWNERS',
  d=>d.encoding='utf8',
  d=>d.sha='badsha',
  d=>d.size=999,
  d=>d.content='%%%',
  d=>d.content='A'.repeat(200000)
 ]){
  const f=fixture();
  f.observations.codeownersGithub=codeowners('.github/CODEOWNERS','* @reviewer\n');
  modify(f.observations.codeownersGithub.data);
  const r=decision(f);
  assert.equal(r.endpointStatuses.codeownersGithub,'invalid');
  check(r,'CL_MAIN_CODEOWNERS_SOURCE_UNKNOWN');
 }
});
test('CL: PR author requested for review cannot satisfy independent reviewer identity',()=>{
 const f=fixture();
 f.observations.requestedReviewers.data.users=[
  {login:'j9619655391-max',id:1},{login:'independent-looking',id:2}];
 const r=decision(f);
 assert.equal(r.requestedReviewerSummary.nonAuthorRequestedUsers,1);
 check(r,'CL_PR_AUTHOR_REVIEW_REQUEST_NOT_INDEPENDENT');
 assert.equal(r.genuineTwoLatestHeadReviewsApproved,false);
});
test('CL: tampered or malformed GitHub requested reviewer users and team data rejected',()=>{
 for(const mutate of [
  x=>x.users=[{login:'someone',id:0}],
  x=>x.users=[{login:'someone',id:5},{login:'someone',id:6}],
  x=>x.teams=[{slug:'a'}],
  x=>x.users='not-array'
 ]){
  const f=fixture();mutate(f.observations.requestedReviewers.data);
  const r=decision(f);
  assert.equal(r.endpointStatuses.requestedReviewers,'invalid');
  check(r,'CL_OFFICIAL_REQUESTEDREVIEWERS_NOT_READ');
 }
});
test('CL: tampered preceding real governance report or false green approvals cannot authorize release',()=>{
 for(const tamper of [
  x=>x.kind='UNRELATED',
  x=>x.sourceBundleSha256='fake',
  x=>x.externallySigned=true,
  x=>x.snapshotDerived.observedPrDraftAndUnmerged=false,
  x=>x.snapshotDerived.releaseDecision='GO'
 ]){
  const f=fixture();tamper(f.priorBy);
  const r=decision(f);
  check(r,'CL_PRECEDING_LIVE_GITHUB_GOVERNANCE_REPORT_INVALID');
  assert.equal(r.officialPublicObservationStructurallyValid,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CL: latest-head mismatch and wrong runner ref/job/source SHA rejected',()=>{
 for(const change of [
  {GITHUB_JOB:'baseline'},
  {GITHUB_SHA:'broken'},
  {GITHUB_REF:'refs/heads/main'},
  {GITHUB_REPOSITORY:'somebody/other'},
  {GITHUB_EXPECTED_PR_HEAD_SHA:'f'.repeat(40)},
  {GITHUB_ACTIONS:'false'}
 ]){
  const f=fixture();f.environment={...env,...change};
  const r=decision(f);
  check(r,'CL_CURRENT_GITHUB_WORKLOAD_IDENTITY_INVALID');
  assert.equal(r.officialPublicObservationStructurallyValid,false);
 }
});
test('CL: a correct null-prototype Node GitHub Actions env is accepted',()=>{
 const f=fixture();f.environment=Object.assign(Object.create(null),env);
 assert.equal(decision(f).officialPublicObservationStructurallyValid,true);
});
test('CL: fixed GitHub API read-only routes use no redirection, unsafe token output or unknown endpoint',async()=>{
 const url='https://api.github.com'+ENDPOINTS.requestedReviewers;
 const result=await fetchReadOnlyGithubGovernance(ENDPOINTS.requestedReviewers,'test-token',
  async (u,opts)=>{
   assert.equal(u,url);
   assert.equal(opts.method,'GET');
   assert.equal(opts.redirect,'error');
   assert.equal(opts.cache,'no-store');
   return response(url,'{"users":[],"teams":[]}');
  });
 assert.equal(result.status,'read');
 await assert.rejects(()=>fetchReadOnlyGithubGovernance(
  '/repos/attacker/victim/contents/.github/CODEOWNERS?ref=main','test-token'),
  /CL_UNREVIEWED_GITHUB_API_ROUTE/);
});
test('CL: GitHub 404 does not mean safe; 403, rate-limit and network failure stay UNKNOWN',async()=>{
 const path=ENDPOINTS.codeownersGithub,url='https://api.github.com'+path;
 for(const [code,expected] of [[404,'absent_or_hidden'],[403,'access_denied'],[429,'unavailable']]){
  const r=await fetchReadOnlyGithubGovernance(path,'test-token',
   async()=>response(url,'{}',{status:code}));
  assert.equal(r.status,expected);
 }
 const unavailable=await fetchReadOnlyGithubGovernance(path,'',async()=>{
  throw Error('should not fetch without token');
 });
 assert.equal(unavailable.status,'unavailable');
 const fail=await fetchReadOnlyGithubGovernance(path,'token',async()=>{throw Error('network secret');});
 assert.equal(fail.status,'unavailable');
});
test('CL: HTTPS redirect, MIME mismatch, oversized length and unbounded stream are invalid',async()=>{
 const path=ENDPOINTS.requestedReviewers,url='https://api.github.com'+path;
 for(const res of [
  response('https://evil.example.net','{}'),
  response(url,'{}',{mime:'text/html'}),
  response(url,'{}',{contentLength:200000}),
  response(url,'{"users":[],"teams":[]}'.padEnd(140000,'x'))
 ]){
  const r=await fetchReadOnlyGithubGovernance(path,'token',async()=>res);
  assert.equal(r.status,'invalid');
 }
});
test('CL: all green CI but missing actual GitHub review/branch settings remains HOLD',()=>{
 const f=fixture();
 f.priorBy.snapshotDerived.rules={observedRuleCount:10};
 f.priorBy.snapshotDerived.reviews={
  submittedReviewCount:2,distinctLatestHeadApprovalCount:2
 };
 f.priorBy.snapshotDerived.observableRequiredBranchRulesPresent=true;
 f.observations.codeownersGithub=codeowners('.github/CODEOWNERS',
  '* @security-looking @business-looking\n/.github/CODEOWNERS @security-looking\n');
 f.observations.requestedReviewers.data.users=[
  {login:'security-looking',id:55},{login:'business-looking',id:66}];
 const r=decision(f);
 assert.equal(r.officialPublicObservationStructurallyValid,true);
 assert.equal(r.genuineTwoLatestHeadReviewsApproved,false);
 assert.equal(r.independentSecurityAndBusinessRoleEnrollmentVerified,false);
 assert.equal(r.effectiveMainRulesAndNoBypassIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
