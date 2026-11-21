import test from 'node:test';
import assert from 'node:assert/strict';
import {
 evaluateLatestSubmittedReviews,assessRealNonauthorApprovalQuorum,
 collectLiveReviewerEvidence,assessCurrentRunHold
} from '../scripts/phase1co-live-exact-head-reviewer-quorum.mjs';
import {REPO,AUTHOR} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const USER_SEC='security-reviewer',USER_BUS='business-reviewer';
const permission=(login,role='write')=>({
 status:'read',data:{user:{login},permission:role}
});
const PR=Object.freeze({
 number:1,state:'open',draft:true,merged:false,
 user:{login:AUTHOR},merge_commit_sha:MERGE,
 updated_at:'2026-11-18T13:45:00Z',
 head:{ref:'chore/phase0-foundation-20261106',sha:HEAD,
  repo:{full_name:REPO}},
 base:{ref:'main',sha:BASE,repo:{full_name:REPO}}
});
const review=(login,id,state='APPROVED',sha=HEAD,time='2026-11-18T13:00:00Z')=>({
 id,state,commit_id:sha,submitted_at:time,user:{login}
});
const approvals=()=>[
 review(USER_SEC,11,'APPROVED',HEAD,'2026-11-18T13:00:00Z'),
 review(USER_BUS,22,'APPROVED',HEAD,'2026-11-18T13:05:00Z')
];
const fixture=()=>({
 securityLogin:USER_SEC,businessLogin:USER_BUS,
 prBefore:structuredClone(PR),prAfter:structuredClone(PR),
 reviews:approvals(),reviewPaginationComplete:true,
 securityPermission:permission(USER_SEC),
 businessPermission:permission(USER_BUS)
});
const evalReal=x=>assessRealNonauthorApprovalQuorum(x);
const error=(r,id)=>assert.ok(r.anomalyCodes.includes(id),r.anomalyCodes.join(';'));
const byReport={
 kind:'LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD',
 sourceBundleSha256:'e'.repeat(64),
 productionReleaseAuthorized:false,releaseDecision:'HOLD',
 snapshotDerived:{
  phase:'1BY',observedPrDraftAndUnmerged:true,
  eventSourceHeadAndBaseMatch:true,ciMergeMatchesPrApi:true,
  observedPrMergeSha:MERGE,observedDevHeadSha:HEAD,
  reviews:{distinctLatestHeadApprovalCount:0},
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const clReport={
 sourceExternallySigned:false,productionReleaseAuthorized:false,
 releaseDecision:'HOLD',decision:{
  phase:'1CL',repo:REPO,observedDevHeadSha:HEAD,
  officialPublicObservationStructurallyValid:true,
  selectedCodeownersLocation:null,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const cnReport={
 externallySigned:false,productionReleaseAuthorized:false,
 releaseDecision:'HOLD',verdict:{
  phase:'1CN',repo:REPO,sourceHeadSha:HEAD,
  officialReadOnlySourceChainStructurallyValid:true,
  exactProposalMatchingRulesetCount:0,
  rulesetListAndAllBypassFieldsReadable:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const env={
 GITHUB_ACTIONS:'true',GITHUB_JOB:'live-github-governance-hold',
 GITHUB_REPOSITORY:REPO,GITHUB_REF:'refs/pull/1/merge',
 GITHUB_SHA:MERGE
};
const ciFixture=()=>({
 byReport:structuredClone(byReport),
 clReport:structuredClone(clReport),
 cnReport:structuredClone(cnReport),
 environment:{...env}
});
const URL='https://api.github.com/repos/'+REPO;
const response=(url,body,{status=200,mime='application/json'}={})=>{
 const r=new Response(JSON.stringify(body),{status,headers:{'content-type':mime}});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CO: two real technical GitHub APPROVED events and two repository write grants never confer Security/Business mandate or production GO',()=>{
 const r=evalReal(fixture());
 assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,true,r.anomalyCodes.join(';'));
 assert.equal(r.currentDevHead,HEAD);
 assert.equal(r.observedDistinctCurrentHeadApprovals,2);
 assert.equal(r.securityNominatedAccountActuallyApprovedCurrentHead,true);
 assert.equal(r.businessNominatedAccountActuallyApprovedCurrentHead,true);
 assert.equal(r.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated,false);
 assert.equal(r.latestHeadApprovalSignaturesIndependentlyCryptographicallyVerified,false);
 assert.equal(r.mainCodeownersAndBypassFreeRulesetIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CO: zero real submitted PR approvals cannot simulate an independent review quorum',()=>{
 const f=fixture();f.reviews=[];
 const r=evalReal(f);
 error(r,'CO_SECURITY_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
 error(r,'CO_BUSINESS_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
 assert.equal(r.observedDistinctCurrentHeadApprovals,0);
 assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,false);
});
test('CO: PR author cannot self-appoint and same person cannot sign two roles',()=>{
 for(const [a,b] of [
  [AUTHOR,USER_BUS],[USER_SEC,AUTHOR],
  [USER_SEC,USER_SEC.toUpperCase()]
 ]){
  const f=fixture();f.securityLogin=a;f.businessLogin=b;
  error(evalReal(f),'CO_REVIEWER_IDENTITY_NOT_TWO_DISTINCT_NONAUTHORS');
 }
});
test('CO: stale approval on previous source commit, even if submitted recently, rejected',()=>{
 const f=fixture();f.reviews[0].commit_id='d'.repeat(40);
 error(evalReal(f),'CO_SECURITY_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
});
test('CO: latest CHANGES_REQUESTED, COMMENTED or DISMISSED overrides older APPROVED',()=>{
 for(const state of ['CHANGES_REQUESTED','COMMENTED','DISMISSED']){
  const f=fixture();
  f.reviews.push(review(USER_SEC,33,state,HEAD,'2026-11-18T13:30:00Z'));
  error(evalReal(f),'CO_SECURITY_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
 }
});
test('CO: submitted reviews are ordered by timestamp, not array order',()=>{
 const f=fixture();
 f.reviews.unshift(review(USER_SEC,99,'COMMENTED',HEAD,'2026-11-18T13:30:00Z'));
 const result=evalReal(f);
 assert.equal(result.securityNominatedAccountActuallyApprovedCurrentHead,false);
 const o=evaluateLatestSubmittedReviews(f.reviews,HEAD,AUTHOR);
 assert.equal(o.byLogin[USER_SEC].lastReviewId,99);
});
test('CO: PENDING draft review never counts as submitted and does not supersede an older submitted review',()=>{
 const f=fixture();
 f.reviews.push({id:44,state:'PENDING',commit_id:HEAD,
  submitted_at:null,user:{login:USER_SEC}});
 const r=evalReal(f);
 assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,true);
 const o=evaluateLatestSubmittedReviews(f.reviews,HEAD,AUTHOR);
 assert.equal(o.counts.nonSubmittedPending,1);
});
test('CO: duplicate review ID or malicious malformed review record fails closed',()=>{
 for(const edit of [
  rows=>rows.push({...rows[0]}),
  rows=>rows[0].id=0,
  rows=>rows[0].user.login='bad/actor',
  rows=>rows[0].state='FAKE_APPROVED',
  rows=>rows[0].commit_id='notsha',
  rows=>rows[0].submitted_at='invalid date'
 ]){
  const f=fixture();edit(f.reviews);
  const r=evalReal(f);
  assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CO: review commit noncurrent or case-only account aliases cannot bypass exact SHA identity',()=>{
 const f=fixture();
 f.reviews[0].user.login=USER_SEC.toUpperCase();
 assert.equal(evalReal(f).securityNominatedAccountActuallyApprovedCurrentHead,true);
 f.reviews[0].commit_id='e'.repeat(40);
 assert.equal(evalReal(f).securityNominatedAccountActuallyApprovedCurrentHead,false);
});
test('CO: PR head/base/merge/updated_at moving between reads is rejected as race',()=>{
 for(const mutate of [
  p=>p.head.sha='d'.repeat(40),
  p=>p.base.sha='e'.repeat(40),
  p=>p.merge_commit_sha='f'.repeat(40),
  p=>p.updated_at='2026-11-18T14:00:00Z'
 ]){
  const f=fixture();mutate(f.prAfter);
  error(evalReal(f),'CO_PR_CHANGED_DURING_ACTUAL_REVIEW_READ');
 }
});
test('CO: non-draft, closed, merged, wrong author, other repo or wrong base is never approved',()=>{
 for(const mutate of [
  p=>p.draft=false,p=>p.state='closed',p=>p.merged=true,
  p=>p.user.login='not-author',p=>p.base.ref='release',
  p=>p.head.repo.full_name='attacker/fork'
 ]){
  const f=fixture();mutate(f.prBefore);
  error(evalReal(f),'CO_PR_ACTUAL_BASE_AUTHOR_OR_DRAFT_IDENTITY_INVALID');
 }
});
test('CO: incomplete review pagination is not an approval even with 2 apparently APPROVED records',()=>{
 const f=fixture();f.reviewPaginationComplete=false;
 error(evalReal(f),'CO_GITHUB_REVIEW_PAGINATION_INCOMPLETE');
});
test('CO: missing or read-only/triage/forged technical repository permissions deny two-person review',()=>{
 for(const mutation of [
  p=>p.status='access_denied',
  p=>p.data.permission='read',
  p=>p.data.permission='triage',
  p=>p.data.user.login='attacker'
 ]){
  const f=fixture();mutation(f.securityPermission);
  error(evalReal(f),'CO_ACTUAL_REVIEWER_REPOSITORY_WRITE_PERMISSION_NOT_VERIFIED');
 }
});
test('CO: even 300 review records cannot be promoted to a full unbounded review history',()=>{
 const entries=Array.from({length:301},(_,i)=>review('user'+i,i+1));
 assert.equal(evaluateLatestSubmittedReviews(entries,HEAD,AUTHOR).valid,false);
});
test('CO: actual GitHub read-only operator mode fetches PR twice, reviews once and only two nominated collaborator permission URLs',async()=>{
 const requests=[];
 const res=await collectLiveReviewerEvidence({
  token:'approved-test-token',securityLogin:USER_SEC,businessLogin:USER_BUS,
  fetchImpl:async(url,opts)=>{
   requests.push({url,method:opts.method,redirect:opts.redirect});
   if(url===URL+'/pulls/1')return response(url,PR);
   if(url===URL+'/pulls/1/reviews?per_page=100')return response(url,approvals());
   if(url===URL+'/collaborators/'+USER_SEC+'/permission')return response(url,
    {user:{login:USER_SEC},permission:'write'});
   if(url===URL+'/collaborators/'+USER_BUS+'/permission')return response(url,
    {user:{login:USER_BUS},permission:'write'});
   throw Error('unexpected upstream call');
  }
 });
 assert.equal(requests.length,5);
 assert.ok(requests.every(x=>x.method==='GET'&&x.redirect==='error'));
 assert.equal(requests.filter(x=>x.url===URL+'/pulls/1').length,2);
 assert.equal(res.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,true,
  res.anomalyCodes.join(';'));
 assert.equal(res.productionReleaseAuthorized,false);
});
test('CO: real read-only API missing token or unavailable reviews fails closed without releasing',async()=>{
 const r=await collectLiveReviewerEvidence({
  token:'',securityLogin:USER_SEC,businessLogin:USER_BUS,
  fetchImpl:async()=>{throw Error('should not call without valid token');}
 });
 assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CO: source-bound current CI with no nominees is an audit of ABSENCE, not a fake appointment',()=>{
 const r=assessCurrentRunHold(ciFixture());
 assert.equal(r.actualCurrentRunSourceStructurallyValid,true,r.anomalyCodes.join(';'));
 assert.equal(r.observedDistinctNonauthorCurrentHeadApprovals,0);
 assert.equal(r.observedExactMainProposalInstalledCount,0);
 assert.equal(r.actualNomineeUsernamesIntentionallyNotStoredInCI,true);
 assert.equal(r.externalReviewerRoleMandatesAndRealNominatedPermissionsVerified,false);
 error(r,'CO_NO_TWO_LATEST_HEAD_GITHUB_APPROVALS_OBSERVED');
 assert.equal(r.releaseDecision,'HOLD');
});
test('CO: tampered prior BY/CL/CN GitHub source receipts or fake signed approval fail structural CI',()=>{
 for(const edit of [
  f=>f.byReport.kind='FAKE',
  f=>f.byReport.snapshotDerived.ciMergeMatchesPrApi=false,
  f=>f.clReport.decision.observedDevHeadSha='f'.repeat(40),
  f=>f.cnReport.verdict.sourceHeadSha='f'.repeat(40),
  f=>f.cnReport.externallySigned=true
 ]){
  const f=ciFixture();edit(f);
  assert.equal(assessCurrentRunHold(f).actualCurrentRunSourceStructurallyValid,false);
 }
});
test('CO: exact CI source event cannot change repository, job, ref or checked-out PR test merge',()=>{
 for(const envChange of [
  {GITHUB_ACTIONS:'false'},{GITHUB_JOB:'baseline'},
  {GITHUB_REPOSITORY:'attacker/fork'},
  {GITHUB_REF:'refs/heads/main'},
  {GITHUB_SHA:'e'.repeat(40)}
 ]){
  const f=ciFixture();Object.assign(f.environment,envChange);
  error(assessCurrentRunHold(f),'CO_GITHUB_RUN_CHECKOUT_AND_EVENT_BINDING_INVALID');
 }
});
