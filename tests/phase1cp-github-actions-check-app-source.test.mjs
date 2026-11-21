import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 APP_ID,ALLOWED_CHECKS,runRoute,checksRoute,readOfficialCheckSource,
 collectOfficialCheckProvenance,assessOfficialAppCheckProvenance
} from '../scripts/phase1cp-github-actions-check-app-source.mjs';
import {REPO} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const RUN_ID=12345678901,SUITE=932487;
const proposal=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const byReport={
 kind:'LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD',
 sourceBundleSha256:'f'.repeat(64),
 productionReleaseAuthorized:false,releaseDecision:'HOLD',
 snapshotDerived:{
  phase:'1BY',observedPrDraftAndUnmerged:true,
  eventSourceHeadAndBaseMatch:true,ciMergeMatchesPrApi:true,
  observedDevHeadSha:HEAD,observedBaseSha:BASE,observedPrMergeSha:MERGE,
  releaseDecision:'HOLD',productionReleaseAuthorized:false
 }
};
const environment={
 GITHUB_ACTIONS:'true',GITHUB_JOB:'live-github-governance-hold',
 GITHUB_REPOSITORY:REPO,GITHUB_REF:'refs/pull/1/merge',
 GITHUB_SHA:MERGE,GITHUB_RUN_ID:String(RUN_ID)
};
const actionRun=()=>({
 id:RUN_ID,check_suite_id:SUITE,status:'completed',conclusion:'success',
 head_sha:HEAD,head_branch:'chore/phase0-foundation-20261106',
 event:'pull_request',
 pull_requests:[{number:1,head:{sha:HEAD},base:{sha:BASE}}]
});
const check=(name,i,suite=SUITE,status='completed',conclusion='success')=>{
 const id=500000+i;
 return {
  id,name,status,conclusion,head_sha:HEAD,
  app:{id:APP_ID,slug:'github-actions'},
  check_suite:{id:suite},
  details_url:'https://github.com/'+REPO+
   '/actions/runs/'+RUN_ID+'/job/'+id
 };
};
const checks=()=>ALLOWED_CHECKS.map((name,i)=>check(name,i));
const fixture=()=>{
 const check_runs=checks();
 return {
  byReport:structuredClone(byReport),
  proposal:structuredClone(proposal),
  environment:{...environment},
  observations:{
   runStatus:'read',run:actionRun(),
   checksStatus:'read',checks:{total_count:check_runs.length,check_runs}
  }
 };
};
const evaluate=x=>assessOfficialAppCheckProvenance(x);
const has=(r,code)=>assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join(';'));
const response=(url,body,{status=200,mime='application/json',length}={})=>{
 const headers={'content-type':mime};
 if(length!==undefined)headers['content-length']=String(length);
 const r=new Response(body,{status,headers});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CP: real observed Github Actions App id 15368 is pinned for every one of 8 job contexts',()=>{
 assert.equal(APP_ID,15368);
 assert.equal(ALLOWED_CHECKS.length,8);
 assert.ok(proposal.rules[3].parameters.required_status_checks.every(x=>
  x.integration_id===APP_ID));
 const r=evaluate(fixture());
 assert.equal(r.officialLiveRunAndCheckSourceStructurallyConsistent,true,r.anomalyCodes.join(';'));
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,true);
 assert.equal(r.currentSuitePassedCount,8);
 assert.equal(r.sourceBoundSignedOidcCiWorkloadAttestationVerified,false);
 assert.equal(r.effectiveMainRequiredChecksInstalled,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CP: live in-progress suite with 6 successful and 2 pending is valid observation but NOT all green',()=>{
 const f=fixture();
 f.observations.run.status='in_progress';
 f.observations.run.conclusion=null;
 for(let i=6;i<8;i++){
  f.observations.checks.check_runs[i].status='in_progress';
  f.observations.checks.check_runs[i].conclusion=null;
 }
 const r=evaluate(f);
 assert.equal(r.officialLiveRunAndCheckSourceStructurallyConsistent,true);
 assert.equal(r.currentSuitePassedCount,6);
 assert.equal(r.currentSuitePendingCount,2);
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
 has(r,'CP_CURRENT_SUITE_HAS_UNFINISHED_REQUIRED_CHECKS');
});
test('CP: second suite on same source HEAD cannot lend success to failed current run',()=>{
 const f=fixture();
 const prior=checks().map((x,i)=>({
  ...x,id:700000+i,check_suite:{id:987654},
  details_url:'https://github.com/'+REPO+'/actions/runs/8888888888/job/'+(700000+i),
  conclusion:i===3?'failure':'success'
 }));
 f.observations.checks.check_runs[3].conclusion='failure';
 f.observations.checks.check_runs.push(...prior);
 f.observations.checks.total_count=f.observations.checks.check_runs.length;
 const r=evaluate(f);
 assert.equal(r.ignoredOtherSuiteCheckCount,8);
 assert.equal(r.currentSuitePassedCount,7);
 assert.equal(r.currentSuiteFailedCount,1);
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
 has(r,'CP_OTHER_CHECK_SUITE_SAME_COMMIT_EXCLUDED');
 has(r,'CP_CURRENT_SUITE_REQUIRED_CHECK_FAILURE');
});
test('CP: other suite with 8 failed jobs does not contaminate the selected successful run',()=>{
 const f=fixture();
 for(let i=0;i<8;i++)f.observations.checks.check_runs.push({
  ...check(ALLOWED_CHECKS[i],i,54321),
  conclusion:'failure'
 });
 f.observations.checks.total_count=16;
 const r=evaluate(f);
 assert.equal(r.currentSuitePassedCount,8);
 assert.equal(r.ignoredOtherSuiteCheckCount,8);
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,true);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CP: a successful check from fake or different app is a source failure',()=>{
 for(const modify of [
  x=>x.app.id=999,
  x=>x.app.slug='fake-actions',
  x=>delete x.app,
  x=>x.details_url='https://attacker.example/actions/runs',
  x=>x.head_sha='d'.repeat(40),
  x=>x.id=-5,
  x=>x.check_suite.id=0
 ]){
  const f=fixture();modify(f.observations.checks.check_runs[0]);
  const r=evaluate(f);
  assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CP: duplicate job check name in selected suite fails structural source integrity',()=>{
 const f=fixture();
 const duplicated={...f.observations.checks.check_runs[0],id:900001,
  details_url:'https://github.com/'+REPO+'/actions/runs/'+RUN_ID+'/job/900001'};
 f.observations.checks.check_runs.push(duplicated);
 f.observations.checks.total_count=9;
 const r=evaluate(f);
 has(r,'CP_DUPLICATE_CHECK_CONTEXT_IN_EXACT_CURRENT_SUITE');
 assert.equal(r.officialLiveRunAndCheckSourceStructurallyConsistent,false);
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
});
test('CP: wrong GitHub run id, head SHA, source branch, event or PR is not exact current run',()=>{
 for(const modify of [
  r=>r.id=456,
  r=>r.head_sha='d'.repeat(40),
  r=>r.head_branch='main',
  r=>r.event='push',
  r=>r.pull_requests=[{number:2,head:{sha:HEAD},base:{sha:BASE}}],
  r=>r.check_suite_id=-1
 ]){
  const f=fixture();modify(f.observations.run);
  const r=evaluate(f);
  has(r,'CP_ACTUAL_GITHUB_ACTIONS_RUN_NOT_VERIFIED');
  assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
 }
});
test('CP: no check source or unbounded pagination cannot be misread as all eight SUCCESS',()=>{
 for(const mutation of [
  o=>o.checksStatus='access_denied',
  o=>o.checks.total_count=100,
  o=>o.checks.total_count=9,
  o=>o.checks.check_runs='forged',
  o=>o.runStatus='unavailable'
 ]){
  const f=fixture();mutation(f.observations);
  const r=evaluate(f);
  assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CP: missing required job or skipped/neutral/failed conclusion never becomes green',()=>{
 for(const state of ['skipped','neutral','failure','cancelled','timed_out','stale']){
  const f=fixture();f.observations.checks.check_runs[0].conclusion=state;
  const r=evaluate(f);
  assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
  assert.equal(r.currentSuiteFailedCount,1);
 }
 const f=fixture();f.observations.checks.check_runs.pop();
 f.observations.checks.total_count=7;
 assert.equal(evaluate(f).currentSuiteMissingCount,1);
});
test('CP: fake official run success while API actual run in progress never becomes full-run passed',()=>{
 const f=fixture();f.observations.run.status='in_progress';
 f.observations.run.conclusion=null;
 const r=evaluate(f);
 assert.equal(r.currentSuitePassedCount,8);
 assert.equal(r.currentExactRunAllEightAppBoundChecksPassed,false);
});
test('CP: proposal with missing or foreign app id must not be considered a safe ruleset',()=>{
 for(const change of [
  x=>delete x.rules[3].parameters.required_status_checks[0].integration_id,
  x=>x.rules[3].parameters.required_status_checks[2].integration_id=999,
  x=>x.rules[3].parameters.required_status_checks[1].context='fake'
 ]){
  const f=fixture();change(f.proposal);
  const r=evaluate(f);
  has(r,'CP_REQUIRED_CHECK_APPLICATION_ID_UNPINNED_OR_UNREVIEWED');
  assert.equal(r.officialLiveRunAndCheckSourceStructurallyConsistent,false);
 }
});
test('CP: modified prior real GitHub source, unsigned custody hash or stale head cannot pass',()=>{
 for(const change of [
  f=>f.byReport.kind='FORGED',
  f=>f.byReport.sourceBundleSha256='bad',
  f=>f.byReport.snapshotDerived.eventSourceHeadAndBaseMatch=false,
  f=>f.byReport.snapshotDerived.observedPrDraftAndUnmerged=false,
  f=>f.byReport.snapshotDerived.ciMergeMatchesPrApi=false,
  f=>f.byReport.snapshotDerived.productionReleaseAuthorized=true
 ]){
  const f=fixture();change(f);
  has(evaluate(f),'CP_PRECEDING_ACTUAL_GITHUB_HEAD_AND_CUSTODY_INVALID');
 }
});
test('CP: CI wrong job/ref/merge checkout SHA/repository/run id is rejected',()=>{
 for(const mod of [
  {GITHUB_JOB:'baseline'},
  {GITHUB_SHA:'f'.repeat(40)},
  {GITHUB_REPOSITORY:'attacker/repo'},
  {GITHUB_REF:'refs/heads/main'},
  {GITHUB_ACTIONS:'false'},
  {GITHUB_RUN_ID:'0'},
  {GITHUB_RUN_ID:'999999999999999999999999'}
 ]){
  const f=fixture();f.environment={...environment,...mod};
  const r=evaluate(f);
  has(r,'CP_GITHUB_CURRENT_WORKLOAD_RUN_SHA_OR_REF_INVALID');
  assert.equal(r.officialLiveRunAndCheckSourceStructurallyConsistent,false);
 }
});
test('CP: valid real Node env with null prototype is allowed',()=>{
 const f=fixture();
 f.environment=Object.assign(Object.create(null),environment);
 assert.equal(evaluate(f).officialLiveRunAndCheckSourceStructurallyConsistent,true);
});
test('CP: fixed official check routes refuse arbitrary hosts or hidden page injection',()=>{
 assert.equal(runRoute(RUN_ID),'/actions/runs/'+RUN_ID);
 assert.equal(checksRoute(HEAD),'/commits/'+HEAD+'/check-runs?per_page=100');
 for(const v of ['../admin','0',-1,0,'notanid',99999999999999999]){
  assert.throws(()=>runRoute(v),/CP_UNREVIEWED_GITHUB_RUN_ID/);
 }
 for(const sha of ['bad',HEAD+'/../../attacker','A'.repeat(40)]){
  assert.throws(()=>checksRoute(sha),/CP_UNREVIEWED_GITHUB_SOURCE_SHA/);
 }
});
test('CP: official GitHub check API uses only read-only GET, fixed host, denied redirect and bounded JSON',async()=>{
 const route=runRoute(RUN_ID),url='https://api.github.com/repos/'+REPO+route;
 const source=await readOfficialCheckSource(route,'token',async(u,opts)=>{
  assert.equal(u,url);
  assert.equal(opts.method,'GET');
  assert.equal(opts.redirect,'error');
  assert.equal(opts.cache,'no-store');
  return response(u,JSON.stringify(actionRun()));
 });
 assert.equal(source.status,'read');
 for(const [mock,expected] of [
  [response(url,'{}',{status:403}),'access_denied'],
  [response(url,'{}',{status:404}),'not_found_or_hidden'],
  [response(url,'{}',{status:429}),'unavailable'],
  [response('https://evil.example','{}'),'invalid'],
  [response(url,'{}',{mime:'text/html'}),'invalid'],
  [response(url,'{}',{length:1000000}),'invalid'],
  [response(url,'['+' '.repeat(525000)+']'),'invalid']
 ]){
  const r=await readOfficialCheckSource(route,'token',async()=>mock);
  assert.equal(r.status,expected);
 }
 await assert.rejects(()=>readOfficialCheckSource('/repos/other/secret','token'),
  /CP_UNREVIEWED_GITHUB_CHECK_SOURCE_ROUTE/);
});
test('CP: no token does not fetch and does not invent third-party security approval',async()=>{
 const r=await readOfficialCheckSource(runRoute(RUN_ID),'',async()=>{
  throw Error('should not fetch without token');
 });
 assert.equal(r.status,'unavailable');
 const f=fixture();f.observations.runStatus='unavailable';f.observations.run=null;
 assert.equal(evaluate(f).productionReleaseAuthorized,false);
});
test('CP: actual bounded read source fetches run then source-HEAD check-runs, no synthetic merge SHA query',async()=>{
 const paths=[];
 const origin='https://api.github.com/repos/'+REPO;
 const r=await collectOfficialCheckProvenance({
  runId:RUN_ID,token:'token',
  fetchImpl:async(u)=>{
   paths.push(u);
   if(u===origin+runRoute(RUN_ID))return response(u,JSON.stringify(actionRun()));
   if(u===origin+checksRoute(HEAD))return response(u,JSON.stringify({
    total_count:8,check_runs:checks()
   }));
   throw Error('unexpected route');
  }
 });
 assert.deepEqual(paths,[origin+runRoute(RUN_ID),origin+checksRoute(HEAD)]);
 assert.equal(evaluate({...fixture(),observations:r}).currentExactRunAllEightAppBoundChecksPassed,true);
});
test('CP: actual run is unavailable -> no source SHA or arbitrary fallback check route',async()=>{
 let count=0;
 const source=await collectOfficialCheckProvenance({
  runId:RUN_ID,token:'token',
  fetchImpl:async u=>{
   count++;
   return response(u,'{}',{status:403});
  }
 });
 assert.equal(count,1);
 assert.equal(source.runStatus,'access_denied');
 assert.equal(source.checksStatus,'not_attempted');
 assert.equal(evaluate({...fixture(),observations:source}).currentExactRunAllEightAppBoundChecksPassed,false);
});
