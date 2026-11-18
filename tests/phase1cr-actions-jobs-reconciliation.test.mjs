import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {REPO,AUTHOR,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {WORKFLOW_ID,WORKFLOW_PATH}
 from '../scripts/phase1cq-postrun-github-check-receipt.mjs';
import {jobsRoute,runRoute,checksRoute,readOfficialCheckSource}
 from '../scripts/phase1cp-github-actions-check-app-source.mjs';
import {assessCompletedJobsCrossApi,verifyCompletedJobsCrossApi}
 from '../scripts/phase1cr-actions-jobs-reconciliation.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const RUN_ID=12345678901,SUITE=123987;
const ROOT='https://api.github.com/repos/'+REPO;
const PROPOSAL=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const statuses={prBefore:'read',run:'read',checks:'read',
 jobs:'read',prAfter:'read'};
const make=()=>{
 const pr={number:1,state:'open',draft:true,merged:false,
  updated_at:'2026-11-19T00:00:00Z',merge_commit_sha:MERGE,
  user:{login:AUTHOR},
  head:{ref:'chore/phase0-foundation-20261106',sha:HEAD,
   repo:{full_name:REPO}},
  base:{ref:'main',sha:BASE,repo:{full_name:REPO}}};
 const run={id:RUN_ID,workflow_id:WORKFLOW_ID,
  name:'Phase 0 baseline',path:WORKFLOW_PATH,event:'pull_request',
  head_branch:'chore/phase0-foundation-20261106',head_sha:HEAD,
  run_attempt:1,check_suite_id:SUITE,status:'completed',
  conclusion:'success',repository:{full_name:REPO},
  head_repository:{full_name:REPO},
  pull_requests:[{number:1,head:{ref:'chore/phase0-foundation-20261106',sha:HEAD},
   base:{ref:'main',sha:BASE}}]};
 const check_runs=REQUIRED_JOBS.map((name,index)=>{
  const id=100000+index;
  return {id,name,head_sha:HEAD,status:'completed',
   conclusion:'success',check_suite:{id:SUITE},
   app:{id:GITHUB_ACTIONS_INTEGRATION_ID,slug:'github-actions'},
   details_url:'https://github.com/'+REPO+'/actions/runs/'+RUN_ID+'/job/'+id};
 });
 const jobs=REQUIRED_JOBS.map((name,index)=>{
  const id=100000+index;
  return {id,name,run_id:RUN_ID,run_attempt:1,head_sha:HEAD,
   workflow_name:'Phase 0 baseline',status:'completed',
   conclusion:'success',url:ROOT+'/actions/jobs/'+id,
   check_run_url:ROOT+'/check-runs/'+id,
   html_url:'https://github.com/'+REPO+'/actions/runs/'+RUN_ID+'/job/'+id};
 });
 return {prBefore:structuredClone(pr),prAfter:structuredClone(pr),
  run,checks:{total_count:8,check_runs},jobs:{total_count:8,jobs},
  proposal:structuredClone(PROPOSAL),sourceStatuses:{...statuses}};
};
const assess=f=>assessCompletedJobsCrossApi(f);
const has=(r,code)=>assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join(';'));
const response=(url,data,{status=200}={})=>{
 const r=new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json'}});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CR: exact eight Actions jobs AND app checks yields UNSIGNED technical result only',()=>{
 const r=assess(make());
 assert.equal(r.completedCrossApiJobsAndChecksTechnicallyVerified,true,r.anomalyCodes.join(';'));
 assert.equal(r.matchedJobs,8);
 assert.equal(r.precedingCQCompletedCheckSourceVerified,true);
 assert.match(r.localUnsignedObservationSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.thirdPartySignedSlsaOrOidcAttestationVerified,false);
});
test('CR: mismatched job ID cannot borrow green named check',()=>{
 const f=make();f.jobs.jobs[0].id=999999;
 has(assess(f),'CR_JOB_ID_RUN_ATTEMPT_SHA_URL_OR_CONCLUSION_MISMATCH');
});
test('CR: wrong run ID, run attempt or old source SHA fails exact job reconciliation',()=>{
 for(const update of [
  j=>j.run_id=RUN_ID+1,j=>j.run_attempt=2,
  j=>j.head_sha='d'.repeat(40)
 ]){
  const f=make();update(f.jobs.jobs[0]);
  has(assess(f),'CR_JOB_ID_RUN_ATTEMPT_SHA_URL_OR_CONCLUSION_MISMATCH');
 }
});
test('CR: counterfeit official job URL, check URL, browser URL or workflow name is denied',()=>{
 for(const update of [
  j=>j.url='https://evil.invalid/jobs/1',
  j=>j.check_run_url='https://evil.invalid/check-runs/1',
  j=>j.html_url='https://evil.invalid/actions',
  j=>j.workflow_name='Shadow Actions'
 ]){
  const f=make();update(f.jobs.jobs[0]);
  has(assess(f),'CR_JOB_ID_RUN_ATTEMPT_SHA_URL_OR_CONCLUSION_MISMATCH');
 }
});
test('CR: pending, failed, cancelled and neutral jobs are never equivalent to success',()=>{
 for(const conclusion of ['failure','cancelled','neutral','skipped',null]){
  const f=make();f.jobs.jobs[0].conclusion=conclusion;
  assert.equal(assess(f).completedCrossApiJobsAndChecksTechnicallyVerified,false);
 }
 const f=make();f.jobs.jobs[0].status='in_progress';
 assert.equal(assess(f).completedCrossApiJobsAndChecksTechnicallyVerified,false);
});
test('CR: duplicate, extra, unknown, missing and unbounded Jobs lists fail-closed',()=>{
 for(const update of [
  f=>f.jobs.jobs.pop(),
  f=>f.jobs.jobs.push({...f.jobs.jobs[0],id:100500}),
  f=>f.jobs.jobs[1].name=f.jobs.jobs[0].name,
  f=>f.jobs.jobs[0].name='fake-job',
  f=>f.jobs.total_count=100,
  f=>f.jobs.total_count=7,
  f=>f.jobs.jobs='invalid'
 ]){
  const f=make();update(f);
  const r=assess(f);
  assert.equal(r.completedCrossApiJobsAndChecksTechnicallyVerified,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CR: success-looking Actions jobs cannot override failed or pending CQ check',()=>{
 const f=make();f.checks.check_runs[0].conclusion='failure';
 has(assess(f),'CR_CQ_COMPLETED_EXACT_SUITE_PR_SOURCE_NOT_VERIFIED');
});
test('CR: PR head/base/update race across all five sources is a HARD HOLD',()=>{
 for(const edit of [
  p=>p.head.sha='e'.repeat(40),
  p=>p.base.sha='f'.repeat(40),
  p=>p.updated_at='2026-11-19T02:00:00Z',
  p=>p.draft=false
 ]){
  const f=make();edit(f.prAfter);
  assert.equal(assess(f).completedCrossApiJobsAndChecksTechnicallyVerified,false);
 }
});
test('CR: any missing denied source is not treated as independent approval',()=>{
 for(const key of Object.keys(statuses)){
  const f=make();f.sourceStatuses[key]='access_denied';
  has(assess(f),'CR_GITHUB_CROSS_API_SOURCE_UNAVAILABLE_OR_DENIED');
 }
});
test('CR: only fixed numeric GET Jobs route may be used',async()=>{
 assert.equal(jobsRoute(RUN_ID),runRoute(RUN_ID)+'/jobs?per_page=100&filter=latest');
 for(const val of ['0','../admin',-3,99999999999999999]){
  assert.throws(()=>jobsRoute(val),/CP_UNREVIEWED_GITHUB_RUN_ID/);
 }
 await assert.rejects(()=>readOfficialCheckSource('/actions/jobs/123','token'),
  /CP_UNREVIEWED_GITHUB_CHECK_SOURCE_ROUTE/);
});
test('CR: operator read order is PR, exact run, source check-runs, run jobs, PR',async()=>{
 const f=make(),calls=[];
 const expected=[
  ROOT+'/pulls/1',ROOT+runRoute(RUN_ID),
  ROOT+checksRoute(HEAD),ROOT+jobsRoute(RUN_ID),ROOT+'/pulls/1'];
 const receipt=await verifyCompletedJobsCrossApi({
  runId:RUN_ID,token:'test',proposal:structuredClone(PROPOSAL),
  fetchImpl:async(url,options)=>{
   calls.push(url);assert.equal(options.method,'GET');
   assert.equal(options.redirect,'error');
   if(url===ROOT+'/pulls/1')return response(url,f.prBefore);
   if(url===ROOT+runRoute(RUN_ID))return response(url,f.run);
   if(url===ROOT+checksRoute(HEAD))return response(url,f.checks);
   if(url===ROOT+jobsRoute(RUN_ID))return response(url,f.jobs);
   throw Error('unreviewed URL');
  }
 });
 assert.deepEqual(calls,expected);
 assert.equal(receipt.completedCrossApiJobsAndChecksTechnicallyVerified,true,
  receipt.anomalyCodes.join(';'));
});
test('CR: mismatched run identity does not query check or job record URLs',async()=>{
 const f=make(),calls=[];
 const r=await verifyCompletedJobsCrossApi({
  runId:RUN_ID,token:'test',proposal:structuredClone(PROPOSAL),
  fetchImpl:async url=>{
   calls.push(url);
   if(url===ROOT+'/pulls/1')return response(url,f.prBefore);
   if(url===ROOT+runRoute(RUN_ID))return response(url,{...f.run,id:5});
   throw Error('unapproved read');
  }
 });
 assert.deepEqual(calls,[ROOT+'/pulls/1',ROOT+runRoute(RUN_ID),ROOT+'/pulls/1']);
 assert.equal(r.completedCrossApiJobsAndChecksTechnicallyVerified,false);
});
test('CR: no token never invents any official API evidence or operator approval',async()=>{
 let called=0;
 const r=await verifyCompletedJobsCrossApi({
  runId:RUN_ID,token:'',proposal:structuredClone(PROPOSAL),
  fetchImpl:async()=>{called++;throw Error('Unexpected access');}
 });
 assert.equal(called,0);
 assert.equal(r.completedCrossApiJobsAndChecksTechnicallyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
