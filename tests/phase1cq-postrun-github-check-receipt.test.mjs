import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 WORKFLOW_ID,WORKFLOW_PATH,APP_ID,
 assessFinishedGithubRun,verifyFinishedRun
} from '../scripts/phase1cq-postrun-github-check-receipt.mjs';
import {REPO,AUTHOR,REQUIRED_JOBS} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
const H='a'.repeat(40),B='b'.repeat(40),M='c'.repeat(40);
const ID=12345678124,SUITE=1244545;
const PROPOSAL=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const PR={
 number:1,state:'open',draft:true,merged:false,updated_at:'2026-11-19T00:00:00Z',
 merge_commit_sha:M,user:{login:AUTHOR},
 head:{ref:'chore/phase0-foundation-20261106',sha:H,repo:{full_name:REPO}},
 base:{ref:'main',sha:B,repo:{full_name:REPO}}
};
const RUN={
 id:ID,workflow_id:WORKFLOW_ID,name:'Phase 0 baseline',
 path:WORKFLOW_PATH,status:'completed',conclusion:'success',
 event:'pull_request',head_branch:'chore/phase0-foundation-20261106',
 head_sha:H,run_attempt:1,check_suite_id:SUITE,
 repository:{full_name:REPO},head_repository:{full_name:REPO},
 pull_requests:[{number:1,head:{ref:'chore/phase0-foundation-20261106',sha:H},
  base:{ref:'main',sha:B}}]
};
const ctx={prBefore:'read',prAfter:'read',run:'read',checks:'read'};
const checks=()=>REQUIRED_JOBS.map((name,i)=>{
 const id=78900+i;
 return {id,name,head_sha:H,status:'completed',conclusion:'success',
  app:{id:APP_ID,slug:'github-actions'},check_suite:{id:SUITE},
  details_url:'https://github.com/'+REPO+'/actions/runs/'+ID+'/job/'+id};
});
const fixture=()=>{
 const c=checks();
 return {run:structuredClone(RUN),checks:{total_count:c.length,check_runs:c},
  prBefore:structuredClone(PR),prAfter:structuredClone(PR),
  proposal:structuredClone(PROPOSAL),sourceStatuses:{...ctx}};
};
const assessment=f=>assessFinishedGithubRun(f);
const code=(r,id)=>assert.ok(r.anomalyCodes.includes(id),r.anomalyCodes.join(','));
const response=(url,data,{status=200,mime='application/json'}={})=>{
 const r=new Response(typeof data==='string'?data:JSON.stringify(data),
  {status,headers:{'content-type':mime}});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CQ: exact completed run eight app-bound checks yields TECHNICAL receipt, never production GO',()=>{
 const r=assessment(fixture());
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,true,
  r.anomalyCodes.join(','));
 assert.equal(r.currentSuiteSuccessfulChecks,8);
 assert.equal(r.ignoredOtherSuiteCheckCount,0);
 assert.equal(r.prHeadStableAcrossPostrunReads,true);
 assert.equal(r.currentPrStillDraftOpenUnmerged,true);
 assert.equal(r.appId,15368);
 assert.match(r.localUnsignedEvidenceSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.independentlySignedCiOidcOrSlsaProvenanceVerified,false);
 assert.equal(r.actualBaseMainCodeownersAndRulesetInstalledVerified,false);
 assert.equal(r.independentSecurityBusinessCurrentHeadRoleApprovalsVerified,false);
 assert.equal(r.externalProviderLegalWormDrOrStagingApprovalVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CQ: completed workflow with older failed second suite cannot borrow or donate checks',()=>{
 const f=fixture();
 const older=checks().map((x,i)=>{
  const id=990000+i;
  return {...x,id,check_suite:{id:666777},conclusion:i===1?'failure':'success',
   details_url:'https://github.com/'+REPO+'/actions/runs/444444444/job/'+id};
 });
 f.checks.check_runs[1].conclusion='failure';
 f.checks.check_runs.push(...older);f.checks.total_count=16;
 const r=assessment(f);
 assert.equal(r.currentSuiteSuccessfulChecks,7);
 assert.equal(r.ignoredOtherSuiteCheckCount,8);
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
 code(r,'CQ_REQUIRED_CHECK_NOT_GENUINE_EXACT_RUN_GITHUB_ACTIONS_SUCCESS');
});
test('CQ: failing other suite on identical source does not poison selected complete suite',()=>{
 const f=fixture();
 const old=checks().map((x,i)=>{
  const id=300000+i;
  return {...x,id,check_suite:{id:88888},conclusion:'failure',
   details_url:'https://github.com/'+REPO+'/actions/runs/777777777/job/'+id};
 });
 f.checks.check_runs.push(...old);f.checks.total_count=16;
 const r=assessment(f);
 assert.equal(r.ignoredOtherSuiteCheckCount,8);
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,true);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CQ: never certify in-progress, queued, cancelled or failed workflow as completed success',()=>{
 for(const [status,conclusion] of [
  ['in_progress',null],['queued',null],['completed','cancelled'],
  ['completed','failure'],['completed','neutral']
 ]){
  const f=fixture();f.run.status=status;f.run.conclusion=conclusion;
  const r=assessment(f);
  code(r,'CQ_COMPLETED_GITHUB_WORKFLOW_RUN_IDENTITY_INVALID');
  assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
 }
});
test('CQ: PR head, base, synthetic merge SHA or update changes during GET causes rejection',()=>{
 for(const mutate of [
  pr=>pr.head.sha='d'.repeat(40),
  pr=>pr.base.sha='e'.repeat(40),
  pr=>pr.merge_commit_sha='f'.repeat(40),
  pr=>pr.updated_at='2026-11-19T01:00:00Z'
 ]){
  const f=fixture();mutate(f.prAfter);
  code(assessment(f),'CQ_PR_CHANGED_DURING_POSTRUN_INSPECTION');
 }
});
test('CQ: wrong PR identity, author, base, draft, fork, merged or closed is invalid',()=>{
 for(const mutate of [
  pr=>pr.draft=false,
  pr=>pr.merged=true,
  pr=>pr.state='closed',
  pr=>pr.user.login='attacker',
  pr=>pr.head.ref='main',
  pr=>pr.head.repo.full_name='attacker/repo',
  pr=>pr.base.repo.full_name='attacker/repo',
  pr=>pr.base.ref='not-main'
 ]){
  const f=fixture();mutate(f.prBefore);
  const r=assessment(f);
  code(r,'CQ_PR_BASE_AUTHOR_DRAFT_OR_SOURCE_IDENTITY_INVALID');
  assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
 }
});
test('CQ: latest PR HEAD must exactly match selected completed workflow head',()=>{
 for(const mutate of [
  f=>f.run.head_sha='d'.repeat(40),
  f=>f.run.pull_requests[0].base.sha='d'.repeat(40),
  f=>f.run.pull_requests[0].head.sha='d'.repeat(40)
 ]){
  const f=fixture();mutate(f);
  code(assessment(f),'CQ_WORKFLOW_RUN_NOT_BOUND_TO_CURRENT_PR_HEAD_AND_BASE');
 }
});
test('CQ: run identity must use fixed GitHub workflow file, name, id and true repository',()=>{
 for(const mutate of [
  r=>r.workflow_id=333,
  r=>r.name='Fake Success Workflow',
  r=>r.path='.github/workflows/unreviewed.yml',
  r=>r.event='workflow_dispatch',
  r=>r.head_branch='main',
  r=>r.head_repository.full_name='attacker/repo',
  r=>r.repository.full_name='attacker/repo',
  r=>r.run_attempt=0,
  r=>r.check_suite_id=0,
  r=>r.pull_requests=[]
 ]){
  const f=fixture();mutate(f.run);
  code(assessment(f),'CQ_COMPLETED_GITHUB_WORKFLOW_RUN_IDENTITY_INVALID');
 }
});
test('CQ: duplicate, missing and unknown check names fail closed for the chosen suite',()=>{
 const cases=[
  f=>f.checks.check_runs.pop(),
  f=>f.checks.check_runs[0].name='fake-job',
  f=>f.checks.check_runs.push({...f.checks.check_runs[0],id:9999}),
 ];
 for(const modify of cases){
  const f=fixture();modify(f);f.checks.total_count=f.checks.check_runs.length;
  const r=assessment(f);
  assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CQ: GitHub App check source spoofing or wrong job URL cannot become successful',()=>{
 for(const mutate of [
  c=>c.app.id=234,
  c=>c.app.slug='attacker-actions',
  c=>c.head_sha='d'.repeat(40),
  c=>c.details_url='https://evil.example.com/job/1',
  c=>c.id=0,
  c=>c.check_suite.id=SUITE+1
 ]){
  const f=fixture();mutate(f.checks.check_runs[0]);
  assert.equal(assessment(f).completedExactEightAppBoundChecksTechnicallyVerified,false);
 }
});
test('CQ: skipped, neutral, cancelled, pending or failed required job never yields eight success',()=>{
 for(const conclusion of ['skipped','neutral','failure','cancelled',null]){
  const f=fixture();f.checks.check_runs[2].conclusion=conclusion;
  assert.equal(assessment(f).completedExactEightAppBoundChecksTechnicallyVerified,false);
 }
 const f=fixture();f.checks.check_runs[2].status='in_progress';
 assert.equal(assessment(f).completedExactEightAppBoundChecksTechnicallyVerified,false);
});
test('CQ: bounded check-run page and count mismatch are not accepted as complete list',()=>{
 for(const mutate of [
  c=>c.total_count=100,
  c=>c.total_count=9,
  c=>c.check_runs='forged',
  c=>c.check_runs=null
 ]){
  const f=fixture();mutate(f.checks);
  code(assessment(f),'CQ_UNBOUNDED_OR_MALFORMED_GITHUB_CHECKRUN_LIST');
 }
});
test('CQ: source denial, missing token, invalid JSON remains HOLD without claiming completed job',()=>{
 for(const status of ['access_denied','not_found_or_hidden','unavailable','invalid']){
  const f=fixture();f.sourceStatuses.run=status;
  const r=assessment(f);
  code(r,'CQ_OFFICIAL_GITHUB_SOURCE_UNAVAILABLE_OR_DENIED');
  assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
 }
});
test('CQ: app-pinned main policy proposal tampering is a structural failure even with green checks',()=>{
 for(const modify of [
  p=>delete p.rules[3].parameters.required_status_checks[0].integration_id,
  p=>p.rules[2].parameters.required_approving_review_count=1,
  p=>p.bypass_actors.push({actor_id:1,actor_type:'RepositoryRole',bypass_mode:'always'})
 ]){
  const f=fixture();modify(f.proposal);
  code(assessment(f),'CQ_UNREVIEWED_APP_PINNED_MAIN_RULESET_PROPOSAL');
 }
});
test('CQ: fixed official read-only API routes are exactly PR before/run/checks/PR after',async()=>{
 const paths=[];
 const root='https://api.github.com/repos/'+REPO;
 const r=await verifyFinishedRun({runId:ID,token:'test-token',proposal:structuredClone(PROPOSAL),
  fetchImpl:async(url,opts)=>{
   paths.push(url);
   assert.equal(opts.method,'GET');
   assert.equal(opts.redirect,'error');
   if(url===root+'/pulls/1')return response(url,PR);
   if(url===root+'/actions/runs/'+ID)return response(url,RUN);
   if(url===root+'/commits/'+H+'/check-runs?per_page=100')
    return response(url,{total_count:8,check_runs:checks()});
   throw Error('unapproved read route');
  }});
 assert.deepEqual(paths,[
  root+'/pulls/1',root+'/actions/runs/'+ID,
  root+'/commits/'+H+'/check-runs?per_page=100',root+'/pulls/1'
 ]);
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,true,
  r.anomalyCodes.join(','));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CQ: missing run or wrong SHA prevents querying untrusted check-run URL',async()=>{
 const root='https://api.github.com/repos/'+REPO;
 const paths=[];
 const r=await verifyFinishedRun({runId:ID,token:'test-token',
  proposal:structuredClone(PROPOSAL),
  fetchImpl:async url=>{
   paths.push(url);
   if(url===root+'/pulls/1')return response(url,PR);
   if(url===root+'/actions/runs/'+ID)return response(url,{},{status:404});
   throw Error('must not query source checks without verified source SHA');
  }});
 assert.deepEqual(paths,[root+'/pulls/1',root+'/actions/runs/'+ID,
  root+'/pulls/1']);
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
});
test('CQ: no token cannot invent read-only GitHub source observations',async()=>{
 let called=0;
 const r=await verifyFinishedRun({runId:ID,token:'',proposal:structuredClone(PROPOSAL),
  fetchImpl:async()=>{called++;throw Error('should not call');}});
 assert.equal(called,0);
 assert.equal(r.completedExactEightAppBoundChecksTechnicallyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
