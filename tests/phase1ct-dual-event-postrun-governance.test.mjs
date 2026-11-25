import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {REPO,AUTHOR,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {BRANCH,PUSH_REF_ROUTE} from '../scripts/phase1cs-push-head-governance.mjs';
import {runRoute,jobsRoute,checksRoute}
 from '../scripts/phase1cp-github-actions-check-app-source.mjs';
import {assessDualEventReceipt,verifyDualEventReceipt}
 from '../scripts/phase1ct-dual-event-postrun-governance.mjs';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const PUSH=12345678901,PR=12345678902,PS=321,RS=322;
const ROOT='https://api.github.com/repos/'+REPO;
const WEB='https://github.com/'+REPO+'/actions/runs/';
const proposal=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const statuses=Object.fromEntries([
 'prBefore','branch','pushRun','prRun','checks','pushJobs','prJobs','prAfter'
].map(x=>[x,'read']));
const make=()=>{
 const pr={number:1,state:'open',draft:true,merged:false,
  updated_at:'2026-11-19T00:00:00Z',merge_commit_sha:MERGE,user:{login:AUTHOR},
  head:{sha:HEAD,ref:BRANCH,repo:{full_name:REPO}},
  base:{sha:BASE,ref:'main',repo:{full_name:REPO}}};
 const run=(event,id,suite)=>({
  id,workflow_id:408632517,name:'Phase 0 baseline',path:'.github/workflows/ci.yml',
  event,head_branch:BRANCH,head_sha:HEAD,run_attempt:1,check_suite_id:suite,
  status:'completed',conclusion:'success',repository:{full_name:REPO},
  head_repository:{full_name:REPO},
  pull_requests:[{number:1,head:{ref:BRANCH,sha:HEAD},
   base:{ref:'main',sha:BASE}}]
 });
 const mk=(event,id,suite,index)=>{
  const name=REQUIRED_JOBS[index],jobId=(event==='push'?100000:200000)+index;
  const conclusion=event==='push'&&name==='source-merge-lineage-hold'?
   'skipped':'success';
  return {
   check:{id:jobId,name,head_sha:HEAD,status:'completed',conclusion,
    check_suite:{id:suite},app:{id:GITHUB_ACTIONS_INTEGRATION_ID,slug:'github-actions'},
    details_url:WEB+id+'/job/'+jobId},
   job:{id:jobId,name,run_id:id,run_attempt:1,head_sha:HEAD,
    workflow_name:'Phase 0 baseline',status:'completed',conclusion,
    url:ROOT+'/actions/jobs/'+jobId,check_run_url:ROOT+'/check-runs/'+jobId,
    html_url:WEB+id+'/job/'+jobId}
  };
 };
 const pc=REQUIRED_JOBS.map((_,i)=>mk('push',PUSH,PS,i)),
  rc=REQUIRED_JOBS.map((_,i)=>mk('pull_request',PR,RS,i));
 return {
  observations:{
   prBefore:structuredClone(pr),prAfter:structuredClone(pr),
   branch:{ref:'refs/heads/'+BRANCH,
    object:{type:'commit',sha:HEAD,url:ROOT+'/git/commits/'+HEAD}},
   pushRun:run('push',PUSH,PS),prRun:run('pull_request',PR,RS),
   checks:{total_count:16,check_runs:[...pc.map(x=>x.check),...rc.map(x=>x.check)]},
   pushJobs:{total_count:8,jobs:pc.map(x=>x.job)},
   prJobs:{total_count:8,jobs:rc.map(x=>x.job)}
  },statuses:{...statuses},proposal:structuredClone(proposal)
 };
};
const assess=fn=>{const f=make();fn?.(f);return assessDualEventReceipt(f)};
const failed=(f,code)=>{
 const r=assess(f);
 assert.equal(r.completedTwoEventTechnicalReceiptVerified,false);
 assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join('|'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
};
const response=(url,data)=>{
 const r=new Response(JSON.stringify(data),{
  status:200,headers:{'content-type':'application/json'}});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CT: exactly two completed suites/jobs pass technical reconciliation but not release',()=>{
 const result=assess();
 assert.equal(result.completedTwoEventTechnicalReceiptVerified,true,result.anomalyCodes.join('|'));
 assert.equal(result.completedPrEightSuccessCrossApiVerified,true);
 assert.equal(result.completedPushSevenSuccessAndOnePrOnlySkipCrossApiVerified,true);
 assert.equal(result.pushSuccesses,7);
 assert.equal(result.pushExpectedSkipped,1);
 assert.equal(result.prMatchedJobs,8);
 assert.match(result.localUnsignedTechnicalSha256,/^[0-9a-f]{64}$/);
 assert.equal(result.independentSecurityBusinessMandatesVerified,false);
 assert.equal(result.installedMainCodeownersRulesetsWithoutBypassVerified,false);
 assert.equal(result.independentSignedOidcSlsaWorkloadAttestationVerified,false);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.productionReleaseBlocked,true);
 assert.equal(result.releaseDecision,'HOLD');
});
test('CT: no push success can be borrowed from PR suite',()=>{
 failed(f=>{f.observations.pushRun.check_suite_id=RS},'CT_MIXED_OR_REUSED_PR_PUSH_SUITE');
});
test('CT: pull-request run cannot stand in for a push',()=>{
 failed(f=>{f.observations.pushRun.event='pull_request'},'CT_COMPLETED_PUSH_RUN_SOURCE_UNVERIFIED');
});
test('CT: current development ref drift invalidates apparently green runs',()=>{
 failed(f=>{f.observations.branch.object.sha='d'.repeat(40)},'CT_CURRENT_BRANCH_REF_NOT_BOUND_TO_PR');
});
test('CT: current Draft PR race or ready state invalidates entire dual observation',()=>{
 for(const change of [
  f=>{f.observations.prAfter.updated_at='2026-11-19T02:00:00Z';},
  f=>{f.observations.prAfter.head.sha='d'.repeat(40);},
  f=>{f.observations.prAfter.base.sha='e'.repeat(40);},
  f=>{f.observations.prAfter.merge_commit_sha='f'.repeat(40);},
  f=>{f.observations.prAfter.draft=false;}
 ])failed(change,'CT_DRAFT_PR_IDENTITY_OR_RACE');
});
test('CT: changed PR required status or job attempt denies all-green',()=>{
 for(const edit of [
  f=>{f.observations.prJobs.jobs[0].run_attempt=2;},
  f=>{f.observations.checks.check_runs[8].conclusion='failure';},
  f=>{f.observations.prRun.status='in_progress';}
 ])failed(edit,'CT_PR_EIGHT_CHECK_JOBS_CROSS_API_REJECTED');
});
test('CT: push cannot skip live governance, baseline or any other required job',()=>{
 for(const name of REQUIRED_JOBS.filter(n=>n!=='source-merge-lineage-hold')){
  failed(f=>{
   const x=f.observations.checks.check_runs.find(c=>
    c.check_suite.id===PS&&c.name===name);
   x.conclusion='skipped';
  },'CT_PUSH_JOB_CHECK_ID_SHA_APP_ATTEMPT_OR_STATUS_MISMATCH');
 }
});
test('CT: PR-only lineage must be truly skipped on push',()=>{
 failed(f=>{
  const name='source-merge-lineage-hold';
  f.observations.checks.check_runs.find(x=>x.name===name&&x.check_suite.id===PS)
   .conclusion='success';
 },'CT_PUSH_JOB_CHECK_ID_SHA_APP_ATTEMPT_OR_STATUS_MISMATCH');
});
test('CT: forged app or URL, wrong SHA and cross-run job ID fail-closed',()=>{
 for(const update of [
  f=>{f.observations.checks.check_runs[0].app.id=2;},
  f=>{f.observations.checks.check_runs[0].details_url='https://evil.example/job';},
  f=>{f.observations.pushJobs.jobs[0].html_url='https://evil.example';},
  f=>{f.observations.pushJobs.jobs[0].run_id=PR;},
  f=>{f.observations.pushJobs.jobs[0].head_sha='e'.repeat(40);},
  f=>{f.observations.pushJobs.jobs[0].id=200000;},
  f=>{f.observations.pushJobs.jobs[0].run_attempt=2;}
 ])failed(update,'CT_PUSH_JOB_CHECK_ID_SHA_APP_ATTEMPT_OR_STATUS_MISMATCH');
});
test('CT: duplicate, extra and truncated current push jobs cannot count as exact',()=>{
 for(const edit of [
  f=>{f.observations.pushJobs.jobs.pop();},
  f=>{f.observations.pushJobs.jobs[1].name=f.observations.pushJobs.jobs[0].name;},
  f=>{f.observations.pushJobs.total_count=99;},
  f=>{f.observations.pushJobs.jobs[1].name='fake-approve';}
 ]){
  const r=assess(edit);
  assert.equal(r.completedTwoEventTechnicalReceiptVerified,false);
 }
});
test('CT: unbounded checks or duplicate current-suite context denied',()=>{
 for(const edit of [
  f=>{f.observations.checks.total_count=99;},
  f=>{f.observations.checks.check_runs[1].name='baseline';},
  f=>{f.observations.checks.check_runs[0].check_suite.id=RS;},
  f=>{f.observations.checks.check_runs.push(f.observations.checks.check_runs[0]);f.observations.checks.total_count++;}
 ]){
  const r=assess(edit);
  assert.equal(r.completedTwoEventTechnicalReceiptVerified,false);
 }
});
test('CT: wrong workflow, prior attempt, aborted workflow or foreign repository rejected',()=>{
 for(const edit of [
  f=>{f.observations.pushRun.workflow_id=1;},
  f=>{f.observations.pushRun.name='Shadow CI';},
  f=>{f.observations.pushRun.path='.github/workflows/attacker.yml';},
  f=>{f.observations.pushRun.status='in_progress';},
  f=>{f.observations.pushRun.conclusion='failure';},
  f=>{f.observations.pushRun.repository.full_name='attacker/other';},
  f=>{f.observations.pushRun.pull_requests=[];}
 ])failed(edit,'CT_COMPLETED_PUSH_RUN_SOURCE_UNVERIFIED');
});
test('CT: denied official source never becomes observed success',()=>{
 for(const key of Object.keys(statuses)){
  const result=assess(f=>{f.statuses[key]='access_denied'});
  assert.equal(result.completedTwoEventTechnicalReceiptVerified,false,key);
  assert.ok(result.anomalyCodes.includes('CT_'+key.toUpperCase()+'_SOURCE_NOT_READ'));
 }
});
test('CT: immutable official GET read sequence binds both event runs once',async()=>{
 const f=make(),log=[];
 const paths=[
  '/pulls/1',PUSH_REF_ROUTE,runRoute(PUSH),runRoute(PR),
  checksRoute(HEAD),jobsRoute(PUSH),jobsRoute(PR),'/pulls/1'
 ];
 const responses=[
  f.observations.prBefore,f.observations.branch,f.observations.pushRun,
  f.observations.prRun,f.observations.checks,f.observations.pushJobs,
  f.observations.prJobs,f.observations.prAfter
 ];
 let cursor=0;
 const r=await verifyDualEventReceipt({
  pushId:PUSH,prId:PR,proposal:f.proposal,token:'test',
  fetchImpl:async(url,init)=>{
   log.push(url);
   assert.equal(init.method,'GET');
   assert.equal(init.redirect,'error');
   assert.equal(url,ROOT+paths[cursor]);
   return response(url,responses[cursor++]);
  }
 });
 assert.deepEqual(log,paths.map(p=>ROOT+p));
 assert.equal(r.completedTwoEventTechnicalReceiptVerified,true,r.anomalyCodes.join('|'));
});
test('CT: source run mismatch precludes cross-API check/job reads',async()=>{
 const f=make();f.observations.pushRun.head_sha='d'.repeat(40);
 const urls=[];
 const r=await verifyDualEventReceipt({
  pushId:PUSH,prId:PR,proposal:f.proposal,token:'test',
  fetchImpl:async(url)=>{
   urls.push(url);
   if(url===ROOT+'/pulls/1')return response(url,f.observations.prBefore);
   if(url===ROOT+PUSH_REF_ROUTE)return response(url,f.observations.branch);
   if(url===ROOT+runRoute(PUSH))return response(url,f.observations.pushRun);
   if(url===ROOT+runRoute(PR))return response(url,f.observations.prRun);
   throw Error('unapproved cross-read');
  }
 });
 assert.deepEqual(urls,[
  ROOT+'/pulls/1',ROOT+PUSH_REF_ROUTE,ROOT+runRoute(PUSH),
  ROOT+runRoute(PR),ROOT+'/pulls/1'
 ]);
 assert.equal(r.completedTwoEventTechnicalReceiptVerified,false);
});
test('CT: missing operator token cannot manufacture a green receipt',async()=>{
 let called=0;
 const r=await verifyDualEventReceipt({
  pushId:PUSH,prId:PR,token:'',proposal:structuredClone(proposal),
  fetchImpl:async()=>{called++;throw Error('must not call');}
 });
 assert.equal(called,0);
 assert.equal(r.completedTwoEventTechnicalReceiptVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
