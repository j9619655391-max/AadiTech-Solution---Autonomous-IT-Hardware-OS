import test from 'node:test';
import assert from 'node:assert/strict';
import {BRANCH,REPOSITORY,PUSH_REF_ROUTE,assessPushObservation,collectPushObservation}
 from '../scripts/phase1cs-push-head-governance.mjs';
import {readOfficialCheckSource}
 from '../scripts/phase1cp-github-actions-check-app-source.mjs';
const sha='a'.repeat(40),base='b'.repeat(40),merge='c'.repeat(40);
const pr=()=>({
 number:1,state:'open',draft:true,merged:false,
 user:{login:'j9619655391-max'},
 head:{sha,ref:BRANCH,repo:{full_name:REPOSITORY}},
 base:{sha:base,ref:'main',repo:{full_name:REPOSITORY}},
 merge_commit_sha:merge,updated_at:'2026-11-19T00:00:00Z'
});
const env=()=>({
 GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'push',
 GITHUB_JOB:'live-github-governance-hold',
 GITHUB_REPOSITORY:REPOSITORY,
 GITHUB_REF:'refs/heads/'+BRANCH,GITHUB_SHA:sha,
 GITHUB_RUN_ID:'123'
});
const run=()=>({
 id:123,event:'push',head_sha:sha,head_branch:BRANCH,
 workflow_id:408632517,name:'Phase 0 baseline',
 path:'.github/workflows/ci.yml',
 repository:{full_name:REPOSITORY},head_repository:{full_name:REPOSITORY},
 run_attempt:1,check_suite_id:321,status:'in_progress',conclusion:null,
 pull_requests:[{number:1,head:{sha},base:{sha:base}}]
});
const observation=()=>({
 first:{status:'read',data:pr()},
 branch:{status:'read',data:{ref:'refs/heads/'+BRANCH,
  object:{type:'commit',sha,url:'https://api.github.com/repos/'+REPOSITORY+'/git/commits/'+sha}}},
 run:{status:'read',data:run()},
 last:{status:'read',data:pr()}
});
const assess=(mutate=()=>{},modifyEnv=()=>{})=>{
 const o=observation(),e=env();mutate(o);modifyEnv(e);
 return assessPushObservation({observations:o,environment:e});
};
test('CS: exact push/PR source agrees; production remains HARD HOLD',()=>{
 const r=assess();
 assert.equal(r.actualPushSourceStructurallyValid,true,r.anomalyCodes.join(','));
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.externallySigned,false);
});
test('CS: pull_request test merge is not an allowed push identity',()=>{
 const r=assess(()=>{},e=>{e.GITHUB_EVENT_NAME='pull_request';e.GITHUB_REF='refs/pull/1/merge';});
 assert.ok(r.anomalyCodes.includes('CS_NOT_EXACT_PUSH_WORKLOAD'));
});
test('CS: wrong job/repository/source/head ref are rejected',()=>{
 for(const edit of [
  e=>{e.GITHUB_JOB='baseline';},
  e=>{e.GITHUB_REPOSITORY='attacker/repo';},
  e=>{e.GITHUB_HEAD_REF='unexpected';},
  e=>{e.GITHUB_SHA='Z'.repeat(40);}
 ])assert.equal(assess(()=>{},edit).actualPushSourceStructurallyValid,false);
});
test('CS: an advanced official ref or altered commit reference is held',()=>{
 for(const edit of [
  o=>{o.branch.data.object.sha='d'.repeat(40);},
  o=>{o.branch.data.ref='refs/heads/main';},
  o=>{o.branch.data.object.type='tag';},
  o=>{o.branch.data.object.url='https://evil.example/commit';}
 ])assert.ok(assess(edit).anomalyCodes.includes('CS_OFFICIAL_BRANCH_REF_OR_SHA_DRIFT'));
});
test('CS: author, head, base and Draft PR must remain correct',()=>{
 for(const edit of [
  o=>{o.first.data.head.sha='d'.repeat(40);o.last.data.head.sha='d'.repeat(40);},
  o=>{o.first.data.user.login='untrusted';},
  o=>{o.last.data.draft=false;},
  o=>{o.first.data.base.ref='unapproved';}
 ])assert.equal(assess(edit).actualPushSourceStructurallyValid,false);
});
test('CS: PR update, merge or base race is held',()=>{
 for(const edit of [
  o=>{o.last.data.updated_at='2026-11-19T00:01:00Z';},
  o=>{o.last.data.merge_commit_sha='d'.repeat(40);},
  o=>{o.last.data.base.sha='d'.repeat(40);}
 ])assert.ok(assess(edit).anomalyCodes.includes('CS_PR_MUTATED_DURING_CUSTODY_READS'));
});
test('CS: foreign run, unapproved workflow, skipped or completed run denied',()=>{
 for(const edit of [
  o=>{o.run.data.event='pull_request';},
  o=>{o.run.data.id=124;},
  o=>{o.run.data.head_sha='d'.repeat(40);},
  o=>{o.run.data.workflow_id=1;},
  o=>{o.run.data.path='.github/workflows/other.yml';},
  o=>{o.run.data.run_attempt=0;},
  o=>{o.run.data.pull_requests=[];},
  o=>{o.run.data.status='completed';o.run.data.conclusion='success';}
 ])assert.ok(assess(edit).anomalyCodes.includes('CS_OFFICIAL_CURRENT_PUSH_RUN_SOURCE_UNVERIFIED'));
});
test('CS: missing, denied and partial source reads cannot become success',()=>{
 for(const field of ['first','branch','run','last']){
  const r=assess(o=>{o[field]={status:'access_denied',data:null};});
  assert.equal(r.actualPushSourceStructurallyValid,false);
  assert.ok(r.anomalyCodes.includes('CS_OFFICIAL_'+field.toUpperCase()+'_NOT_READ'));
 }
});
test('CS: malformed Actions run id never creates a valid source',()=>{
 for(const id of ['', '0','123;curl evil','NaN','999999999999999999999999']){
  assert.equal(assess(()=>{},e=>{e.GITHUB_RUN_ID=id;}).actualPushSourceStructurallyValid,false);
 }
});
test('CS: hard allowlist forbids arbitrary ref path injection',async()=>{
 assert.equal(PUSH_REF_ROUTE,'/git/ref/heads/chore/phase0-foundation-20261106');
 await assert.rejects(
  readOfficialCheckSource('/git/ref/heads/main','x',async()=>{throw Error('must not call');}),
  /CP_UNREVIEWED_GITHUB_CHECK_SOURCE_ROUTE/
 );
});
test('CS: no token means no source admission or inferred approval',async()=>{
 const result=await collectPushObservation({token:'',runId:123,
  fetchImpl:async()=>{throw Error('must not call');}});
 for(const field of ['first','branch','run','last'])
  assert.notEqual(result[field].status,'read');
 assert.equal(assessPushObservation({
  observations:result,environment:env()
 }).actualPushSourceStructurallyValid,false);
});
