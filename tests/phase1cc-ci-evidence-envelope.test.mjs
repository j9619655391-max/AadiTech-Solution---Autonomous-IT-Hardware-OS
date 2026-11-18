import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {BUILD_INPUT_PATHS,makeBuildInputInventory}
 from '../scripts/phase1bv-build-input-provenance.mjs';
import {assessActionsPinCustody}
 from '../scripts/phase1bz-actions-pin-preflight.mjs';
import {assessCiSourceReceipt,verifyUnsignedEnvelopeDigest}
 from '../scripts/phase1cc-ci-evidence-envelope.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
const base='b'.repeat(40),head='c'.repeat(40),merge='d'.repeat(40);
const sources=Object.fromEntries(BUILD_INPUT_PATHS.map(path=>
 [path,readFileSync(path,'utf8')]));
const workflow=sources['.github/workflows/ci.yml'];
const files=['ci.yml'];
const clone=x=>structuredClone(x);
function fixture(mode='pull_request'){
 const sha=mode==='push'?head:merge;
 const environment={
  CI:'true',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:REPO,
  GITHUB_EVENT_NAME:mode,
  GITHUB_REF:mode==='push'?'refs/heads/'+DEV:'refs/pull/1/merge',
  GITHUB_HEAD_REF:mode==='push'?'':DEV,
  GITHUB_BASE_REF:mode==='push'?'':'main',
  GITHUB_SHA:sha
 };
 const event=mode==='push'?{
  ref:'refs/heads/'+DEV,after:head,deleted:false,forced:false,
  repository:{full_name:REPO}
 }:{
  number:1,repository:{full_name:REPO},
  pull_request:{
   number:1,state:'open',draft:true,merged:false,
   user:{login:'j9619655391-max'},
   head:{ref:DEV,sha:head,repo:{full_name:REPO}},
   base:{ref:'main',sha:base,repo:{full_name:REPO}},
   merge_commit_sha:'e'.repeat(40)
  }
 };
 const commitRaw='tree '+'a'.repeat(40)+'\n'+
  (mode==='push'?'parent '+base+'\n':
   'parent '+base+'\nparent '+head+'\n')+
  'author CI <ci@example.invalid> 1 +0000\n\nmessage\n';
 const bv={
  boundary:{localBuildInputBoundaryConsistent:true,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'},
  inventory:makeBuildInputInventory(sources,{GITHUB_SHA:sha})
 };
 const bz=assessActionsPinCustody({workflow,workflowFiles:files});
 const rawBV=JSON.stringify(bv),rawBZ=JSON.stringify(bz);
 return {bv,bz,sources,environment,event,checkoutSha:sha,commitRaw,rawBV,rawBZ};
}
const evaluate=(change={},mode='pull_request')=>
 assessCiSourceReceipt({...fixture(mode),...change});
test('1CC: PR merge exact two parents and locally rehashed source inventory match',()=>{
 const report=evaluate();
 assert.equal(report.localSourceAndArtifactsConsistent,true,
  report.body.sourceAndReceiptAnomalyCodes.join(','));
 assert.equal(report.body.sourceHeadSha,head);
 assert.equal(report.body.baseSha,base);
 assert.deepEqual(report.body.observedGitParentShas,[base,head]);
 assert.equal(report.body.selectedSources.length,BUILD_INPUT_PATHS.length);
 assert.ok(BUILD_INPUT_PATHS.includes('scripts/phase1cc-ci-evidence-envelope.mjs'));
 assert.ok(BUILD_INPUT_PATHS.includes('tests/phase1cc-ci-evidence-envelope.test.mjs'));
 assert.equal(verifyUnsignedEnvelopeDigest(report),true);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.releaseDecision,'HOLD');
});
test('1CC: stale webhook merge SHA is metadata, actual checked out parents govern',()=>{
 const r=evaluate();
 assert.equal(r.localSourceAndArtifactsConsistent,true);
 assert.notEqual(r.body.checkedOutSha,merge.replace(/d/g,'e'));
});
test('1CC: valid development push binds its own real Git SHA but grants no release',()=>{
 const r=evaluate({},'push');
 assert.equal(r.localSourceAndArtifactsConsistent,true,
  r.body.sourceAndReceiptAnomalyCodes.join(','));
 assert.equal(r.body.sourceHeadSha,head);
 assert.equal(r.body.githubEventName,'push');
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CC: PR second-parent substitution, swapped parents or wrong refs are denied',()=>{
 const x=fixture();
 for(const changes of [
  {commitRaw:x.commitRaw.replace('parent '+head,'parent '+'f'.repeat(40))},
  {commitRaw:x.commitRaw.replace('parent '+base+'\nparent '+head,
    'parent '+head+'\nparent '+base)},
  {environment:{...x.environment,GITHUB_REF:'refs/heads/main'}},
  {environment:{...x.environment,GITHUB_SHA:'0'.repeat(40)}},
  {event:{...x.event,number:2}},
  {event:{...x.event,repository:{full_name:'attacker/evil'}}}
 ]){
  const r=assessCiSourceReceipt({...x,...changes});
  assert.equal(r.localSourceAndArtifactsConsistent,false,
   JSON.stringify(changes));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('1CC: push rollback, force, ref spoof and checkout drift are rejected',()=>{
 const x=fixture('push');
 for(const changes of [
  {event:{...x.event,after:'0'.repeat(40)}},
  {event:{...x.event,forced:true}},
  {event:{...x.event,deleted:true}},
  {event:{...x.event,ref:'refs/heads/main'}},
  {checkoutSha:'9'.repeat(40)},
  {environment:{...x.environment,GITHUB_REPOSITORY:'attacker/repo'}}
 ]){
  const r=assessCiSourceReceipt({...x,...changes});
  assert.equal(r.localSourceAndArtifactsConsistent,false);
 }
});
test('1CC: tampering one build source byte or omitting a source is detected',()=>{
 const x=fixture();
 const tampered={...x.sources,'package.json':x.sources['package.json']+'\n'};
 assert.ok(assessCiSourceReceipt({...x,sources:tampered}).body
  .sourceAndReceiptAnomalyCodes.includes(
   'CC_BUILD_INPUT_INVENTORY_FILE_OR_BUNDLE_MISMATCH'));
 const absent={...x.sources};delete absent['bun.lock'];
 const r=assessCiSourceReceipt({...x,sources:absent});
 assert.ok(r.body.sourceAndReceiptAnomalyCodes.includes(
  'CC_REQUIRED_SOURCE_FILE_MISSING_OR_OVERSIZED'));
});
test('1CC: mutated SHA pins, job scopes or signoff claims never pass custody',()=>{
 const x=fixture();
 for(const changes of [
  {selectedActionUses:19},
  {selectedWorkflowSha256:'a'.repeat(64)},
  {phase1caBoundedJobScopeConsistent:false},
  {publisherIdentityIndependentlyVerified:true},
  {releaseDecision:'GO'},
  {actionExecutionAndRunnerIndependentlyAttested:true}
 ]){
  const bz={...x.bz,...changes};
  const r=assessCiSourceReceipt({...x,bz,rawBZ:JSON.stringify(bz)});
  assert.ok(r.body.sourceAndReceiptAnomalyCodes.includes(
   'CC_ACTIONS_AND_JOB_SCOPE_RECEIPT_MISMATCH'));
 }
});
test('1CC: claimed signed or WORM build inventory cannot self-approve',()=>{
 const x=fixture();
 for(const changes of [
  {signedByIndependentWitness:true},
  {verifiedExternalWormRetention:true},
  {productionReleaseAuthorized:true}
 ]){
  const bv={...x.bv,inventory:{...x.bv.inventory,...changes}};
  const r=assessCiSourceReceipt({...x,bv,rawBV:JSON.stringify(bv)});
  assert.ok(r.body.sourceAndReceiptAnomalyCodes.includes(
   'CC_BUILD_RECEIPT_SELF_APPROVAL_OR_MISSING_HOLD'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('1CC: truncated, altered, invalid or inconsistent report bytes fail closed',()=>{
 const x=fixture();
 for(const changes of [
  {rawBV:''},{rawBZ:'{not json}'},
  {rawBV:JSON.stringify({other:'fake'})},
  {rawBZ:' '.repeat(131073)}
 ]){
  const r=assessCiSourceReceipt({...x,...changes});
  assert.equal(r.localSourceAndArtifactsConsistent,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
test('1CC: malformed raw Git object or unrelated CI event never passes',()=>{
 const x=fixture();
 for(const changes of [
  {commitRaw:'tree nope\nparent nope\n'},
  {commitRaw:'tree '+'a'.repeat(40)+'\nparent '+base+'\n\n'},
  {environment:{...x.environment,GITHUB_EVENT_NAME:'workflow_dispatch'}}
 ]){
  const r=assessCiSourceReceipt({...x,...changes});
  assert.equal(r.localSourceAndArtifactsConsistent,false);
 }
});
test('1CC: domain-separated digest detects unsanctioned receipt mutation',()=>{
 const r=evaluate();
 const altered=clone(r);altered.body.sourceHeadSha='f'.repeat(40);
 assert.equal(verifyUnsignedEnvelopeDigest(altered),false);
 assert.equal(verifyUnsignedEnvelopeDigest({...r,envelopeSha256:'0'.repeat(64)}),false);
 assert.equal(verifyUnsignedEnvelopeDigest({...r,productionReleaseAuthorized:true}),false);
 assert.equal(verifyUnsignedEnvelopeDigest({...r,
  independentlySignedWorkloadProvenanceVerified:true}),false);
 assert.equal(r.independentlySignedWorkloadProvenanceVerified,false);
 assert.equal(r.externallyWitnessedImmutableRetentionVerified,false);
});
