import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessActionsPinCustody,REVIEWED_ACTIONS}
 from '../scripts/phase1bz-actions-pin-preflight.mjs';
const workflow=readFileSync('.github/workflows/ci.yml','utf8');
const good={workflow,workflowFiles:['ci.yml']};
const evaluate=changes=>assessActionsPinCustody({...good,...changes});
test('BZ: checked-in immutable action pins and only the CI workflow are held',()=>{
 const r=evaluate();
 assert.equal(r.immutableSelectedActionRefsCorroborated,true,r.anomalyCodes.join(','));
 assert.ok(r.selectedActionUses>=3);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.criticalHighDependencyGateWaived,false);
 assert.equal(r.publisherIdentityIndependentlyVerified,false);
 assert.ok(/^[a-f0-9]{64}$/.test(r.selectedWorkflowSha256));
});
test('BZ: any mutable tag or changed action commit is rejected',()=>{
 for(const [name,sha] of Object.entries(REVIEWED_ACTIONS)){
  for(const substitution of [name+'@v4',name+'@'+'a'.repeat(40),name+'@main']){
   const altered=workflow.replace(name+'@'+sha,substitution);
   assert.notEqual(altered,workflow);
   assert.ok(evaluate({workflow:altered}).anomalyCodes.includes(
    'BZ_UNREVIEWED_OR_MUTABLE_ACTION_REF'));
  }
 }
});
test('BZ: unknown vendor, Docker action and expression syntax are rejected',()=>{
 const old='actions/checkout@'+REVIEWED_ACTIONS['actions/checkout'];
 for(const value of ['attacker/fake@'+'b'.repeat(40),
  'docker://alpine:latest','./.github/actions/unreviewed',
  "'"+old+"'"]){
  const changed=workflow.replace(old,value);
  assert.equal(evaluate({workflow:changed}).immutableSelectedActionRefsCorroborated,false);
 }
});
test('BZ: hidden inline action mappings or multiline uses never get overlooked',()=>{
 for(const added of [
  '\n      - { uses: attacker/steal@v1 }\n',
  '\n      - uses:\n          attacker/supply-chain@v2\n',
  '\n      - uses: attacker/other@v1\n'
 ]){
  assert.equal(evaluate({workflow:workflow+added}).immutableSelectedActionRefsCorroborated,false);
 }
});
test('BZ: extra, absent or substituted workflow filenames are denied',()=>{
 for(const filenames of [[],['ci.yml','release.yml'],['other.yml'],['ci.yml','ci.yml']]){
  assert.ok(evaluate({workflowFiles:filenames}).anomalyCodes.includes('BZ_UNREVIEWED_WORKFLOW_FILE'));
 }
});
test('BZ: widened permissions, PR target and dispatch triggers fail closed',()=>{
 const variants=[
  workflow.replace('  pull_request:','  pull_request_target:'),
  workflow.replace('  contents: read','  contents: write'),
  workflow+'\nworkflow_dispatch:\n',
  workflow+'\n    id-token: write\n',
  workflow+'\n    environment: production\n'
 ];
 for(const changed of variants)
  assert.equal(evaluate({workflow:changed}).immutableSelectedActionRefsCorroborated,false);
});
test('BZ: missing required pinned action and malformed source reject',()=>{
 const ref='oven-sh/setup-bun@'+REVIEWED_ACTIONS['oven-sh/setup-bun'];
 const stripped=workflow.replaceAll('- uses: '+ref,'- run: echo omitted');
 assert.ok(evaluate({workflow:stripped}).anomalyCodes.includes('BZ_REQUIRED_REVIEWED_ACTION_MISSING'));
 assert.equal(evaluate({workflow:'x'.repeat(131073)}).immutableSelectedActionRefsCorroborated,false);
 assert.equal(evaluate({workflow:''}).immutableSelectedActionRefsCorroborated,false);
});
test('BZ: source digest changes even when syntax remains valid; not release attestation',()=>{
 const baseline=evaluate();
 const changed=evaluate({workflow:workflow+'\n# comment added\n'});
 assert.equal(changed.immutableSelectedActionRefsCorroborated,true);
 assert.notEqual(baseline.selectedWorkflowSha256,changed.selectedWorkflowSha256);
 assert.equal(changed.actionExecutionAndRunnerIndependentlyAttested,false);
 assert.equal(changed.externalWormRetentionVerified,false);
 assert.equal(changed.productionReleaseBlocked,true);
});
