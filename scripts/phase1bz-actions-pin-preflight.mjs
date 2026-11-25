import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1BZ: deny-only local Actions ref custody. The pinned SHAs were
// observed in actual GitHub-hosted CI logs on 2026-11-18. A local checkout
// cannot independently authenticate GitHub's publisher or runner.
export const REVIEWED_ACTIONS=Object.freeze({
 'actions/checkout':'11d5960a326750d5838078e36cf38b85af677262',
 'oven-sh/setup-bun':'0c5077e51419868618aeaa5fe8019c62421857d6',
 'actions/upload-artifact':'ea165f8d65b6e75b540449e92b4886f43607fa02'
});
const EXPECTED_WORKFLOWS=Object.freeze(['ci.yml']);
const sha256=value=>createHash('sha256').update(value).digest('hex');
// Phase 1CA: bounded, fail-closed CI YAML job/scope drift detector.
// Intentionally NOT a general YAML parser, authoritative GitHub policy or
// third-party attestation. Reject alternate/ambiguous syntax rather than infer.
function phase1caWorkflowShapeAnomalies(input) {
 const errors=new Set();
 const lines=input.split('\n');
 if(/[\r\t\0]/.test(input))errors.add('CA_AMBIGUOUS_YAML_WHITESPACE');
 const top=lines.map((s,i)=>{
  const m=/^([A-Za-z][A-Za-z0-9_-]*):/.exec(s);
  return m?{name:m[1],index:i}:null;
 }).filter(Boolean);
 const requiredTop=['name','on','permissions','jobs'];
 if(top.map(x=>x.name).join('|')!==requiredTop.join('|'))
  errors.add('CA_DUPLICATE_OR_UNREVIEWED_TOP_LEVEL_KEY');
 const positions=Object.fromEntries(top.map(x=>[x.name,x.index]));
 if(requiredTop.some(key=>!Number.isInteger(positions[key]))) {
  errors.add('CA_REQUIRED_CI_SECTION_MISSING');
  return [...errors].sort();
 }
 if(lines[positions.name]!=='name: Phase 0 baseline' ||
    lines[positions.on]!=='on:' ||
    lines[positions.permissions]!=='permissions:' ||
    lines[positions.jobs]!=='jobs:')
  errors.add('CA_INLINE_OR_CHANGED_CI_ROOT');
 const events=lines.slice(positions.on+1,positions.permissions)
   .filter(x=>x.trim()&&!x.trim().startsWith('#'));
 if(events.join('|')!=='  push:|  pull_request:')
  errors.add('CA_CI_TRIGGER_SHADOWING');
 const globalScope=lines.slice(positions.permissions+1,positions.jobs)
   .filter(x=>x.trim()&&!x.trim().startsWith('#'));
 if(globalScope.join('|')!=='  contents: read')
  errors.add('CA_GLOBAL_TOKEN_SCOPE_SHADOWING');
 const expectedNames=[
  'baseline','build-input-provenance','review-vendor-intake-hold',
  'independent-evidence-hold','live-github-governance-hold',
  'source-merge-lineage-hold','production-runtime-scope',
  'mysql-integration'
 ];
 const starts=[];
 for(let i=positions.jobs+1;i<lines.length;i++){
  const line=lines[i];
  if(/^  [^ \t#]/.test(line)){
   const match=/^  ([a-z][a-z0-9-]*):$/.exec(line);
   if(!match)errors.add('CA_UNREVIEWED_JOB_DECLARATION');
   else starts.push({name:match[1],index:i});
  }
 }
 if(starts.map(x=>x.name).join('|')!==expectedNames.join('|'))
  errors.add('CA_UNREVIEWED_OR_MISSING_CI_JOB');
 const expectedPermissions={
  'live-github-governance-hold':['    permissions:','      contents: read','      pull-requests: read','      actions: read','      checks: read'],
  'source-merge-lineage-hold':['    permissions:','      contents: read']
 };
 for(let i=0;i<starts.length;i++){
  const {name,index}=starts[i];
  const block=lines.slice(index,(starts[i+1]?.index??lines.length));
  const runners=block.filter(x=>/^    runs-on\s*:/.test(x));
  if(runners.length!==1||runners[0]!=='    runs-on: ubuntu-24.04')
   errors.add('CA_RUNNER_IMAGE_OR_PLACEMENT_DRIFT');
  const timeouts=block.filter(x=>/^    timeout-minutes\s*:/.test(x));
  if(timeouts.length!==1||
     !/^    timeout-minutes: (?:[1-9]|1[0-9]|20)$/.test(timeouts[0]))
   errors.add('CA_JOB_TIMEOUT_UNBOUNDED');
  if(block.filter(x=>/^    steps\s*:/.test(x)).length!==1)
   errors.add('CA_UNREVIEWED_JOB_STEPS_SHAPE');
  const jobPermissions=block.map((x,k)=>/^\s+permissions\s*:/.test(x)?k:-1)
    .filter(k=>k>=0);
  const required=expectedPermissions[name]??[];
  if(required.length===0){
   if(jobPermissions.length)errors.add('CA_UNEXPECTED_JOB_TOKEN_OVERRIDE');
  }else{
   const start=jobPermissions[0];
   const actual=start===undefined?[]:block.slice(start,start+required.length);
   if(jobPermissions.length!==1||actual.join('|')!==required.join('|')||
      /^      [a-z][a-z-]*\s*:/.test(block[start+required.length]??''))
    errors.add('CA_JOB_TOKEN_SCOPE_WIDENED');
  }
  const conditions=block.filter(x=>/^    if\s*:/.test(x));
  if(name==='source-merge-lineage-hold'){
   if(conditions.length!==1||
      conditions[0]!=="    if: github.event_name == 'pull_request'")
    errors.add('CA_MERGE_LINEAGE_EVENT_GUARD_DRIFT');
  }else if(conditions.length)errors.add('CA_UNREVIEWED_JOB_SKIP_CONDITION');
  if(block.some(x=>/^\s+(?:continue-on-error|environment|container|uses)\s*:/.test(x) &&
                       !/^\s+-?\s*uses\s*:/.test(x)))
   errors.add('CA_JOB_OR_STEP_PRIVILEGE_BYPASS');
 }
 // The only currently reviewed interpolation values are the 3 read-only,
 // source-bound API inputs in the GitHub observer job. No PR title/body,
 // shell, arbitrary event payload, secret or repository expression admitted.
 const expressionToken=String.fromCharCode(36)+'{{';
 const expressions=lines.filter(x=>x.includes(expressionToken)).map(x=>x.trim());
 const allowed=[
  // Dedicated Phase 1CS push-only official ref and current-run GET.
  'GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  'GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  'GITHUB_EXPECTED_PR_HEAD_SHA: '+expressionToken+' github.event.pull_request.head.sha }}',
  'GITHUB_EXPECTED_PR_BASE_SHA: '+expressionToken+' github.event.pull_request.base.sha }}',
  // Phase 1CL reuses the SAME read-only Github Actions token and exact
  // pull_request.head.sha (no arbitrary event body, PR author text or
  // additional privilege). These must occur only inside the named CL step.
  'GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  'GITHUB_EXPECTED_PR_HEAD_SHA: '+expressionToken+' github.event.pull_request.head.sha }}',
  // Phase 1CN reuses the existing GitHub read-only token in the exact
  // named source-bound ruleset inventory observer step, never a PAT/secret.
  'GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  // Phase 1CP reuses the same read-only Github token to fetch the current
  // exact run and real check-runs. Only actions:read/checks:read, no writes.
  'GITHUB_READ_TOKEN: '+expressionToken+' github.token }}'
 ];
 if(expressions.length!==allowed.length||
    expressions.some((value,index)=>value!==allowed[index]))
  errors.add('CA_UNREVIEWED_GITHUB_EXPRESSION');
 // The second two expressions are permissible ONLY in this fixed read-only
 // GitHub observer step, with a literal program and no extra shell input.
 const csHeader='      - name: Phase 1CS exact current push ref, PR head and workflow identity HARD HOLD';
 const byHeader='      - name: Phase 1BY official GitHub PR reviews and effective branch rules read-only observation (HARD HOLD)';
 const csExpected=[csHeader,
  "        if: github.event_name == 'push'",
  '        env:',
  '          GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  '        run: node scripts/phase1cs-push-head-governance.mjs --ci-hold'];
 const byExpected=[byHeader,
  "        if: github.event_name == 'pull_request'",
  '        env:',
  '          GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  '          GITHUB_EXPECTED_PR_HEAD_SHA: '+expressionToken+' github.event.pull_request.head.sha }}',
  '          GITHUB_EXPECTED_PR_BASE_SHA: '+expressionToken+' github.event.pull_request.base.sha }}',
  '        run: node scripts/phase1by-github-governance-observer.mjs --ci-hold'];
 for(const [header,expected] of [[csHeader,csExpected],[byHeader,byExpected]]){
  const at=lines.indexOf(header);
  if(at<0||lines.slice(at,at+expected.length).join('|')!==expected.join('|')||
     lines.filter(line=>line===header).length!==1)
   errors.add('CA_UNREVIEWED_CS_PUSH_OR_BY_PR_EVENT_GUARD');
 }
 const startLive=lines.indexOf('  live-github-governance-hold:');
 const endLive=lines.indexOf('  source-merge-lineage-hold:');
 const actualStepIfs=lines.slice(startLive,endLive).filter(x=>/^        if:/.test(x));
 const expectedStepIfs=[
  "        if: github.event_name == 'push'",
  ...Array(5).fill("        if: github.event_name == 'pull_request'"),
  "        if: always() && github.event_name == 'pull_request'",
  "        if: always() && github.event_name == 'push'"
 ];
 if(actualStepIfs.join('|')!==expectedStepIfs.join('|'))
  errors.add('CA_UNREVIEWED_GOVERNANCE_EVENT_STEP_GUARD');
 const csUploadHeader='      - name: Upload UNSIGNED exact push-source governance receipt (never release approval)';
 const csUpload=[csUploadHeader,
  "        if: always() && github.event_name == 'push'",
  '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  '        with:',
  '          name: phase1cs-push-ref-pr-head-held-unsigned',
  '          path: phase1cs-push-governance-hold.json',
  '          if-no-files-found: error'];
 const uploadIndex=lines.indexOf(csUploadHeader);
 if(uploadIndex<0||lines.slice(uploadIndex,uploadIndex+csUpload.length).join('|')!==csUpload.join('|')||
    lines.filter(x=>x===csUploadHeader).length!==1)
  errors.add('CA_UNREVIEWED_CS_PUSH_ARTIFACT');
 const prUpload='      - name: Upload source-bound UNSIGNED read-only GitHub governance observation; NOT release approval';
 if(lines.indexOf(prUpload)<0||lines[lines.indexOf(prUpload)+1]!==
    "        if: always() && github.event_name == 'pull_request'")
  errors.add('CA_UNREVIEWED_PR_GOVERNANCE_ARTIFACT_GUARD');
 const clHeader='      - name: Phase 1CL live main-branch CODEOWNERS and PR requested reviewer actual API state (HARD HOLD)';
 const clIndex=lines.indexOf(clHeader);
 const clExpected=[
  clHeader,
  "        if: github.event_name == 'pull_request'",
  '        env:',
  '          GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  '          GITHUB_EXPECTED_PR_HEAD_SHA: '+expressionToken+' github.event.pull_request.head.sha }}',
  '        run: node scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs --ci-hold'
 ];
 if(clIndex<0||lines.slice(clIndex,clIndex+clExpected.length).join('|')!==
    clExpected.join('|')||lines.filter(x=>x===clHeader).length!==1)
  errors.add('CA_UNREVIEWED_PHASE1CL_READONLY_STEP_OR_SOURCE_BINDING');
 const cnHeader='      - name: Phase 1CN actual GitHub main ruleset inventory and hidden bypass actor visibility (HARD HOLD)';
 const cnIndex=lines.indexOf(cnHeader);
 const cnExpected=[
  cnHeader,
  "        if: github.event_name == 'pull_request'",
  '        env:',
  '          GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  '        run: node scripts/phase1cn-ruleset-bypass-reconciliation.mjs --ci-hold'
 ];
 if(cnIndex<0||lines.slice(cnIndex,cnIndex+cnExpected.length).join('|')!==
    cnExpected.join('|')||lines.filter(x=>x===cnHeader).length!==1)
  errors.add('CA_UNREVIEWED_PHASE1CN_READONLY_RULESET_STEP_OR_SOURCE_BINDING');
 const coHeader='      - name: Phase 1CO exact-head real submitted reviewer evidence and independent mandate prerequisite (HARD HOLD)';
 const coIndex=lines.indexOf(coHeader);
 const coExpected=[coHeader,
  "        if: github.event_name == 'pull_request'",
  '        run: node scripts/phase1co-live-exact-head-reviewer-quorum.mjs --ci-hold'];
 if(coIndex<0||lines.slice(coIndex,coIndex+coExpected.length).join('|')!==
    coExpected.join('|')||lines.filter(x=>x===coHeader).length!==1)
  errors.add('CA_UNREVIEWED_PHASE1CO_EXACT_READONLY_OPERATOR_STEP');
 const cpHeader='      - name: Phase 1CP bound real Github Actions check app and exact current run suite (HARD HOLD)';
 const cpIndex=lines.indexOf(cpHeader);
 const cpExpected=[cpHeader,
  "        if: github.event_name == 'pull_request'",
  '        env:',
  '          GITHUB_READ_TOKEN: '+expressionToken+' github.token }}',
  '        run: node scripts/phase1cp-github-actions-check-app-source.mjs --ci-hold'];
 if(cpIndex<0||lines.slice(cpIndex,cpIndex+cpExpected.length).join('|')!==
    cpExpected.join('|')||lines.filter(x=>x===cpHeader).length!==1)
  errors.add('CA_UNREVIEWED_PHASE1CP_EXACT_RUN_CHECK_APP_READONLY_STEP');
 if(lines.some(x=>/^\s*(?:<<\s*:|[a-z][a-z-]*:\s*[&*!][^\s])/.test(x)))
  errors.add('CA_UNREVIEWED_YAML_MERGE_OR_TAG');
 return [...errors].sort();
}

export function assessActionsPinCustody({workflow,workflowFiles}={}){
 const errors=new Set();
 if(typeof workflow!=='string'||!workflow.length||
    Buffer.byteLength(workflow)>131072)
  errors.add('BZ_WORKFLOW_MISSING_OR_OVERSIZED');
 if(!Array.isArray(workflowFiles)||workflowFiles.length!==1||
    workflowFiles[0]!==EXPECTED_WORKFLOWS[0])
  errors.add('BZ_UNREVIEWED_WORKFLOW_FILE');
 const input=typeof workflow==='string'?workflow:'';
 const actionLines=input.split(/\r?\n/).filter(line=>/^\s*(?:-\s+)?uses\s*:/.test(line));
 const allUsesCount=(input.match(/\buses\s*:/g)||[]).length;
 if(!actionLines.length||allUsesCount!==actionLines.length)
  errors.add('BZ_UNREVIEWED_YAML_ACTION_REFERENCE_SYNTAX');
 const observed={};
 for(const line of actionLines){
  const m=/^\s*(?:-\s+)?uses\s*:\s*([^\s#]+)\s*(?:#.*)?$/.exec(line);
  if(!m){
   errors.add('BZ_DYNAMIC_OR_MULTILINE_ACTION_REFERENCE');
   continue;
  }
  const actionRef=m[1];
  const at=actionRef.lastIndexOf('@');
  const ownerAction=at>0?actionRef.slice(0,at):'';
  const commit=at>0?actionRef.slice(at+1):'';
  if(!Object.hasOwn(REVIEWED_ACTIONS,ownerAction)||
     !/^[a-f0-9]{40}$/.test(commit)||
     REVIEWED_ACTIONS[ownerAction]!==commit)
   errors.add('BZ_UNREVIEWED_OR_MUTABLE_ACTION_REF');
  else observed[ownerAction]=(observed[ownerAction]||0)+1;
 }
 for(const name of Object.keys(REVIEWED_ACTIONS))
  if(!observed[name])errors.add('BZ_REQUIRED_REVIEWED_ACTION_MISSING');
 if(/^\s*(?:pull_request_target|workflow_run|workflow_dispatch|repository_dispatch)\s*:/m.test(input)||
    /^\s*(?:id-token|contents|actions|packages|security-events)\s*:\s*write\s*$/m.test(input)||
    /^\s*(?:environment|secrets)\s*:/m.test(input))
  errors.add('BZ_CI_EVENT_PERMISSION_OR_SECRET_DRIFT');
 if(!/^on:\s*\n\s*push:\s*\n\s*pull_request:\s*$/m.test(input)||
    !/^permissions:\s*\n\s*contents:\s*read\s*$/m.test(input))
  errors.add('BZ_READ_ONLY_CI_TRIGGER_OR_SCOPE_MISSING');
 const phase1caAnomalies=phase1caWorkflowShapeAnomalies(input);
 for(const code of phase1caAnomalies)errors.add(code);
 return Object.freeze({
  phase1caBoundedJobScopeConsistent:phase1caAnomalies.length===0,
  phase1caAnomalyCodes:Object.freeze(phase1caAnomalies),
  independentCiWorkflowSemanticsAttested:false,
  schemaVersion:1,phase:'1BZ',kind:'UNSIGNED_ACTIONS_PIN_CUSTODY_HOLD',
  immutableSelectedActionRefsCorroborated:errors.size===0,
  anomalyCodes:Object.freeze([...errors].sort()),
  selectedActionUses:actionLines.length,
  selectedWorkflowFiles:workflowFiles,
  selectedWorkflowSha256:sha256(input),
  expectedPinnedActionCommitIds:REVIEWED_ACTIONS,
  publisherIdentityIndependentlyVerified:false,
  actionExecutionAndRunnerIndependentlyAttested:false,
  externalWormRetentionVerified:false,
  upstreamPicomatchFixVerified:false,
  criticalHighDependencyGateWaived:false,
  independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('BZ only supports --ci-hold');
 const dir='.github/workflows';
 const list=readdirSync(dir).sort();
 const file=dir+'/ci.yml';
 const stat=lstatSync(file);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size>131072)
  throw Error('BZ workflow must be a bounded regular file');
 const report=assessActionsPinCustody({
  workflow:readFileSync(file,'utf8'),workflowFiles:list
 });
 writeFileSync('phase1bz-actions-pin-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(!report.immutableSelectedActionRefsCorroborated||
    report.productionReleaseAuthorized||report.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(error){
  console.error('Phase 1BZ Actions source custody fail-closed:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 }
}
