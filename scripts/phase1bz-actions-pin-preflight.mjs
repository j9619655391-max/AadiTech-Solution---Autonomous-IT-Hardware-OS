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
 return Object.freeze({
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
