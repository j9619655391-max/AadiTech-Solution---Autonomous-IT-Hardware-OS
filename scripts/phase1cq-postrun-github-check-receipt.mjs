import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,AUTHOR,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID,
 assessProposedMainRuleset
} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {
 readOfficialCheckSource,runRoute,checksRoute
} from './phase1cp-github-actions-check-app-source.mjs';
import {readFileSync,lstatSync} from 'node:fs';

// Phase 1CQ: This is an OPERATOR-INITIATED post-run re-check. It cannot run
// inside the workflow it certifies, where checks are still pending.
// It uses only official GitHub REST GETs and a short-lived read-only token.
// Technical finished-check observation != signed provenance or release.
export const WORKFLOW_ID=408632517;
export const EXPECTED_NAME='Phase 0 baseline';
export const WORKFLOW_PATH='.github/workflows/ci.yml';
export const DEV='chore/phase0-foundation-20261106';
export const APP_ID=GITHUB_ACTIONS_INTEGRATION_ID;
const SHA=/^[a-f0-9]{40}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safeId=x=>Number.isSafeInteger(x)&&x>0;
const checkNames=new Set(REQUIRED_JOBS);
const sha256=x=>createHash('sha256').update(x).digest('hex');
const sort=(a,b)=>a.localeCompare(b);
export function assessFinishedGithubRun({
 run=null,checks=null,prBefore=null,prAfter=null,
 proposal=null,sourceStatuses={}
}={}){
 const errors=new Set();
 const policy=assessProposedMainRuleset(proposal);
 if(!policy.localProposedRestPayloadStructurallySafe)
  errors.add('CQ_UNREVIEWED_APP_PINNED_MAIN_RULESET_PROPOSAL');
 if(sourceStatuses.prBefore!=='read'||sourceStatuses.prAfter!=='read'||
    sourceStatuses.run!=='read'||sourceStatuses.checks!=='read')
  errors.add('CQ_OFFICIAL_GITHUB_SOURCE_UNAVAILABLE_OR_DENIED');
 const validPR=pr=>object(pr)&&pr.number===1&&pr.state==='open'&&
  pr.draft===true&&pr.merged===false&&pr.user?.login===AUTHOR&&
  pr.head?.ref===DEV&&pr.base?.ref==='main'&&
  pr.head?.repo?.full_name===REPO&&
  pr.base?.repo?.full_name===REPO&&
  SHA.test(pr.head?.sha??'')&&SHA.test(pr.base?.sha??'')&&
  SHA.test(pr.merge_commit_sha??'')&&
  typeof pr.updated_at==='string'&&
  Number.isFinite(Date.parse(pr.updated_at));
 const prValid=validPR(prBefore)&&validPR(prAfter);
 if(!prValid)errors.add('CQ_PR_BASE_AUTHOR_DRAFT_OR_SOURCE_IDENTITY_INVALID');
 const stable=prValid&&
  ['head','base'].every(k=>prBefore[k].sha===prAfter[k].sha)&&
  prBefore.merge_commit_sha===prAfter.merge_commit_sha&&
  prBefore.updated_at===prAfter.updated_at;
 if(!stable)errors.add('CQ_PR_CHANGED_DURING_POSTRUN_INSPECTION');
 const runValid=object(run)&&safeId(run.id)&&safeId(run.workflow_id)&&
  run.workflow_id===WORKFLOW_ID&&run.name===EXPECTED_NAME&&
  run.path===WORKFLOW_PATH&&
  run.status==='completed'&&run.conclusion==='success'&&
  run.event==='pull_request'&&run.head_branch===DEV&&
  run.repository?.full_name===REPO&&
  run.head_repository?.full_name===REPO&&
  SHA.test(run.head_sha??'')&&safeId(run.check_suite_id)&&
  safeId(run.run_attempt)&&Array.isArray(run.pull_requests)&&
  run.pull_requests.length===1&&
  run.pull_requests[0]?.number===1&&
  run.pull_requests[0]?.head?.ref===DEV&&
  run.pull_requests[0]?.base?.ref==='main'&&
  run.pull_requests[0]?.head?.sha===run.head_sha;
 if(!runValid)errors.add('CQ_COMPLETED_GITHUB_WORKFLOW_RUN_IDENTITY_INVALID');
 if(!prValid||!runValid||
    run.head_sha!==prBefore.head.sha||
    run.pull_requests[0]?.base?.sha!==prBefore.base.sha)
  errors.add('CQ_WORKFLOW_RUN_NOT_BOUND_TO_CURRENT_PR_HEAD_AND_BASE');
 const records=object(checks)&&Array.isArray(checks.check_runs)&&
  Number.isSafeInteger(checks.total_count)&&
  checks.total_count===checks.check_runs.length&&
  checks.total_count<100?checks.check_runs:null;
 if(!records)errors.add('CQ_UNBOUNDED_OR_MALFORMED_GITHUB_CHECKRUN_LIST');
 const selected=new Map();let other=0,unknown=0,duplicates=0;
 for(const item of records??[]){
  if(!object(item)||!object(item.check_suite)||!safeId(item.check_suite.id)){
   errors.add('CQ_MALFORMED_CHECK_SUITE_RECORD');continue;
  }
  if(!runValid||item.check_suite.id!==run.check_suite_id){
   other++;continue;
  }
  if(!checkNames.has(item.name)){
   unknown++;errors.add('CQ_UNREVIEWED_CHECK_IN_EXACT_SUITE');continue;
  }
  if(selected.has(item.name)){
   duplicates++;errors.add('CQ_DUPLICATE_NAMED_CHECK_IN_EXACT_SUITE');continue;
  }
  selected.set(item.name,item);
 }
 const jobs=[];let successful=0,failed=0,missing=0;
 for(const name of REQUIRED_JOBS){
  const check=selected.get(name);
  if(!check){missing++;jobs.push({name,state:'missing'});continue;}
  const details='https://github.com/'+REPO+
   '/actions/runs/'+run.id+'/job/'+check.id;
  const correct=safeId(check.id)&&check.name===name&&
   check.head_sha===run.head_sha&&
   check.check_suite.id===run.check_suite_id&&
   check.app?.id===APP_ID&&check.app?.slug==='github-actions'&&
   check.details_url===details&&check.status==='completed'&&
   check.conclusion==='success';
  if(correct){successful++;jobs.push({name,state:'success',
   checkId:check.id,appId:APP_ID});}
  else{
   failed++;
   errors.add('CQ_REQUIRED_CHECK_NOT_GENUINE_EXACT_RUN_GITHUB_ACTIONS_SUCCESS');
   jobs.push({name,state:'not_accepted'});
  }
 }
 if(missing)errors.add('CQ_EXACT_SUITE_REQUIRED_CHECK_MISSING');
 const technical=errors.size===0&&successful===REQUIRED_JOBS.length&&
    selected.size===REQUIRED_JOBS.length&&stable&&runValid&&
    records!==null&&unknown===0&&duplicates===0;
 // Hash is local audit checksum, NOT signature / provider authority.
 const sourceSummary={
  prHead:prValid?prBefore.head.sha:null,
  prBase:prValid?prBefore.base.sha:null,
  workflowRunId:runValid?run.id:null,
  checkSuiteId:runValid?run.check_suite_id:null,
  appId:APP_ID,
  status:run?.status??null,
  jobs:jobs.map(x=>({name:x.name,state:x.state,checkId:x.checkId??null}))
 };
 return Object.freeze({
  phase:'1CQ',schemaVersion:1,
  kind:'POSTRUN_ACTUAL_GITHUB_APP_BOUND_EIGHT_CHECK_READONLY_RECEIPT',
  repository:REPO,workflowPath:WORKFLOW_PATH,
  ...sourceSummary,
  externalGithubReadSourcesComplete:
   Object.values(sourceStatuses).length===4&&
   ['prBefore','prAfter','run','checks'].every(x=>sourceStatuses[x]==='read'),
  completedExactEightAppBoundChecksTechnicallyVerified:technical,
  requiredCheckCount:REQUIRED_JOBS.length,
  currentSuiteSuccessfulChecks:successful,
  currentSuiteMissingChecks:missing,
  currentSuiteRejectedChecks:failed,
  unreviewedExtraCurrentSuiteChecks:unknown,
  duplicateCurrentSuiteChecks:duplicates,
  ignoredOtherSuiteCheckCount:other,
  currentPrStillDraftOpenUnmerged:prValid,
  prHeadStableAcrossPostrunReads:stable,
  anomalyCodes:[...errors].sort(sort),
  localUnsignedEvidenceSha256:sha256(JSON.stringify(sourceSummary)),
  independentlySignedCiOidcOrSlsaProvenanceVerified:false,
  actualBaseMainCodeownersAndRulesetInstalledVerified:false,
  independentSecurityBusinessCurrentHeadRoleApprovalsVerified:false,
  externalProviderLegalWormDrOrStagingApprovalVerified:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD'
 });
}
export async function verifyFinishedRun({
 runId,token,fetchImpl=fetch,proposal
}={}){
 const statuses={prBefore:'unavailable',run:'unavailable',
  checks:'unavailable',prAfter:'unavailable'};
 const before=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 statuses.prBefore=before.status;
 const run=await readOfficialCheckSource(runRoute(runId),token,fetchImpl);
 statuses.run=run.status;
 let checks={status:'not_attempted',data:null};
 if(run.status==='read'&&SHA.test(run.data?.head_sha??'')){
  checks=await readOfficialCheckSource(
   checksRoute(run.data.head_sha),token,fetchImpl);
 }
 statuses.checks=checks.status;
 const after=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 statuses.prAfter=after.status;
 return assessFinishedGithubRun({
  run:run.data,checks:checks.data,
  prBefore:before.data,prAfter:after.data,proposal,
  sourceStatuses:statuses
 });
}
function localProposedRuleset(){
 const path='docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json';
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>65536)
  throw Error('CQ_UNSAFE_OR_MISSING_REVIEWED_LOCAL_RULESET_PROPOSAL');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const [cmd,id,...extra]=process.argv.slice(2);
 if(cmd!=='--verify-completed-run'||extra.length||!id||
    !/^[1-9]\d{0,15}$/.test(id)||!Number.isSafeInteger(Number(id)))
  throw Error('CQ_EXPECTS_ONLY_EXPLICIT_READONLY_--verify-completed-run_NUMERIC_ID');
 // The run is complete by design; never pretend to certify our own
 // still-running GitHub Actions workflow from within that workflow.
 if(process.env.GITHUB_ACTIONS==='true')
  throw Error('CQ_POSTRUN_OPERATOR_MODE_FORBIDDEN_INSIDE_GITHUB_ACTIONS');
 const verdict=await verifyFinishedRun({
  runId:Number(id),token:process.env.GITHUB_READ_TOKEN,
  proposal:localProposedRuleset()
 });
 console.log(JSON.stringify(verdict,null,2));
 if(!verdict.completedExactEightAppBoundChecksTechnicallyVerified)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(e=>{
  console.error('CQ completed-run source verification held:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 });
}
