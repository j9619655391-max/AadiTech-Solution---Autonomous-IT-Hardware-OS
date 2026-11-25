import {createHash} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,REQUIRED_JOBS} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {assessFinishedGithubRun} from './phase1cq-postrun-github-check-receipt.mjs';
import {runRoute,checksRoute,jobsRoute,readOfficialCheckSource} from './phase1cp-github-actions-check-app-source.mjs';

// Phase 1CR: operator-only post-completion, GET-only cross-API reconciliation.
// A Check Runs success is insufficient unless the Actions Jobs API corroborates
// the SAME job IDs, current run attempt, source SHA and conclusion.
// GitHub API observations are UNSIGNED and NEVER authorize production.
const SHA=/^[a-f0-9]{40}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safeId=x=>Number.isSafeInteger(x)&&x>0;
const sha256=x=>createHash('sha256').update(x).digest('hex');
const ORIGIN='https://api.github.com/repos/'+REPO;
const NAMES=new Set(REQUIRED_JOBS);
const REQUIRED=REQUIRED_JOBS.length;
const SOURCE_KEYS=['prBefore','run','checks','jobs','prAfter'];
const sort=(a,b)=>a.localeCompare(b);

export function assessCompletedJobsCrossApi({
 prBefore=null,prAfter=null,run=null,checks=null,jobs=null,
 proposal=null,sourceStatuses={}
}={}){
 const errors=new Set();
 const cq=assessFinishedGithubRun({
  prBefore,prAfter,run,checks,proposal,
  sourceStatuses:{
   prBefore:sourceStatuses.prBefore,prAfter:sourceStatuses.prAfter,
   run:sourceStatuses.run,checks:sourceStatuses.checks
  }
 });
 if(!cq.completedExactEightAppBoundChecksTechnicallyVerified)
  errors.add('CR_CQ_COMPLETED_EXACT_SUITE_PR_SOURCE_NOT_VERIFIED');
 if(SOURCE_KEYS.some(k=>sourceStatuses[k]!=='read')||
    Object.keys(sourceStatuses).length!==SOURCE_KEYS.length)
  errors.add('CR_GITHUB_CROSS_API_SOURCE_UNAVAILABLE_OR_DENIED');
 const list=object(jobs)&&Array.isArray(jobs.jobs)&&
  Number.isSafeInteger(jobs.total_count)&&
  jobs.total_count===jobs.jobs.length&&jobs.total_count===REQUIRED?
  jobs.jobs:null;
 if(!list)errors.add('CR_ACTIONS_JOBS_PAGE_UNBOUNDED_MISSING_OR_EXTRA');
 const expected=new Map(cq.jobs?.map(x=>[x.name,x])??[]);
 const found=new Set();let matched=0;
 for(const job of list??[]){
  if(!object(job)||!NAMES.has(job.name)||found.has(job.name)){
   errors.add('CR_DUPLICATE_OR_UNREVIEWED_ACTIONS_JOB');continue;
  }
  found.add(job.name);
  const check=expected.get(job.name);
  const id=safeId(job.id)?job.id:null;
  const valid=check?.state==='success'&&id===check.checkId&&
   safeId(run?.id)&&job.run_id===run.id&&
   safeId(run?.run_attempt)&&job.run_attempt===run.run_attempt&&
   SHA.test(run?.head_sha??'')&&job.head_sha===run.head_sha&&
   job.status==='completed'&&job.conclusion==='success'&&
   job.workflow_name==='Phase 0 baseline'&&
   job.url===ORIGIN+'/actions/jobs/'+id&&
   job.check_run_url===ORIGIN+'/check-runs/'+id&&
   job.html_url==='https://github.com/'+REPO+
    '/actions/runs/'+run.id+'/job/'+id;
  if(valid)matched++;
  else errors.add('CR_JOB_ID_RUN_ATTEMPT_SHA_URL_OR_CONCLUSION_MISMATCH');
 }
 if(found.size!==REQUIRED||matched!==REQUIRED)
  errors.add('CR_EIGHT_EXACT_ACTIONS_JOBS_NOT_RECONCILED');
 const technicallyVerified=errors.size===0&&matched===REQUIRED;
 const snapshot={
  prHead:cq.prHead,prBase:cq.prBase,
  workflowRunId:cq.workflowRunId,checkSuiteId:cq.checkSuiteId,
  runAttempt:safeId(run?.run_attempt)?run.run_attempt:null,
  expectedCheckIds:cq.jobs?.map(x=>({name:x.name,checkId:x.checkId??null}))??[],
  crossApiMatchedJobCount:matched
 };
 return Object.freeze({
  phase:'1CR',schemaVersion:1,
  kind:'POSTRUN_GITHUB_CHECKS_AND_ACTIONS_JOBS_EXACT_ID_READONLY_HOLD',
  repository:REPO,...snapshot,
  completedCrossApiJobsAndChecksTechnicallyVerified:technicallyVerified,
  precedingCQCompletedCheckSourceVerified:
   cq.completedExactEightAppBoundChecksTechnicallyVerified,
  requiredJobs:REQUIRED,matchedJobs:matched,
  prStableAcrossWholeFiveReadObservation:cq.prHeadStableAcrossPostrunReads,
  sourceStatusesComplete:SOURCE_KEYS.every(k=>sourceStatuses[k]==='read'),
  anomalyCodes:[...errors].sort(sort),
  localUnsignedObservationSha256:sha256(JSON.stringify(snapshot)),
  thirdPartySignedSlsaOrOidcAttestationVerified:false,
  independentlyAppointedSecurityAndBusinessApprovalsVerified:false,
  installedProtectedMainRulesetsVerified:false,
  realEmudhraMcaWormDrStagingAcceptanceVerified:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export async function verifyCompletedJobsCrossApi({
 runId,token,fetchImpl=fetch,proposal=null
}={}){
 const idRoute=runRoute(runId);
 const sources={prBefore:'unavailable',run:'unavailable',
  checks:'not_attempted',jobs:'not_attempted',prAfter:'unavailable'};
 const before=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 sources.prBefore=before.status;
 const run=await readOfficialCheckSource(idRoute,token,fetchImpl);
 sources.run=run.status;
 let checks={data:null,status:'not_attempted'};
 let jobs={data:null,status:'not_attempted'};
 if(run.status==='read'&&run.data?.id===Number(runId)&&
    SHA.test(run.data?.head_sha??'')){
  checks=await readOfficialCheckSource(
   checksRoute(run.data.head_sha),token,fetchImpl);
  jobs=await readOfficialCheckSource(jobsRoute(runId),token,fetchImpl);
 }
 sources.checks=checks.status;sources.jobs=jobs.status;
 // Final PR read happens AFTER both independent GitHub API observations.
 const after=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 sources.prAfter=after.status;
 return assessCompletedJobsCrossApi({
  prBefore:before.data,prAfter:after.data,run:run.data,
  checks:checks.data,jobs:jobs.data,
  proposal,sourceStatuses:sources
 });
}
function localProposal(){
 const path='docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json';
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>65536)
  throw Error('CR_UNSAFE_OR_MISSING_LOCAL_RULESET_PROPOSAL');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const [flag,id,...extra]=process.argv.slice(2);
 if(flag!=='--verify-run-jobs'||extra.length||!id||
    !/^[1-9]\d{0,15}$/.test(id)||!Number.isSafeInteger(Number(id)))
  throw Error('CR_EXPECTS_ONLY_--verify-run-jobs_NUMERIC_RUN_ID');
 if(process.env.GITHUB_ACTIONS==='true')
  throw Error('CR_OPERATOR_POSTRUN_CANNOT_RUN_INSIDE_GITHUB_ACTIONS');
 const receipt=await verifyCompletedJobsCrossApi({
  runId:Number(id),token:process.env.GITHUB_READ_TOKEN,
  proposal:localProposal()
 });
 console.log(JSON.stringify(receipt,null,2));
 if(!receipt.completedCrossApiJobsAndChecksTechnicallyVerified)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CR completed-run cross-API verification held:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
