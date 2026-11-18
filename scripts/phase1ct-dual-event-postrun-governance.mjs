import {createHash} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {assessCompletedJobsCrossApi}
 from './phase1cr-actions-jobs-reconciliation.mjs';
import {PUSH_REF_ROUTE,BRANCH}
 from './phase1cs-push-head-governance.mjs';
import {runRoute,jobsRoute,checksRoute,readOfficialCheckSource}
 from './phase1cp-github-actions-check-app-source.mjs';

// Phase 1CT: operator-only, completed-run, two-event cross-API reconciliation.
// Push requires 7 successful jobs + a genuinely SKIPPED PR-only merge-lineage.
// PR requires 8 successes. Separate suite IDs AND job IDs; never cross-lend.
// This unsigned receipt is not independent reviewer/security/provider approval.
const SHA=/^[a-f0-9]{40}$/;
const NAMES=new Set(REQUIRED_JOBS);
const APP=GITHUB_ACTIONS_INTEGRATION_ID;
const ROOT='https://api.github.com/repos/'+REPO;
const BROWSER='https://github.com/'+REPO+'/actions/runs/';
const KEYS=['prBefore','branch','pushRun','prRun','checks','pushJobs','prJobs','prAfter'];
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const num=x=>Number.isSafeInteger(x)&&x>0;
const sha256=x=>createHash('sha256').update(x).digest('hex');
const safeId=x=>typeof x==='string'&&/^[1-9]\d{0,15}$/.test(x)&&
 Number.isSafeInteger(Number(x));
const prValid=p=>object(p)&&p.number===1&&p.state==='open'&&p.draft===true&&
 p.merged===false&&p.user?.login==='j9619655391-max'&&
 p.head?.ref===BRANCH&&p.base?.ref==='main'&&
 p.head?.repo?.full_name===REPO&&p.base?.repo?.full_name===REPO&&
 SHA.test(p.head?.sha??'')&&SHA.test(p.base?.sha??'')&&
 SHA.test(p.merge_commit_sha??'')&&
 typeof p.updated_at==='string'&&Number.isFinite(Date.parse(p.updated_at));
export function assessDualEventReceipt({
 observations={},proposal=null,statuses={}
}={}){
 const anomalies=new Set();
 for(const key of KEYS)
  if(statuses[key]!=='read')anomalies.add('CT_'+key.toUpperCase()+'_SOURCE_NOT_READ');
 if(Object.keys(statuses).length!==KEYS.length)
  anomalies.add('CT_SOURCE_SET_UNREVIEWED');
 const before=observations.prBefore,after=observations.prAfter;
 const prStable=prValid(before)&&prValid(after)&&
  before.head.sha===after.head.sha&&before.base.sha===after.base.sha&&
  before.merge_commit_sha===after.merge_commit_sha&&
  before.updated_at===after.updated_at;
 if(!prStable)anomalies.add('CT_DRAFT_PR_IDENTITY_OR_RACE');
 const source=prStable?before.head.sha:null;
 const ref=observations.branch;
 const officialRef=object(ref)&&ref.ref==='refs/heads/'+BRANCH&&
  ref.object?.type==='commit'&&ref.object.sha===source&&
  ref.object.url===ROOT+'/git/commits/'+source;
 if(!officialRef)anomalies.add('CT_CURRENT_BRANCH_REF_NOT_BOUND_TO_PR');
 const push=observations.pushRun,pr=observations.prRun;
 const prReceipt=assessCompletedJobsCrossApi({
  prBefore:before,prAfter:after,
  run:pr,checks:observations.checks,jobs:observations.prJobs,
  proposal,
  sourceStatuses:{
   prBefore:statuses.prBefore,run:statuses.prRun,checks:statuses.checks,
   jobs:statuses.prJobs,prAfter:statuses.prAfter
  }
 });
 if(!prReceipt.completedCrossApiJobsAndChecksTechnicallyVerified)
  anomalies.add('CT_PR_EIGHT_CHECK_JOBS_CROSS_API_REJECTED');
 const pushRun=object(push)&&num(push.id)&&push.id!==pr?.id&&
  push.event==='push'&&push.head_sha===source&&
  push.head_branch===BRANCH&&push.workflow_id===408632517&&
  push.name==='Phase 0 baseline'&&push.path==='.github/workflows/ci.yml'&&
  push.status==='completed'&&push.conclusion==='success'&&
  num(push.run_attempt)&&num(push.check_suite_id)&&
  push.repository?.full_name===REPO&&push.head_repository?.full_name===REPO&&
  Array.isArray(push.pull_requests)&&push.pull_requests.length===1&&
  push.pull_requests[0]?.number===1&&
  push.pull_requests[0]?.head?.sha===source&&
  push.pull_requests[0]?.base?.sha===before?.base?.sha&&
  push.pull_requests[0]?.head?.ref===BRANCH&&
  push.pull_requests[0]?.base?.ref==='main';
 if(!pushRun)anomalies.add('CT_COMPLETED_PUSH_RUN_SOURCE_UNVERIFIED');
 const distinctSuites=pushRun&&num(pr?.check_suite_id)&&
  push.check_suite_id!==pr.check_suite_id;
 if(!distinctSuites)anomalies.add('CT_MIXED_OR_REUSED_PR_PUSH_SUITE');
 const full=object(observations.checks)&&
  Array.isArray(observations.checks.check_runs)&&
  Number.isSafeInteger(observations.checks.total_count)&&
  observations.checks.total_count===observations.checks.check_runs.length&&
  observations.checks.total_count<100?observations.checks.check_runs:null;
 if(!full)anomalies.add('CT_CHECKS_PAGE_UNBOUNDED_OR_MALFORMED');
 const checks=(full??[]).filter(x=>x?.check_suite?.id===push?.check_suite_id);
 if(checks.length!==REQUIRED_JOBS.length)
  anomalies.add('CT_PUSH_CHECK_SUITE_NOT_EXACT_EIGHT');
 const jobsObj=observations.pushJobs;
 const jobs=object(jobsObj)&&Array.isArray(jobsObj.jobs)&&
  jobsObj.total_count===REQUIRED_JOBS.length&&
  jobsObj.jobs.length===REQUIRED_JOBS.length?jobsObj.jobs:null;
 if(!jobs)anomalies.add('CT_PUSH_JOBS_NOT_EXACT_EIGHT');
 const byName=new Map(),jobByName=new Map();
 for(const c of checks){
  if(!object(c)||!NAMES.has(c.name)||byName.has(c.name))
   anomalies.add('CT_UNKNOWN_OR_DUPLICATE_PUSH_CHECK');
  else byName.set(c.name,c);
 }
 for(const j of jobs??[]){
  if(!object(j)||!NAMES.has(j.name)||jobByName.has(j.name))
   anomalies.add('CT_UNKNOWN_OR_DUPLICATE_PUSH_JOB');
  else jobByName.set(j.name,j);
 }
 const prIds=new Set(
  Array.isArray(observations.prJobs?.jobs)?
   observations.prJobs.jobs.map(x=>x.id):[]
 );
 let passed=0,expectedSkipped=0,matched=0;
 const details=[];
 for(const name of REQUIRED_JOBS){
  const c=byName.get(name),j=jobByName.get(name);
  const expectedConclusion=name==='source-merge-lineage-hold'?'skipped':'success';
  const correct=object(c)&&object(j)&&num(c.id)&&c.id===j.id&&
   !prIds.has(c.id)&&c.head_sha===source&&
   c.check_suite?.id===push?.check_suite_id&&
   c.app?.id===APP&&c.app?.slug==='github-actions'&&
   c.details_url===BROWSER+push?.id+'/job/'+c.id&&
   c.status==='completed'&&c.conclusion===expectedConclusion&&
   j.status==='completed'&&j.conclusion===expectedConclusion&&
   j.run_id===push?.id&&j.run_attempt===push?.run_attempt&&
   j.head_sha===source&&j.workflow_name==='Phase 0 baseline'&&
   j.url===ROOT+'/actions/jobs/'+c.id&&
   j.check_run_url===ROOT+'/check-runs/'+c.id&&
   j.html_url===BROWSER+push?.id+'/job/'+c.id;
  details.push({name,expectedConclusion,checkAndJobMatch:!!correct});
  if(correct){
   matched++;
   if(expectedConclusion==='success')passed++;
   else expectedSkipped++;
  }else anomalies.add('CT_PUSH_JOB_CHECK_ID_SHA_APP_ATTEMPT_OR_STATUS_MISMATCH');
 }
 const technical=anomalies.size===0&&
  prReceipt.completedCrossApiJobsAndChecksTechnicallyVerified&&
  officialRef&&pushRun&&distinctSuites&&
  matched===REQUIRED_JOBS.length&&passed===7&&expectedSkipped===1;
 const data={
  sourceHeadSha:source,baseSha:prStable?before.base.sha:null,
  pushRunId:pushRun?push.id:null,prRunId:pr?.id??null,
  pushSuiteId:pushRun?push.check_suite_id:null,
  prSuiteId:pr?.check_suite_id??null,
  pushMatchedJobs:matched,pushSuccesses:passed,pushExpectedSkipped:expectedSkipped,
  prMatchedJobs:prReceipt.matchedJobs
 };
 return Object.freeze({
  phase:'1CT',schemaVersion:1,
  kind:'UNSIGNED_COMPLETED_DUAL_EVENT_GITHUB_CHECK_JOB_RECEIPT_HARD_HOLD',
  repository:REPO,...data,
  officialPrUnchangedAcrossAllReads:prStable,
  sourceBranchAndPrHeadMatch:officialRef,
  completedPrEightSuccessCrossApiVerified:
   prReceipt.completedCrossApiJobsAndChecksTechnicallyVerified,
  completedPushSevenSuccessAndOnePrOnlySkipCrossApiVerified:
   pushRun&&distinctSuites&&matched===8&&passed===7&&expectedSkipped===1&&
   ![...anomalies].some(x=>x.startsWith('CT_PUSH')),
  completedTwoEventTechnicalReceiptVerified:technical,
  selectedPushChecks:details,
  sourceStatuses:KEYS.reduce((out,key)=>(out[key]=statuses[key]??'missing',out),{}),
  anomalyCodes:Object.freeze([...anomalies].sort()),
  localUnsignedTechnicalSha256:sha256(JSON.stringify(data)),
  independentSecurityBusinessMandatesVerified:false,
  installedMainCodeownersRulesetsWithoutBypassVerified:false,
  independentSignedOidcSlsaWorkloadAttestationVerified:false,
  externalEmudhraMcaWormDrStagingAcceptanceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export async function verifyDualEventReceipt({
 pushId,prId,token,proposal,fetchImpl=fetch
}={}){
 const statuses={};
 const pull=async(key,route)=>{
  const receipt=await readOfficialCheckSource(route,token,fetchImpl);
  statuses[key]=receipt.status;return receipt.data;
 };
 const before=await pull('prBefore','/pulls/1');
 const branch=await pull('branch',PUSH_REF_ROUTE);
 const push=await pull('pushRun',runRoute(pushId));
 const pr=await pull('prRun',runRoute(prId));
 let checks=null,pushJobs=null,prJobs=null;
 if(push?.id===Number(pushId)&&pr?.id===Number(prId)&&
    SHA.test(push.head_sha??'')&&push.head_sha===pr.head_sha){
  checks=await pull('checks',checksRoute(push.head_sha));
  pushJobs=await pull('pushJobs',jobsRoute(pushId));
  prJobs=await pull('prJobs',jobsRoute(prId));
 }else {
  for(const x of ['checks','pushJobs','prJobs'])statuses[x]='not_attempted';
 }
 const after=await pull('prAfter','/pulls/1');
 return assessDualEventReceipt({
  observations:{prBefore:before,branch,pushRun:push,prRun:pr,
   checks,pushJobs,prJobs,prAfter:after},
  proposal,statuses
 });
}
function localProposal(){
 const path='docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json';
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>65536)
  throw Error('CT_INVALID_LOCAL_UNINSTALLED_RULESET_PROPOSAL');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const [flag,pushId,prId,...extra]=process.argv.slice(2);
 if(flag!=='--verify-dual-runs'||extra.length||
    !safeId(pushId)||!safeId(prId)||pushId===prId)
  throw Error('CT_EXPECTS_--verify-dual-runs_PUSH_ID_PR_ID');
 if(process.env.GITHUB_ACTIONS==='true')
  throw Error('CT_COMPLETED_RUN_OPERATOR_CANNOT_RUN_IN_ACTIONS');
 const receipt=await verifyDualEventReceipt({
  pushId:Number(pushId),prId:Number(prId),
  token:process.env.GITHUB_READ_TOKEN,proposal:localProposal()
 });
 console.log(JSON.stringify(receipt,null,2));
 if(!receipt.completedTwoEventTechnicalReceiptVerified)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CT operator dual-run readonly receipt blocked:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
