import {Buffer} from 'node:buffer';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID,
 assessProposedMainRuleset
} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {readOfficialGithubEndpoint} from './phase1by-github-governance-observer.mjs';

// 1CP: The Github Rulesets API permits integration_id for each required
// check. Actual check-runs observed for this repo have github-actions/15368.
// GitHub reports MULTIPLE check suites for the same source commit, even where
// a previous suite failed: never combine passes across different suites/runs.
// No actor, local unsigned report or green app check is independent OIDC
// provenance, authorized external review or production GO.
const ORIGIN='https://api.github.com/repos/'+REPO;
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const POSITIVE=/^[1-9]\d{0,15}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const MAX_JSON=524288;
const EXPECTED_DETAILS='https://github.com/'+REPO+'/actions/runs/';
export const ALLOWED_CHECKS=Object.freeze([...REQUIRED_JOBS]);
export const APP_ID=GITHUB_ACTIONS_INTEGRATION_ID;
const checkSet=new Set(REQUIRED_JOBS);

export function runRoute(id){
 if(!POSITIVE.test(String(id))||!Number.isSafeInteger(Number(id)))
  throw Error('CP_UNREVIEWED_GITHUB_RUN_ID');
 return '/actions/runs/'+String(id);
}
export function jobsRoute(id){
 return runRoute(id)+'/jobs?per_page=100&filter=latest';
}
export function checksRoute(sha){
 if(!SHA.test(sha??''))throw Error('CP_UNREVIEWED_GITHUB_SOURCE_SHA');
 return '/commits/'+sha+'/check-runs?per_page=100';
}
export async function readOfficialCheckSource(route,token,fetchImpl=fetch){
 if(route!=='/pulls/1'&&route!=='/git/ref/heads/chore/phase0-foundation-20261106'&&
    !/^\/actions\/runs\/[1-9]\d{0,15}$/.test(route)&&
    !/^\/actions\/runs\/[1-9]\d{0,15}\/jobs\?per_page=100&filter=latest$/.test(route)&&
    !/^\/commits\/[a-f0-9]{40}\/check-runs\?per_page=100$/.test(route))
  throw Error('CP_UNREVIEWED_GITHUB_CHECK_SOURCE_ROUTE');
 if(typeof token!=='string'||token.length<1||token.length>4096)
  return {status:'unavailable',data:null};
 const url=ORIGIN+route;
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),6500);
 try{
  const reply=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:controller.signal,
   headers:{
    Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1CP-GithubApp-CheckSource-HOLD'
   }
  });
  if(reply.status!==200)return {
   status:reply.status===401||reply.status===403?'access_denied':
    reply.status===404?'not_found_or_hidden':'unavailable',data:null
  };
  if(reply.redirected||reply.url!==url||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      reply.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null};
  const header=reply.headers?.get?.('content-length');
  if(header!==null&&header!==undefined&&
     (!/^\d+$/.test(header)||Number(header)>MAX_JSON))
   return {status:'invalid',data:null};
  const reader=reply.body?.getReader();
  if(!reader)return {status:'invalid',data:null};
  const data=[];let size=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))return {status:'invalid',data:null};
   size+=value.byteLength;
   if(size>MAX_JSON)return {status:'invalid',data:null};
   data.push(Buffer.from(value));
  }
  const parsed=JSON.parse(Buffer.concat(data).toString('utf8'));
  return {status:'read',data:parsed};
 }catch{return {status:'unavailable',data:null};}
 finally{clearTimeout(timer);}
}
export async function collectOfficialCheckProvenance({
 runId,token,fetchImpl=fetch
}={}){
 const run=await readOfficialCheckSource(runRoute(runId),token,fetchImpl);
 if(run.status!=='read'||!SHA.test(run.data?.head_sha??''))
  return {runStatus:run.status,run:run.data??null,
   checksStatus:'not_attempted',checks:null};
 const checks=await readOfficialCheckSource(
  checksRoute(run.data.head_sha),token,fetchImpl);
 return {runStatus:run.status,run:run.data,
  checksStatus:checks.status,checks:checks.data};
}
export function assessOfficialAppCheckProvenance({
 observations={},byReport=null,proposal=null,environment={}
}={}){
 const errors=new Set(),anomalies=new Set();
 const cm=assessProposedMainRuleset(proposal),by=byReport?.snapshotDerived;
 if(!cm.localProposedRestPayloadStructurallySafe)
  errors.add('CP_REQUIRED_CHECK_APPLICATION_ID_UNPINNED_OR_UNREVIEWED');
 if(byReport?.kind!=='LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD'||
    !HASH.test(byReport?.sourceBundleSha256??'')||
    byReport?.productionReleaseAuthorized!==false||
    byReport?.releaseDecision!=='HOLD'||
    by?.phase!=='1BY'||by?.observedPrDraftAndUnmerged!==true||
    by?.eventSourceHeadAndBaseMatch!==true||
    by?.ciMergeMatchesPrApi!==true||
    by?.releaseDecision!=='HOLD'||
    !SHA.test(by?.observedDevHeadSha??'')||
    by?.productionReleaseAuthorized!==false)
  errors.add('CP_PRECEDING_ACTUAL_GITHUB_HEAD_AND_CUSTODY_INVALID');
 const contextGood=object(environment)&&
   environment.GITHUB_ACTIONS==='true'&&
   environment.GITHUB_JOB==='live-github-governance-hold'&&
   environment.GITHUB_REPOSITORY===REPO&&
   environment.GITHUB_REF==='refs/pull/1/merge'&&
   SHA.test(environment.GITHUB_SHA??'')&&
   by?.observedPrMergeSha===environment.GITHUB_SHA&&
   POSITIVE.test(String(environment.GITHUB_RUN_ID??''))&&
   Number.isSafeInteger(Number(environment.GITHUB_RUN_ID));
 if(!contextGood)errors.add('CP_GITHUB_CURRENT_WORKLOAD_RUN_SHA_OR_REF_INVALID');
 const runId=contextGood?Number(environment.GITHUB_RUN_ID):null;
 const run=observations?.runStatus==='read'?observations.run:null;
 const validRun=object(run)&&run.id===runId&&
   run.head_sha===by?.observedDevHeadSha&&
   run.event==='pull_request'&&
   run.head_branch==='chore/phase0-foundation-20261106'&&
   Number.isSafeInteger(run.check_suite_id)&&run.check_suite_id>0&&
   ['in_progress','queued','requested','waiting','pending','completed'].includes(run.status)&&
   Array.isArray(run.pull_requests)&&
   run.pull_requests.some(p=>p?.number===1&&p?.head?.sha===by?.observedDevHeadSha&&
     p?.base?.sha===by?.observedBaseSha);
 if(!validRun)anomalies.add('CP_ACTUAL_GITHUB_ACTIONS_RUN_NOT_VERIFIED');
 const listed=observations?.checksStatus==='read'&&
   object(observations.checks)&&
   Array.isArray(observations.checks.check_runs)&&
   observations.checks.total_count===observations.checks.check_runs.length&&
   observations.checks.total_count<100?
    observations.checks.check_runs:null;
 if(!listed)anomalies.add('CP_CHECK_RUNS_MISSING_OR_PAGINATION_UNBOUNDED');
 const currentSuite=new Map();let otherSuites=0,malformed=0;
 for(const check of listed??[]){
  // Ignore earlier check suites on the same dev HEAD. Phase 1CO actually
  // observed both a SUCCESS suite and a FAIL/SKIPPED suite on one SHA.
  if(!object(check)||!object(check.check_suite)||
     !Number.isSafeInteger(check.check_suite.id)||check.check_suite.id<=0){
   malformed++;continue;
  }
  if(!validRun||check.check_suite.id!==run.check_suite_id){
   otherSuites++;continue;
  }
  if(!checkSet.has(check.name))continue;
  const prefix=EXPECTED_DETAILS+runId+'/job/';
  const validRecord=Number.isSafeInteger(check.id)&&check.id>0&&
   check.head_sha===by?.observedDevHeadSha&&
   check.app?.id===APP_ID&&check.app?.slug==='github-actions'&&
   check.details_url===prefix+check.id&&
   ['queued','in_progress','completed','pending','waiting','requested'].includes(check.status)&&
   (check.status!=='completed'||
    ['success','failure','cancelled','timed_out','neutral','skipped','action_required','stale','startup_failure'].includes(check.conclusion));
  if(!validRecord){errors.add('CP_FORGED_CHECK_APP_SHA_OR_WORKFLOW_JOB_SOURCE');continue;}
  if(currentSuite.has(check.name)){
   errors.add('CP_DUPLICATE_CHECK_CONTEXT_IN_EXACT_CURRENT_SUITE');continue;
  }
  currentSuite.set(check.name,check);
 }
 if(malformed)anomalies.add('CP_MALFORMED_OR_UNRELATED_GITHUB_CHECK_SOURCE');
 let passed=0,missing=0,pending=0,failed=0;
 const observed={};
 for(const name of REQUIRED_JOBS){
  const check=currentSuite.get(name);
  if(!check){missing++;observed[name]='not_observed';}
  else if(check.status!=='completed'){pending++;observed[name]='pending';}
  else if(check.conclusion!=='success'){failed++;observed[name]='non_success';}
  else{passed++;observed[name]='success';}
 }
 if(missing||pending)anomalies.add('CP_CURRENT_SUITE_HAS_UNFINISHED_REQUIRED_CHECKS');
 if(failed)anomalies.add('CP_CURRENT_SUITE_REQUIRED_CHECK_FAILURE');
 if(otherSuites)anomalies.add('CP_OTHER_CHECK_SUITE_SAME_COMMIT_EXCLUDED');
 return Object.freeze({
  phase:'1CP',schemaVersion:1,
  kind:'OFFICIAL_GITHUB_ACTIONS_APP_ID_AND_EXACT_SUITE_READONLY_HOLD',
  repository:REPO,
  sourceHeadSha:by?.observedDevHeadSha??null,
  observedWorkflowRunId:runId,
  observedCheckSuiteId:validRun?run.check_suite_id:null,
  pinnedExpectedGitHubAppId:APP_ID,
  requiredCheckCount:REQUIRED_JOBS.length,
  currentSuiteObservedStatuses:observed,
  currentSuitePassedCount:passed,currentSuiteMissingCount:missing,
  currentSuitePendingCount:pending,currentSuiteFailedCount:failed,
  ignoredOtherSuiteCheckCount:otherSuites,
  currentExactRunAllEightAppBoundChecksPassed:
   validRun&&listed!==null&&passed===REQUIRED_JOBS.length&&
   errors.size===0&&run.status==='completed'&&run.conclusion==='success',
  officialLiveRunAndCheckSourceStructurallyConsistent:errors.size===0,
  anomalyCodes:[...errors,...anomalies].sort(),
  // A green GitHub App check on a commit is not an independently signed
  // SLSA/OIDC attestation, privileged code review or release GO.
  independentCryptographicGithubAppOriginVerified:false,
  sourceBoundSignedOidcCiWorkloadAttestationVerified:false,
  effectiveMainRequiredChecksInstalled:false,
  independentSecurityBusinessReviewerMandatesVerified:false,
  externalProviderLegalWormDrAndStagingApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function readLocal(path,max){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>max)
  throw Error('CP_UNSAFE_OR_MISSING_LOCAL_PRECEDING_REPORT');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--ci-hold')
  throw Error('CP_ONLY_ZERO_INPUT_READONLY_CI_HOLD');
 const by=readLocal('phase1by-github-readonly-governance-hold.json',262144),
  proposal=readLocal('docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json',65536);
 const observations=await collectOfficialCheckProvenance({
  runId:process.env.GITHUB_RUN_ID,token:process.env.GITHUB_READ_TOKEN
 });
 const verdict=assessOfficialAppCheckProvenance({
  observations,byReport:by,proposal,environment:process.env
 });
 const report={verdict,sourceReadStatuses:{
  run:observations.runStatus,checkRuns:observations.checksStatus
 },externallySigned:false,independentWorm:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 writeFileSync('phase1cp-github-actions-app-check-source-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 // During the running CI job there are naturally pending check runs.
 // The evidence observation job must fail only on spoofed source/custody,
 // never promote partial or pending status into an all-green approval.
 if(!verdict.officialLiveRunAndCheckSourceStructurallyConsistent||
    verdict.productionReleaseAuthorized!==false||verdict.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CP real GitHub App check source not accepted:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
