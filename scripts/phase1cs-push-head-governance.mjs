import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readOfficialCheckSource,runRoute} from './phase1cp-github-actions-check-app-source.mjs';

// Phase 1CS: A push must be checked as a push, never as a PR test merge.
// Technical read-only observation. Not a signed attestation or release GO.
export const REPOSITORY='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const BRANCH='chore/phase0-foundation-20261106';
export const PUSH_REF_ROUTE='/git/ref/heads/chore/phase0-foundation-20261106';
const SHA=/^[a-f0-9]{40}$/;
const NUM=/^[1-9]\d{0,15}$/;
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const check=(errors,ok,code)=>{if(!ok)errors.add(code);};
const prShape=pr=>obj(pr)&&pr.number===1&&pr.state==='open'&&
 pr.draft===true&&pr.merged===false&&pr.user?.login==='j9619655391-max'&&
 pr.head?.repo?.full_name===REPOSITORY&&pr.base?.repo?.full_name===REPOSITORY&&
 pr.head?.ref===BRANCH&&pr.base?.ref==='main'&&
 SHA.test(pr.head?.sha??'')&&SHA.test(pr.base?.sha??'')&&
 SHA.test(pr.merge_commit_sha??'')&&
 typeof pr.updated_at==='string'&&!Number.isNaN(Date.parse(pr.updated_at));
export async function collectPushObservation({token,runId,fetchImpl=fetch}={}){
 const first=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 const branch=await readOfficialCheckSource(PUSH_REF_ROUTE,token,fetchImpl);
 let run={status:'not_attempted',data:null};
 if(NUM.test(String(runId??''))&&Number.isSafeInteger(Number(runId)))
  run=await readOfficialCheckSource(runRoute(runId),token,fetchImpl);
 const last=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 return {first,branch,run,last};
}
export function assessPushObservation({observations={},environment={}}={}){
 const errors=new Set(),statuses={};
 for(const field of ['first','branch','run','last']){
  const entry=observations[field];
  statuses[field]=typeof entry?.status==='string'?entry.status:'invalid';
  if(statuses[field]!=='read')errors.add('CS_OFFICIAL_'+field.toUpperCase()+'_NOT_READ');
 }
 const env=environment,source=env?.GITHUB_SHA,runId=env?.GITHUB_RUN_ID;
 const context=env?.GITHUB_ACTIONS==='true'&&env?.GITHUB_EVENT_NAME==='push'&&
  env?.GITHUB_JOB==='live-github-governance-hold'&&
  env?.GITHUB_REPOSITORY===REPOSITORY&&
  env?.GITHUB_REF==='refs/heads/'+BRANCH&&
  !env?.GITHUB_HEAD_REF&&!env?.GITHUB_BASE_REF&&
  SHA.test(source??'')&&NUM.test(String(runId??''))&&
  Number.isSafeInteger(Number(runId));
 check(errors,context,'CS_NOT_EXACT_PUSH_WORKLOAD');
 const first=observations.first?.status==='read'?observations.first.data:null;
 const last=observations.last?.status==='read'?observations.last.data:null;
 check(errors,prShape(first)&&prShape(last),'CS_DRAFT_PR_IDENTITY_NOT_VERIFIED');
 const stable=prShape(first)&&prShape(last)&&
  first.head.sha===last.head.sha&&first.base.sha===last.base.sha&&
  first.updated_at===last.updated_at&&
  first.merge_commit_sha===last.merge_commit_sha;
 check(errors,stable,'CS_PR_MUTATED_DURING_CUSTODY_READS');
 check(errors,stable&&first.head.sha===source,'CS_PUSH_SHA_NOT_CURRENT_PR_HEAD');
 const branch=observations.branch?.status==='read'?observations.branch.data:null;
 const correctRef=obj(branch)&&branch.ref==='refs/heads/'+BRANCH&&
  branch.object?.type==='commit'&&branch.object.sha===source&&
  branch.object.url==='https://api.github.com/repos/'+REPOSITORY+
   '/git/commits/'+source;
 check(errors,correctRef,'CS_OFFICIAL_BRANCH_REF_OR_SHA_DRIFT');
 const run=observations.run?.status==='read'?observations.run.data:null;
 const validRun=obj(run)&&context&&run.id===Number(runId)&&
  run.event==='push'&&run.head_sha===source&&run.head_branch===BRANCH&&
  run.workflow_id===408632517&&run.name==='Phase 0 baseline'&&
  run.path==='.github/workflows/ci.yml'&&
  run.repository?.full_name===REPOSITORY&&
  run.head_repository?.full_name===REPOSITORY&&
  Number.isSafeInteger(run.run_attempt)&&run.run_attempt>=1&&
  Number.isSafeInteger(run.check_suite_id)&&run.check_suite_id>0&&
  ['in_progress','queued','requested','waiting','pending'].includes(run.status)&&
  (run.conclusion===null||run.conclusion===undefined)&&
  Array.isArray(run.pull_requests)&&run.pull_requests.some(p=>
   p?.number===1&&p.head?.sha===source&&p.base?.sha===first?.base?.sha);
 check(errors,validRun,'CS_OFFICIAL_CURRENT_PUSH_RUN_SOURCE_UNVERIFIED');
 return Object.freeze({
  phase:'1CS',schemaVersion:1,
  kind:'UNSIGNED_GITHUB_PUSH_REF_PR_RUN_RECONCILIATION_HOLD',
  repository:REPOSITORY,branch:BRANCH,
  observedSourceSha:context?source:null,observedRunId:context?Number(runId):null,
  endpointStatuses:statuses,
  exactPushWorkloadRefAndEventVerified:context,
  observedDraftPrStableAcrossReads:stable,
  officialPushedRefAndCurrentPrHeadMatch:
   correctRef&&stable&&first.head.sha===source,
  actualPushSourceStructurallyValid:errors.size===0,
  anomalyCodes:Object.freeze([...errors].sort()),
  independentSignedCiProvenanceVerified:false,
  independentReviewerMandatesVerified:false,
  installedBaseMainBranchPolicyVerified:false,
  externalProviderLegalWormDrStagingVerified:false,
  externallySigned:false,independentWorm:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CS_ONLY_GITHUB_PUSH_READONLY_CI_HOLD');
 const observations=await collectPushObservation({
  token:process.env.GITHUB_READ_TOKEN,runId:process.env.GITHUB_RUN_ID
 });
 const verdict=assessPushObservation({observations,environment:process.env});
 const output={verdict,externallySigned:false,independentWorm:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 writeFileSync('phase1cs-push-governance-hold.json',
  JSON.stringify(output,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(output,null,2));
 if(!verdict.actualPushSourceStructurallyValid||
    verdict.productionReleaseAuthorized!==false||
    verdict.productionReleaseBlocked!==true||
    verdict.releaseDecision!=='HOLD')process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CS push-only GitHub source custody held:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
