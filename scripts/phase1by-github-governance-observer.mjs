import {readFileSync,writeFileSync} from 'node:fs';
import {Buffer} from 'node:buffer';
import {TextDecoder} from 'node:util';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {BUILD_INPUT_PATHS,makeBuildInputInventory}
 from './phase1bv-build-input-provenance.mjs';

// Phase 1BY: source-bound read-only GitHub REST observations. This uses only
// GitHub's fixed official API endpoint; no redirect, mutation or admin token.
// Reading current PR/rules is NOT independent key enrollment or release GO.
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const AUTHOR='j9619655391-max';
const DEV='chore/phase0-foundation-20261106';
const ORIGIN='https://api.github.com';
const ROOT='/repos/'+REPO;
const SHA=/^[0-9a-f]{40}$/;
// Phase 1DJ: no unbounded response.text() ingestion or ever-growing PR body.
export const BY_MAX_API_JSON_BYTES=196608;
export const BY_MAX_PR_DESCRIPTION_BYTES=8192;
const REQUIRED_CHECKS=Object.freeze([
 'baseline','mysql-integration','production-runtime-scope',
 'build-input-provenance','review-vendor-intake-hold',
 'independent-evidence-hold','live-github-governance-hold',
 'source-merge-lineage-hold'
]);
const ENDPOINTS=Object.freeze({
 pr:ROOT+'/pulls/1',
 reviews:ROOT+'/pulls/1/reviews?per_page=100',
 rules:ROOT+'/rules/branches/main',
 protection:ROOT+'/branches/main/protection'
});
function safeTimestamp(value){
 return typeof value==='string'&&Number.isFinite(Date.parse(value))?
  Date.parse(value):Number.NEGATIVE_INFINITY;
}
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
function apiStatus(status){
 if(status===200)return 'read';
 if(status===401||status===403)return 'access_denied';
 if(status===404)return 'not_found_or_hidden';
 if(status===429||status>=500)return 'temporarily_unavailable';
 return 'unavailable';
}
export async function readOfficialGithubEndpoint(path,token,{
 fetchImpl=fetch,timeoutMs=6500
}={}){
 // Closed source endpoints: no attacker-provided URL, SSRF or API mutation.
 if(!Object.values(ENDPOINTS).includes(path)&&
    !/^\/repos\/j9619655391-max\/AadiTech-Solution---Autonomous-IT-Hardware-OS\/pulls\/1\/reviews\?per_page=100&page=[1-3]$/.test(path))
  throw Error('BY untrusted API path');
 if(typeof token!=='string'||!token.length||token.length>4096)
  return {status:'missing_token',data:null,httpStatus:null};
 const url=ORIGIN+path;
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),timeoutMs);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',
   signal:controller.signal,
   headers:{
    Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1DJ-BoundedOfficialGithub-HOLD'
   }
  });
  const status=apiStatus(response.status);
  if(status!=='read')return {status,data:null,httpStatus:response.status};
  if(response.redirected||response.url!==url||
     !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      response.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null,httpStatus:200};
  const declared=response.headers?.get?.('content-length');
  if(declared!==null&&declared!==undefined){
   if(!/^\d+$/.test(declared)||
      !Number.isSafeInteger(Number(declared)))
    return {status:'invalid',data:null,httpStatus:200};
   if(Number(declared)>BY_MAX_API_JSON_BYTES)
    return {status:'oversize',data:null,httpStatus:200};
  }
  if(!response.body||typeof response.body.getReader!=='function')
   return {status:'invalid',data:null,httpStatus:200};
  const reader=response.body.getReader(),chunks=[];
  let received=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))
    return {status:'invalid',data:null,httpStatus:200};
   if(received+value.byteLength>BY_MAX_API_JSON_BYTES){
    controller.abort();
    return {status:'oversize',data:null,httpStatus:200};
   }
   received+=value.byteLength;
   chunks.push(Buffer.from(value));
  }
  let json;
  try{
   const content=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true})
    .decode(Buffer.concat(chunks,received));
   json=JSON.parse(content);
  }catch{return {status:'invalid',data:null,httpStatus:200};}
  if(!obj(json)&&!Array.isArray(json))
   return {status:'invalid',data:null,httpStatus:200};
  return {status:'read',data:json,httpStatus:200};
 }catch{
  // Untrusted network/credential errors are intentionally not reflected.
  return {status:'unavailable',data:null,httpStatus:null};
 }finally{clearTimeout(timeout);}
}
export async function collectReadonlyGithubSnapshot({
 token,fetchImpl=fetch,environment={}
}={}){
 const endpoints={};
 if(typeof token!=='string'||!token.length){
  for(const key of Object.keys(ENDPOINTS))
   endpoints[key]={status:'missing_token',data:null};
 }else{
  // Fixed 4 reads; never follow untrusted Link headers.
  for(const [key,path] of Object.entries(ENDPOINTS))
   endpoints[key]=await readOfficialGithubEndpoint(path,token,{fetchImpl});
  if(endpoints.reviews.status==='read'&&Array.isArray(endpoints.reviews.data)){
   const all=[...endpoints.reviews.data];
   // Exactly 100 reviews might have a next page. Request only literal
   // bounded page numbers, never a provider-supplied URL.
   for(let page=2;page<=3&&all.length===(page-1)*100;page++){
    const next=await readOfficialGithubEndpoint(
     ENDPOINTS.reviews+'&page='+page,token,{fetchImpl});
    if(next.status!=='read'||!Array.isArray(next.data)){
     endpoints.reviews={status:'incomplete_pagination',data:null};break;
    }
    all.push(...next.data);
   }
   if(endpoints.reviews.status==='read'){
    endpoints.reviews={...endpoints.reviews,
     status:all.length>=300?'incomplete_pagination':'read',data:all};
   }
  }
 }
 return {
  observedAt:new Date().toISOString(),
  repository:environment.GITHUB_REPOSITORY??null,
  githubRef:environment.GITHUB_REF??null,
  githubSha:environment.GITHUB_SHA??null,
  eventHeadSha:environment.GITHUB_EXPECTED_PR_HEAD_SHA??null,
  eventBaseSha:environment.GITHUB_EXPECTED_PR_BASE_SHA??null,
  githubHeadRef:environment.GITHUB_HEAD_REF??null,
  githubBaseRef:environment.GITHUB_BASE_REF??null,
  eventName:environment.GITHUB_EVENT_NAME??null,
  endpoints
 };
}
function appliedRulesSummary(rules){
 if(!Array.isArray(rules))return {
  observedRuleCount:null,sourceRequiresPr:false,
  sourceTwoReviews:false,sourceCodeOwnerReview:false,
  sourceLastPushApproval:false,sourceStatusCheckNames:[],
  sourcePreventsForcePush:false,sourcePreventsDeletion:false,
  sourceBlocksAdminBypassIndependentlyVerified:false
 };
 const pullRules=rules.filter(r=>r?.type==='pull_request');
 const checkRules=rules.filter(r=>r?.type==='required_status_checks');
 const statuses=checkRules.flatMap(r=>
  Array.isArray(r.parameters?.required_status_checks)?
   r.parameters.required_status_checks.map(x=>x.context).filter(x=>typeof x==='string'):[]);
 return {
  observedRuleCount:rules.length,
  sourceRequiresPr:pullRules.length>0,
  sourceTwoReviews:pullRules.some(r=>
   Number.isInteger(r.parameters?.required_approving_review_count)&&
   r.parameters.required_approving_review_count>=2),
  sourceCodeOwnerReview:pullRules.some(r=>r.parameters?.require_code_owner_review===true),
  sourceLastPushApproval:pullRules.some(r=>r.parameters?.require_last_push_approval===true),
  sourceStatusCheckNames:[...new Set(statuses)].sort(),
  sourcePreventsForcePush:rules.some(r=>r?.type==='non_fast_forward'),
  sourcePreventsDeletion:rules.some(r=>r?.type==='deletion'),
  // Effective rules API does not independently prove ruleset bypass actors.
  sourceBlocksAdminBypassIndependentlyVerified:false
 };
}
function legacyProtectionSummary(protection){
 if(!obj(protection))return {available:false,
  enforcedReviewCount:null,dismissStaleReviews:false,
  requireCodeOwnerReviews:false,requireLastPushApproval:false,
  enforceAdmins:false};
 const r=protection.required_pull_request_reviews;
 return {available:true,
  enforcedReviewCount:Number.isInteger(r?.required_approving_review_count)?
   r.required_approving_review_count:null,
  dismissStaleReviews:r?.dismiss_stale_reviews===true,
  requireCodeOwnerReviews:r?.require_code_owner_reviews===true,
  requireLastPushApproval:r?.require_last_push_approval===true,
  enforceAdmins:protection.enforce_admins?.enabled===true};
}
function latestExactHeadReviews(reviews,headSha,author){
 if(!Array.isArray(reviews))return {
  submittedReviewCount:null,distinctLatestHeadApprovalCount:0,
  observedApproverLogins:[],reviewerRolesAuthenticated:false
 };
 const latest=new Map();
 for(const item of reviews){
  const login=item?.user?.login;
  if(typeof login!=='string'||!login||!Number.isInteger(item.id)||
     typeof item.state!=='string')continue;
  const prior=latest.get(login);
  if(!prior||safeTimestamp(item.submitted_at)>safeTimestamp(prior.submitted_at)||
    (safeTimestamp(item.submitted_at)===safeTimestamp(prior.submitted_at)&&item.id>prior.id))
   latest.set(login,item);
 }
 const approved=[...latest.values()].filter(x=>x.state==='APPROVED'&&
  x.commit_id===headSha&&x.user.login!==author).map(x=>x.user.login).sort();
 return {
  submittedReviewCount:reviews.length,
  distinctLatestHeadApprovalCount:approved.length,
  observedApproverLogins:approved.slice(0,16),
  reviewerRolesAuthenticated:false
 };
}
export function assessObservedGithubGovernance(snapshot,{expectedRepository=REPO,
 expectedBranch=DEV,expectedBase='main'}={}){
 const anomalies=new Set();
 const endpoints=snapshot?.endpoints;
 if(!obj(endpoints))throw Error('BY missing validated GitHub observation');
 const endpointStatuses={};
 for(const name of Object.keys(ENDPOINTS)){
  const status=endpoints[name]?.status;
  endpointStatuses[name]=typeof status==='string'?status:'unavailable';
  if(status!=='read')anomalies.add('BY_GITHUB_'+name.toUpperCase()+'_NOT_READ');
 }
 const pr=endpoints.pr?.status==='read'?endpoints.pr.data:null;
 const prDescriptionBytes=pr?.body===null?0:
  typeof pr?.body==='string'?Buffer.byteLength(pr.body,'utf8'):null;
 const prDescriptionWithinBudget=Number.isSafeInteger(prDescriptionBytes)&&
  prDescriptionBytes<=BY_MAX_PR_DESCRIPTION_BYTES;
 if(!prDescriptionWithinBudget)
  anomalies.add('BY_PR_DESCRIPTION_OUTSIDE_BOUNDED_EVIDENCE_INDEX');
 const correctRepo=expectedRepository===REPO&&
  snapshot.repository===REPO;
 const correctPR=pr?.number===1&&pr?.state==='open'&&pr?.draft===true&&
  pr?.merged===false&&pr?.base?.ref===expectedBase&&
  pr?.head?.ref===expectedBranch&&pr?.user?.login===AUTHOR&&
  pr?.base?.repo?.full_name===REPO&&
  pr?.head?.repo?.full_name===REPO&&
  SHA.test(pr?.head?.sha??'')&&SHA.test(pr?.base?.sha??'');
 const exactGitHubEventSource=SHA.test(snapshot.eventHeadSha??'')&&
  SHA.test(snapshot.eventBaseSha??'')&&
  snapshot.eventHeadSha===pr?.head?.sha&&
  snapshot.eventBaseSha===pr?.base?.sha;
 if(!exactGitHubEventSource)
  anomalies.add('BY_PR_SOURCE_HEAD_OR_BASE_DRIFT_FROM_EVENT');
 if(!correctRepo||!correctPR)anomalies.add('BY_PR_REPO_OR_DRAFT_IDENTITY_MISMATCH');
 const ciRefGood=snapshot.eventName==='pull_request'&&
  snapshot.githubRef==='refs/pull/1/merge'&&
  snapshot.githubHeadRef===DEV&&snapshot.githubBaseRef==='main'&&
  SHA.test(snapshot.githubSha??'');
 if(!ciRefGood)anomalies.add('BY_CI_REF_OR_MERGE_SHA_INVALID');
 // Github's test-merge commit must be independently correlated to PR
 // merge_commit_sha if the API reports it; absent/changed => UNKNOWN.
 const mergeMatches=ciRefGood&&
  pr?.merge_commit_sha===snapshot.githubSha;
 if(!mergeMatches)anomalies.add('BY_PR_TEST_MERGE_SHA_UNCORRELATED');
 const reviews=latestExactHeadReviews(
  endpoints.reviews?.status==='read'?endpoints.reviews.data:null,
  pr?.head?.sha,AUTHOR);
 if(reviews.distinctLatestHeadApprovalCount<2)
  anomalies.add('BY_INSUFFICIENT_EXACT_HEAD_NONAUTHOR_REVIEWS');
 const rules=appliedRulesSummary(
  endpoints.rules?.status==='read'?endpoints.rules.data:null);
 const legacy=legacyProtectionSummary(
  endpoints.protection?.status==='read'?endpoints.protection.data:null);
 const observableRulesHaveMinimum=
  rules.sourceRequiresPr&&rules.sourceTwoReviews&&
  rules.sourceCodeOwnerReview&&rules.sourceLastPushApproval&&
  rules.sourcePreventsForcePush&&rules.sourcePreventsDeletion&&
  REQUIRED_CHECKS.every(x=>rules.sourceStatusCheckNames.includes(x));
 const observableLegacyMinimum=legacy.available&&
  legacy.enforcedReviewCount>=2&&legacy.dismissStaleReviews&&
  legacy.requireCodeOwnerReviews&&legacy.requireLastPushApproval&&
  legacy.enforceAdmins;
 if(!observableRulesHaveMinimum&&!observableLegacyMinimum)
  anomalies.add('BY_BRANCH_PROTECTION_REQUIREMENTS_NOT_ESTABLISHED');
 // Rules may be bypassed by admins/apps; an apparently complete read-only
 // snapshot is NOT independently accepted release authority.
 if(!rules.sourceBlocksAdminBypassIndependentlyVerified)
  anomalies.add('BY_RULESET_BYPASS_CONTROL_NOT_INDEPENDENTLY_PROVEN');
 return Object.freeze({
  schemaVersion:1,phase:'1BY',kind:'READ_ONLY_GITHUB_GOVERNANCE_OBSERVATION',
  endpointStatuses,
  prDescriptionWithinBudget,
  observedPrDescriptionUtf8Bytes:prDescriptionBytes,
  prDescriptionBudgetUtf8Bytes:BY_MAX_PR_DESCRIPTION_BYTES,
  githubRepoContextMatched:correctRepo,
  observedPrDraftAndUnmerged:correctPR,
  eventSourceHeadAndBaseMatch:exactGitHubEventSource,
  observedDevHeadSha:correctPR?pr.head.sha:null,
  observedBaseSha:correctPR?pr.base.sha:null,
  observedPrMergeSha:mergeMatches?snapshot.githubSha:null,
  ciMergeMatchesPrApi:mergeMatches,
  reviews,rules,legacy,
  branchRulesOrLegacyApiReadSucceeded:
   endpoints.rules?.status==='read'||endpoints.protection?.status==='read',
  effectiveProtectedBranchPolicyIndependentlyAuthenticated:false,
  observableRequiredBranchRulesPresent:
   observableRulesHaveMinimum||observableLegacyMinimum,
  independentReviewerSecurityAndBusinessRolesVerified:false,
  externallyEnrolledReviewerKeysVerified:false,
  signedCIProvenanceVerified:false,
  externallyWitnessedWormProvenanceVerified:false,
  protectedBranchAdminBypassIndependentlyReviewed:false,
  genuineProviderAuthorizationVerified:false,
  zeroHighDependencyAuditPassed:false,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('BY read-only observation only; no external approval command');
 const snapshot=await collectReadonlyGithubSnapshot({
  token:process.env.GITHUB_READ_TOKEN,environment:process.env
 });
 const result=assessObservedGithubGovernance(snapshot);
 const sources={};
 for(const name of BUILD_INPUT_PATHS)sources[name]=readFileSync(name,'utf8');
 const inventory=makeBuildInputInventory(sources,process.env);
 const output={kind:'LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD',
  sourceBundleSha256:inventory.bundleSha256,
  snapshotDerived:result,
  endpointReadSuccessCount:
   Object.values(result.endpointStatuses).filter(x=>x==='read').length,
  externallySigned:false,independentWorm:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 writeFileSync('phase1by-github-readonly-governance-hold.json',
  JSON.stringify(output,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(output,null,2));
 // No review or ruleset approval could ever turn this into GO.
 if(result.prDescriptionWithinBudget===false||
    result.productionReleaseAuthorized||output.productionReleaseAuthorized||
    result.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{await main();}catch(e){
  console.error('Phase 1BY protected repo observer HOLD failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
