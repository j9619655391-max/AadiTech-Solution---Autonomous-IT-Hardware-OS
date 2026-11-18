import {Buffer} from 'node:buffer';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessProposedMainRuleset,REPO,REQUIRED_JOBS}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';

// Phase 1CN: actual official GitHub ruleset-list/detail read-only monitor.
// A read-scoped job is explicitly NOT entitled to see all bypass actors:
// GitHub hides ruleset.bypass_actors unless caller can WRITE the ruleset.
// This is not a policy installer, reviewer-identity authenticator, merger,
// production gate waiver, signed source provenance or external acceptance.
const ROOT='https://api.github.com/repos/'+REPO;
const GHSA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const LIST_SUFFIX='/rulesets?per_page=100&page=';
const LIST_PARAMS='&includes_parents=true&targets=branch';
const RULESET_ID=/^[1-9][0-9]{0,11}$/;
const MAX_JSON_BYTES=131072;
const MAX_LIST=12;
const EXPECTED_CONTEXTS=new Set(REQUIRED_JOBS);
const code=x=>x===200?'read':x===401||x===403?'access_denied':
 x===404?'not_found_or_hidden':'unavailable';
export function rulesetListPath(page){
 if(!Number.isInteger(page)||page<1||page>2)throw Error('CN_UNAPPROVED_PAGE');
 return LIST_SUFFIX+page+LIST_PARAMS;
}
export function rulesetDetailPath(id){
 if(!RULESET_ID.test(String(id)))throw Error('CN_UNAPPROVED_RULESET_ID');
 return '/rulesets/'+String(id)+'?includes_parents=true';
}
export async function readOfficialRulesets(path,token,fetchImpl=fetch){
 if(![rulesetListPath(1),rulesetListPath(2)].includes(path)&&
  !/^\/rulesets\/[1-9][0-9]{0,11}\?includes_parents=true$/.test(path))
  throw Error('CN_UNREVIEWED_GITHUB_ROUTE');
 if(typeof token!=='string'||token.length<1||token.length>4096)
  return {status:'unavailable',data:null,httpStatus:null};
 const url=ROOT+path;
 const ac=new AbortController(),timer=setTimeout(()=>ac.abort(),6000);
 try{
  const result=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:ac.signal,
   headers:{
    Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1CN-ReadOnly-Ruleset-Inventory-HOLD'
   }
  });
  if(result.status!==200)return {
   status:code(result.status),data:null,httpStatus:result.status
  };
  if(result.redirected||result.url!==url||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      result.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null,httpStatus:200};
  const length=result.headers?.get?.('content-length');
  if(length!==null&&length!==undefined&&
     (!/^\d+$/.test(length)||Number(length)>MAX_JSON_BYTES))
   return {status:'invalid',data:null,httpStatus:200};
  const reader=result.body?.getReader();
  if(!reader)return {status:'invalid',data:null,httpStatus:200};
  let size=0;const chunks=[];
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))return {status:'invalid',data:null,httpStatus:200};
   size+=value.byteLength;
   if(size>MAX_JSON_BYTES)return {status:'invalid',data:null,httpStatus:200};
   chunks.push(Buffer.from(value));
  }
  return {status:'read',
   data:JSON.parse(Buffer.concat(chunks).toString('utf8')),httpStatus:200};
 }catch{return {status:'unavailable',data:null,httpStatus:null};}
 finally{clearTimeout(timer);}
}
export async function collectActualRulesets({token,fetchImpl=fetch}={}){
 const listResponse=await readOfficialRulesets(rulesetListPath(1),token,fetchImpl);
 if(listResponse.status!=='read')
  return {listStatus:listResponse.status,listingComplete:false,
   listed:[],details:{},detailStatus:{},httpStatus:listResponse.httpStatus};
 if(!Array.isArray(listResponse.data)||listResponse.data.length>100)
  return {listStatus:'invalid',listingComplete:false,
   listed:[],details:{},detailStatus:{},httpStatus:200};
 let listed=[...listResponse.data],complete=true;
 if(listed.length===100){
  const second=await readOfficialRulesets(rulesetListPath(2),token,fetchImpl);
  if(second.status!=='read'||!Array.isArray(second.data)||second.data.length>100)
   return {listStatus:'incomplete_pagination',listingComplete:false,
    listed:[],details:{},detailStatus:{},httpStatus:200};
  listed=[...listed,...second.data];
  if(second.data.length===100)complete=false;
 }
 if(!complete||listed.length>MAX_LIST)
  return {listStatus:'incomplete_pagination',listingComplete:false,
   listed:[],details:{},detailStatus:{},httpStatus:200};
 const ids=listed.map(item=>item?.id);
 if(ids.some(id=>!Number.isSafeInteger(id)||!RULESET_ID.test(String(id)))||
    new Set(ids).size!==ids.length)
  return {listStatus:'invalid',listingComplete:false,
   listed:[],details:{},detailStatus:{},httpStatus:200};
 const details={},detailStatus={};
 for(const id of ids){
  const result=await readOfficialRulesets(rulesetDetailPath(id),token,fetchImpl);
  detailStatus[String(id)]=result.status;
  if(result.status==='read')details[String(id)]=result.data;
 }
 return {listStatus:'read',listingComplete:true,listed,details,detailStatus,
  httpStatus:200};
}
const proposalMatches=(detail,proposal)=>{
 if(!object(detail)||!object(proposal)||detail.target!=='branch'||
    detail.enforcement!=='active')return false;
 if(JSON.stringify(detail.conditions?.ref_name?.include)!==
    JSON.stringify(proposal.conditions.ref_name.include)||
    JSON.stringify(detail.conditions?.ref_name?.exclude)!==
    JSON.stringify(proposal.conditions.ref_name.exclude))
  return false;
 const rules=detail.rules;
 if(!Array.isArray(rules))return false;
 const find=type=>rules.filter(r=>r?.type===type);
 if(['deletion','non_fast_forward','pull_request','required_status_checks']
  .some(type=>find(type).length!==1))return false;
 const pull=find('pull_request')[0].parameters;
 const required=proposal.rules.find(x=>x.type==='pull_request').parameters;
 for(const name of [
  'dismiss_stale_reviews_on_push','require_code_owner_review',
  'require_last_push_approval','required_approving_review_count',
  'required_review_thread_resolution'
 ])if(pull?.[name]!==required[name])return false;
 if(!Array.isArray(pull?.allowed_merge_methods)||
    required.allowed_merge_methods.some(m=>!pull.allowed_merge_methods.includes(m)))return false;
 const checks=find('required_status_checks')[0].parameters;
 if(checks?.strict_required_status_checks_policy!==true||
    checks?.do_not_enforce_on_create!==false||
    !Array.isArray(checks?.required_status_checks))return false;
 const contexts=checks.required_status_checks.map(c=>c?.context);
 return contexts.length===EXPECTED_CONTEXTS.size&&
  contexts.every(c=>EXPECTED_CONTEXTS.has(c))&&
  new Set(contexts).size===EXPECTED_CONTEXTS.size;
};
export function assessActualRulesetReconciliation({
 observations={},proposal=null,byReport=null,clReport=null,environment={}
}={}){
 const errors=new Set(),anomalies=new Set();
 const cm=assessProposedMainRuleset(proposal);
 if(!cm.localProposedRestPayloadStructurallySafe)
  errors.add('CN_UNREVIEWED_LOCAL_GITHUB_RULESET_PROPOSAL');
 const by=byReport?.snapshotDerived,cl=clReport?.decision;
 if(byReport?.kind!=='LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD'||
    !HASH.test(byReport?.sourceBundleSha256??'')||
    byReport?.productionReleaseAuthorized!==false||
    byReport?.releaseDecision!=='HOLD'||
    by?.phase!=='1BY'||by?.observedPrDraftAndUnmerged!==true||
    by?.eventSourceHeadAndBaseMatch!==true||
    by?.ciMergeMatchesPrApi!==true||
    by?.productionReleaseAuthorized!==false||
    by?.releaseDecision!=='HOLD')
  errors.add('CN_ACTUAL_GITHUB_PR_AND_BRANCH_SOURCE_CUSTODY_INVALID');
 if(clReport?.sourceExternallySigned!==false||
    clReport?.productionReleaseAuthorized!==false||
    clReport?.releaseDecision!=='HOLD'||
    cl?.phase!=='1CL'||cl?.repo!==REPO||
    cl?.officialPublicObservationStructurallyValid!==true||
    cl?.productionReleaseAuthorized!==false||
    cl?.releaseDecision!=='HOLD'||
    cl?.observedDevHeadSha!==by?.observedDevHeadSha)
  errors.add('CN_CODEOWNERS_OBSERVER_CUSTODY_INVALID');
 if(!object(environment)||environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_JOB!=='live-github-governance-hold'||
    environment.GITHUB_REPOSITORY!==REPO||
    environment.GITHUB_REF!=='refs/pull/1/merge'||
    !GHSA.test(environment.GITHUB_SHA??'')||
    !GHSA.test(by?.observedDevHeadSha??'')||
    !GHSA.test(by?.observedBaseSha??'')||
    by?.observedPrMergeSha!==environment.GITHUB_SHA)
  errors.add('CN_GITHUB_RUN_SOURCE_JOB_OR_PR_SHA_INVALID');
 const listed=observations?.listStatus==='read'&&
  observations.listingComplete===true&&
  Array.isArray(observations.listed)?observations.listed:null;
 if(!listed)anomalies.add('CN_OFFICIAL_RULESET_LIST_UNAVAILABLE_OR_INCOMPLETE');
 if(listed&&listed.length===0)anomalies.add('CN_NO_REPOSITORY_RULESETS_OBSERVED');
 let fullyVisible=listed!==null&&listed.length>0,hidden=0,configuredBypasses=0,
  matching=0,drifted=0,activeCount=0;
 const details=[];
 for(const item of listed??[]){
  const id=item?.id;
  const detail=observations.details?.[String(id)];
  const sourceStatus=observations.detailStatus?.[String(id)];
  if(!Number.isSafeInteger(id)||id<1||!RULESET_ID.test(String(id))||
     !object(item)||!['branch','tag','push','repository'].includes(item.target)||
     !['active','evaluate','disabled'].includes(item.enforcement)){
    fullyVisible=false;anomalies.add('CN_UNREVIEWED_RULESET_LIST_RECORD');continue;
  }
  if(sourceStatus!=='read'||!object(detail)||detail.id!==id||
     detail.name!==item.name||detail.target!==item.target||
     detail.enforcement!==item.enforcement){
    fullyVisible=false;anomalies.add('CN_RULESET_DETAIL_UNAVAILABLE_OR_MISMATCH');continue;
  }
  if(item.enforcement==='active'&&item.target==='branch')activeCount++;
  // GitHub omits bypass_actors for read-only callers; an omitted member is
  // NEVER interpreted as [] or verified lack of admin/app bypass.
  const bypassVisible=Array.isArray(detail.bypass_actors);
  if(!bypassVisible){hidden++;fullyVisible=false;
   anomalies.add('CN_GITHUB_RULESET_BYPASS_ACTORS_NOT_VISIBLE');}
  else {
   configuredBypasses+=detail.bypass_actors.length;
   if(detail.bypass_actors.length)anomalies.add('CN_CONFIGURED_BYPASS_ACTORS_OBSERVED');
  }
  const matches=item.enforcement==='active'&&item.target==='branch'&&
    proposalMatches(detail,proposal);
  if(matches)matching++;
  else if(item.target==='branch'&&item.enforcement==='active')drifted++;
  details.push({
   sourceId:id,status:'read',target:item.target,enforcement:item.enforcement,
   matchesStrictMainProposal:matches,
   bypassActorsFieldVisibleToThisCaller:bypassVisible,
   configuredBypassActorCountVisible:bypassVisible?detail.bypass_actors.length:null
  });
 }
 if(listed?.length&&matching===0)
  anomalies.add('CN_NO_ACTIVE_PROPOSAL_MATCHING_MAIN_RULESET_OBSERVED');
 if(by?.rules?.observedRuleCount===0&&matching>0)
  anomalies.add('CN_OFFICIAL_APPLIED_BRANCH_RULES_DISAGREE_WITH_RULESET_DETAILS');
 if(by?.rules?.observedRuleCount===0)
  anomalies.add('CN_GITHUB_EFFECTIVE_MAIN_RULES_EMPTY');
 if(by?.reviews?.distinctLatestHeadApprovalCount<2)
  anomalies.add('CN_GENUINE_CURRENT_HEAD_APPROVAL_QUORUM_ABSENT');
 if(cl?.selectedCodeownersLocation===null)
  anomalies.add('CN_MAIN_CODEOWNERS_NOT_OBSERVED');
 if(cl?.requestedReviewerSummary?.requestedUsers===0&&
    cl?.requestedReviewerSummary?.requestedTeams===0)
  anomalies.add('CN_NO_INDEPENDENT_REVIEWER_REQUEST_OBSERVED');
 const clean=errors.size===0;
 return Object.freeze({
  phase:'1CN',schemaVersion:1,
  kind:'OFFICIAL_LIVE_RULESET_BYPASS_RECONCILIATION_READONLY_HOLD',
  repo:REPO,sourceHeadSha:by?.observedDevHeadSha??null,
  proposalSha256:cm.proposalContentSha256,
  listedRulesetCount:listed?.length??null,
  activeBranchRulesetCount:listed?activeCount:null,
  exactProposalMatchingRulesetCount:listed?matching:null,
  activeBranchRulesetDriftCount:listed?drifted:null,
  detailRecords:details,
  bypassFieldHiddenOnReadOnlySourceCount:listed?hidden:null,
  configuredBypassActorsObservedCount:listed?configuredBypasses:null,
  rulesetListAndAllBypassFieldsReadable:fullyVisible,
  officialReadOnlySourceChainStructurallyValid:clean,
  anomalyCodes:[...errors,...anomalies].sort(),
  independentSecurityAndBusinessRolesAuthenticated:false,
  reviewerAccessAndLatestHeadApprovalsIndependentlyVerified:false,
  mainCODEOWNERSAppliedAndRuleEnforced:false,
  configuredAdminAndAppBypassAbsenceIndependentlyVerified:false,
  actualMainRulesetAuthorizedAndEnforced:false,
  externalProviderLegalWormAndCiSigningApproved:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function read(path,max=1048576){
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)
  throw Error('CN_LOCAL_OBSERVER_OR_PROPOSAL_NOT_SAFE');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CN_ONLY_READONLY_CI_HOLD');
 const observations=await collectActualRulesets({
  token:process.env.GITHUB_READ_TOKEN
 });
 const verdict=assessActualRulesetReconciliation({
  observations,
  proposal:read('docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json',65536),
  byReport:read('phase1by-github-readonly-governance-hold.json',262144),
  clReport:read('phase1cl-live-codeowners-reviewer-onboarding-hold.json',262144),
  environment:process.env
 });
 const report={verdict,observationStatus:{
  listStatus:observations.listStatus,
  detailStatus:observations.detailStatus
 },externallySigned:false,independentWorm:false,
  releaseDecision:'HOLD',productionReleaseAuthorized:false};
 writeFileSync('phase1cn-official-ruleset-bypass-reconciliation-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(!verdict.officialReadOnlySourceChainStructurallyValid||
    verdict.releaseDecision!=='HOLD'||verdict.productionReleaseAuthorized!==false)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CN observed GitHub rulesets not accepted:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
