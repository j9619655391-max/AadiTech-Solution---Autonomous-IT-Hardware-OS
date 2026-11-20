import {Buffer} from 'node:buffer';
import {TextDecoder} from 'node:util';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,AUTHOR,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID}
 from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {evaluateLatestSubmittedReviews}
 from './phase1co-live-exact-head-reviewer-quorum.mjs';

// Phase 1DC: LIVE GitHub official read-only governance readiness, no mock
// provider onboarding and no review request, ruleset install or production GO.
// A 403 from integration is UNKNOWN, never falsely "no branch protection".
export const API='https://api.github.com/repos/'+REPO;
export const PATHS=Object.freeze({
 main:'/git/ref/heads/main',
 pr:'/pulls/1',
 reviews:'/pulls/1/reviews?per_page=100',
 rulesets:'/rulesets?per_page=100&includes_parents=true&targets=branch',
 protection:'/branches/main/protection',
 githubCodeowners:'/contents/.github/CODEOWNERS?ref=main',
 rootCodeowners:'/contents/CODEOWNERS?ref=main',
 docsCodeowners:'/contents/docs/CODEOWNERS?ref=main'
});
const SHA=/^[0-9a-f]{40}$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const status=x=>object(x)&&['read','absent_or_hidden','access_denied','unavailable','invalid'].includes(x.status);
const read=x=>status(x)&&x.status==='read';
const err=(x)=>status(x)?x.status:'unavailable';
const validUser=x=>typeof x==='string'&&/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(x);
export const EXPECTED_PATHS=Object.freeze(Object.keys(PATHS));
export const EXTERNAL_GATES=Object.freeze([
 'GOVERNANCE_SECURITY_AND_BUSINESS_NONAUTHOR_MANDATE',
 'GOVERNANCE_ADMIN_INSTALL_MAIN_CODEOWNERS',
 'GOVERNANCE_ADMIN_ENFORCE_BYPASS_FREE_MAIN_RULESETS',
 'GOVERNANCE_INDEPENDENT_LATEST_HEAD_REVIEWERS',
 'CORPORATE_MCA_AND_LEGAL_SIGNATORY',
 'CA_CCA_RCAI_EMUDHRA_SIGNED_CHAIN_CRL_OCSP',
 'PROVIDER_OFFICIAL_AUTHORIZED_ENDPOINTS_AND_REVOCATION',
 'EXTERNAL_IMMUTABLE_CAS_WORM_DR_INDEPENDENT_CHECK',
 'OIDC_SLSA_AND_SECURITY_LEGAL_OWNER_OPS_STAGING'
]);
const applyErrors=(errors,condition,message)=>{if(!condition)errors.add(message);};
function officialRef(x){
 return read(x)&&x.data?.ref==='refs/heads/main'&&
  SHA.test(x.data?.object?.sha??'')&&
  x.data?.object?.type==='commit';
}
function acceptablePr(x){
 const p=x?.data;
 return read(x)&&object(p)&&p.number===1&&p.state==='open'&&
  p.draft===true&&p.merged===false&&p.user?.login===AUTHOR&&
  p.head?.ref==='chore/phase0-foundation-20261106'&&
  p.base?.ref==='main'&&
  p.head?.repo?.full_name===REPO&&p.base?.repo?.full_name===REPO&&
  SHA.test(p.head?.sha??'')&&SHA.test(p.base?.sha??'')&&
  SHA.test(p.merge_commit_sha??'')&&
  typeof p.updated_at==='string'&&Number.isFinite(Date.parse(p.updated_at));
}
// Phase 1DH: syntax-only *strict subset* shared with the 1CM admin
// proposal and 1DG pinned SHA/role-specific validator. No corporate
// identity, Git blob authenticity, effective admin protection or GO follows.
export const REVIEWED_CODEOWNER_PATTERNS=Object.freeze([
 '*','/.github/CODEOWNERS','/.github/workflows/',
 '/docs/security/','/server/security/','/scripts/','/tests/'
]);
const REVIEWED_OWNER_SET=new Set(REVIEWED_CODEOWNER_PATTERNS);
export function validOwners(data,path){
 if(!object(data)||data.type!=='file'||data.path!==path||
    data.encoding!=='base64'||!SHA.test(data.sha??'')||
    typeof data.content!=='string'||data.content.length>87384||
    !Number.isSafeInteger(data.size)||data.size<1||data.size>65536)
  return {valid:false,rootCovers:false};
 const b64=data.content.replace(/\s/g,'');
 if(!b64||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64))
  return {valid:false,rootCovers:false};
 const raw=Buffer.from(b64,'base64');
 if(raw.length!==data.size||raw.toString('base64')!==b64)
  return {valid:false,rootCovers:false};
 let text;
 try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);}
 catch{return {valid:false,rootCovers:false};}
 // Fewer cases than GitHub CODEOWNERS supports are intentional: unknown
 // grammar or a late shadow rule must be reviewed by a real administrator.
 if(!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(text)||
    text.includes('\r')&&!/^([^\r]|\r\n)*$/.test(text))
  return {valid:true,rootCovers:false};
 const lines=text.split(/\r?\n/).map(x=>x.trim())
  .filter(x=>x.length>0&&!x.startsWith('#'));
 if(lines.length<1||lines.length>REVIEWED_OWNER_SET.size)
  return {valid:true,rootCovers:false};
 const seen=new Set();let firstOwners=null;
 for(const line of lines){
  const fields=line.split(/[\t ]+/);
  if(fields.length!==3||!REVIEWED_OWNER_SET.has(fields[0])||
     seen.has(fields[0]))return {valid:true,rootCovers:false};
  const logins=fields.slice(1).map(x=>x.startsWith('@')?x.slice(1):'');
  if(!logins.every(x=>validUser(x)&&
     x.toLowerCase()!==AUTHOR.toLowerCase())||
     logins[0].toLowerCase()===logins[1].toLowerCase())
   return {valid:true,rootCovers:false};
  const pair=logins.map(x=>x.toLowerCase()).sort().join('\0');
  if(firstOwners!==null&&pair!==firstOwners)
   return {valid:true,rootCovers:false};
  firstOwners=pair;seen.add(fields[0]);
 }
 return {valid:true,rootCovers:seen.has('*')};
}
export function protectedMainRuleset(detail){
 if(!object(detail)||detail.enforcement!=='active'||detail.target!=='branch'||
    !Array.isArray(detail.bypass_actors)||detail.bypass_actors.length!==0||
    !Array.isArray(detail.conditions?.ref_name?.include)||
    !detail.conditions.ref_name.include.includes('refs/heads/main')||
    !Array.isArray(detail.conditions?.ref_name?.exclude)||
    detail.conditions.ref_name.exclude.length!==0||
    !Array.isArray(detail.rules))return false;
 const matching=type=>detail.rules.filter(x=>x?.type===type);
 if(['deletion','non_fast_forward','pull_request','required_status_checks']
  .some(type=>matching(type).length!==1))return false;
 const pull=matching('pull_request')[0].parameters;
 if(!Number.isSafeInteger(pull?.required_approving_review_count)||
    pull.required_approving_review_count<2||
    pull?.dismiss_stale_reviews_on_push!==true||
    pull?.require_code_owner_review!==true||
    pull?.require_last_push_approval!==true||
    pull?.required_review_thread_resolution!==true)return false;
 const checks=matching('required_status_checks')[0].parameters;
 if(checks?.strict_required_status_checks_policy!==true||
    checks?.do_not_enforce_on_create!==false||
    !Array.isArray(checks.required_status_checks)||
    checks.required_status_checks.length!==REQUIRED_JOBS.length)
  return false;
 const seen=new Set();
 for(const c of checks.required_status_checks){
  if(!REQUIRED_JOBS.includes(c?.context)||seen.has(c.context)||
     c.integration_id!==GITHUB_ACTIONS_INTEGRATION_ID)return false;
  seen.add(c.context);
 }
 return seen.size===REQUIRED_JOBS.length;
}
export function assessActualReadOnlyHandoff(observations={}){
 const errors=new Set(),pr1=observations?.prBefore,pr2=observations?.prAfter,
  main1=observations?.mainBefore,main2=observations?.mainAfter;
 applyErrors(errors,acceptablePr(pr1)&&acceptablePr(pr2),
  'DC_OFFICIAL_DRAFT_PR_STATE_MISSING_OR_INVALID');
 const stable=acceptablePr(pr1)&&acceptablePr(pr2)&&
  pr1.data.head.sha===pr2.data.head.sha&&
  pr1.data.base.sha===pr2.data.base.sha&&
  pr1.data.merge_commit_sha===pr2.data.merge_commit_sha&&
  pr1.data.updated_at===pr2.data.updated_at;
 applyErrors(errors,stable,'DC_LIVE_PR_TOUCHED_DURING_EVIDENCE_READ');
 const mainStable=officialRef(main1)&&officialRef(main2)&&
  main1.data.object.sha===main2.data.object.sha&&
  main1.data.object.sha===pr1?.data?.base?.sha;
 applyErrors(errors,mainStable,'DC_MAIN_BASE_REF_CHANGED_OR_UNREADABLE');
 const reviews=observations?.reviews;
 const complete=reviews?.status==='read'&&reviews.complete===true&&
  Array.isArray(reviews.data)&&reviews.data.length<300;
 applyErrors(errors,complete,'DC_SUBMITTED_REVIEW_PAGINATION_MISSING');
 const review=complete?
  evaluateLatestSubmittedReviews(reviews.data,pr1?.data?.head?.sha,AUTHOR):
  null;
 if(!review?.valid)errors.add('DC_SUBMITTED_GITHUB_REVIEWS_UNTRUSTED');
 const technicalReview=stable&&mainStable&&review?.valid===true&&
  review.counts.currentHeadApprovals>=2;
 if(!technicalReview)errors.add('DC_TWO_DISTINCT_NONAUTHOR_LATEST_HEAD_APPROVALS_NOT_OBSERVED');
 const owners=observations?.codeowners;
 let present=0,coverage=0,ownerHidden=false,selectedEffective=false;
 for(const [key,path] of [
  ['githubCodeowners','.github/CODEOWNERS'],
  ['rootCodeowners','CODEOWNERS'],['docsCodeowners','docs/CODEOWNERS']]){
  const r=owners?.[key];
  if(read(r)){
   const check=validOwners(r.data,path);
   if(check.valid)present++;
   // GitHub uses the FIRST existing CODEOWNERS file, not the union
   // of coverage in all three file locations. A broken higher-priority
   // file must never be rescued by a valid lower-priority one.
   if(!selectedEffective){
    selectedEffective=true;
    if(check.rootCovers)coverage=1;
    else errors.add('DC_CODEOWNERS_EXISTS_BUT_STRICT_MAIN_COVERAGE_NOT_PROVEN_'+key);
   }
  }else if(!status(r)||!['absent_or_hidden','read'].includes(r.status))
   ownerHidden=true;
 }
 if(present===0||coverage===0)errors.add('DC_MAIN_CODEOWNERS_NOT_VERIFIABLY_INSTALLED');
 if(ownerHidden)errors.add('DC_CODEOWNERS_SOURCE_ACCESS_UNKNOWN');
 const list=observations?.rulesets;
 const listGood=list?.status==='read'&&list.complete===true&&
  Array.isArray(list.data)&&list.data.length<200&&
  list.data.every(x=>Number.isSafeInteger(x?.id)&&x.id>0)&&
  new Set(list.data.map(x=>x.id)).size===list.data.length;
 applyErrors(errors,listGood,'DC_OFFICIAL_RULESET_LIST_UNVERIFIED_OR_INCOMPLETE');
 let active=0,accepted=0,detailsUnknown=false;
 for(const item of listGood?list.data:[]){
  if(item.target!=='branch')continue;
  if(item.enforcement==='active')active++;
  const detail=observations?.rulesetDetails?.[String(item.id)];
  if(!read(detail)){detailsUnknown=true;continue;}
  if(protectedMainRuleset(detail.data))accepted++;
 }
 if(detailsUnknown)errors.add('DC_MAIN_RULESET_DETAIL_OR_BYPASS_VISIBILITY_UNKNOWN');
 if(accepted===0)errors.add('DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
 const branch=observations?.protection;
 const protectionAccessible=read(branch)&&
  branch.data?.enforce_admins?.enabled===true&&
  branch.data?.required_pull_request_reviews?.required_approving_review_count>=2&&
  branch.data?.required_pull_request_reviews?.dismiss_stale_reviews===true&&
  branch.data?.required_pull_request_reviews?.require_code_owner_reviews===true&&
  branch.data?.required_status_checks?.strict===true;
 const protectionDenied=err(branch)==='access_denied';
 if(!protectionAccessible)errors.add('DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK');
 // Branch protection may supplement, but never replaces a missing ruleset,
 // CODEOWNERS, independently authenticated officers or external acceptance.
 const items=[
  {key:'sourceAndStableDraftPr',observed:stable&&mainStable},
  {key:'twoTechnicalNonauthorLatestHeadApprovals',observed:technicalReview},
  {key:'mainCodeownersStrictCoverage',observed:coverage>0},
  {key:'mainActiveBypassFreeRuleset',observed:accepted>0},
  {key:'mainBranchProtectionReadable',observed:protectionAccessible},
  {key:'externalSecurityBusinessMandatesAuthenticated',observed:false},
  {key:'providerCaMcaAndWormDrIndependentlyApproved',observed:false}
 ];
 const technicallyObserved=stable&&mainStable&&technicalReview&&
  coverage>0&&accepted>0&&protectionAccessible&&errors.size===0;
 return Object.freeze({
  phase:'1DC',schemaVersion:1,
  kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
  repository:REPO,prNumber:1,
  currentDevelopmentHeadSha:stable?pr1.data.head.sha:null,
  currentMainBaseSha:mainStable?main1.data.object.sha:null,
  officialMainRefAndDraftPrStable:stable&&mainStable,
  officialSubmittedReviewPaginationComplete:complete,
  observedSubmittedReviewCount:review?.counts?.submitted??null,
  observedDistinctCurrentHeadNonauthorApprovals:
   review?.counts?.currentHeadApprovals??0,
  observedCodeownersFileCount:present,
  strictRootCoverageCodeownersFiles:coverage,
  observedActiveBranchRulesetCount:active,
  observedStrictBypassFreeMainRulesetCount:accepted,
  directMainBranchProtectionStatus:err(branch),
  directMainBranchProtectionExplicitly403:protectionDenied,
  technicallyObservedGithubPrerequisitesOnly:technicallyObserved,
  checklist:Object.freeze(items),
  outstandingExternalPrerequisiteKeys:EXTERNAL_GATES,
  anomalyCodes:Object.freeze([...errors].sort()),
  legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated:false,
  externallyAuthorizedTrustProviderMandateAndKeyEnrollment:false,
  independentlyVerifiedCcaRcaiEmudhraMcaCrLOcsp:false,
  actualExternalWormCasAndDrVerified:false,
  actualIndependentOidcSlsaAndStagingAcceptance:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
const maxLen=131072;
export function allowedPath(p){
 if(Object.values(PATHS).includes(p))return true;
 if(/^\/pulls\/1\/reviews\?per_page=100&page=[2-3]$/.test(p))return true;
 if(/^\/rulesets\?per_page=100&includes_parents=true&targets=branch&page=2$/.test(p))
  return true;
 return /^\/rulesets\/[1-9]\d{0,11}\?includes_parents=true$/.test(p);
}
export async function readActualGithubPath(path,{
 token='',fetchImpl=fetch
}={}){
 if(!allowedPath(path))throw Error('DC_REJECTED_NON_ALLOWLISTED_GITHUB_PATH');
 if(typeof token!=='string'||token.length>4096)
  return {status:'invalid',data:null,httpStatus:null};
 const url=API+path,ctl=new AbortController();
 const timer=setTimeout(()=>ctl.abort(),6500);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:ctl.signal,
   headers:{
    Accept:'application/vnd.github+json',
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-1DC-ReadOnly-Official-Governance-HOLD',
    ...(token?{Authorization:'Bearer '+token}:{})
   }
  });
  if(response.status!==200){
   return {status:response.status===403||response.status===401?
     'access_denied':response.status===404?'absent_or_hidden':'unavailable',
    data:null,httpStatus:response.status};
  }
  if(response.redirected||response.url!==url||
     !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      response.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null,httpStatus:200};
  const declared=response.headers?.get?.('content-length');
  if(declared!==null&&declared!==undefined&&
    (!/^\d+$/.test(declared)||Number(declared)>maxLen))
   return {status:'invalid',data:null,httpStatus:200};
  const reader=response.body?.getReader();
  if(!reader)return {status:'invalid',data:null,httpStatus:200};
  const parts=[];let n=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array)||n+value.length>maxLen)
    return {status:'invalid',data:null,httpStatus:200};
   n+=value.length;parts.push(Buffer.from(value));
  }
  const parsed=JSON.parse(Buffer.concat(parts).toString('utf8'));
  if(!object(parsed)&&!Array.isArray(parsed))
   return {status:'invalid',data:null,httpStatus:200};
  return {status:'read',data:parsed,httpStatus:200};
 }catch{return {status:'unavailable',data:null,httpStatus:null};}
 finally{clearTimeout(timer)}
}
export async function collectLiveActualGovernance({
 token='',fetchImpl=fetch
}={}){
 const readPath=path=>readActualGithubPath(path,{token,fetchImpl});
 const prBefore=await readPath(PATHS.pr);
 const mainBefore=await readPath(PATHS.main);
 const list=async(base,max,variant)=>{
  const first=await readPath(base);
  if(!read(first)||!Array.isArray(first.data)||first.data.length>100)
   return {status:first.status==='read'?'invalid':err(first),data:[],complete:false};
  const values=[...first.data];
  if(values.length===100){
   for(let p=2;p<=max;p++){
    const suffix=variant==='review'?'&page='+p:'&page=2';
    const next=await readPath(base+suffix);
    if(!read(next)||!Array.isArray(next.data)||next.data.length>100)
     return {status:err(next),data:[],complete:false};
    values.push(...next.data);
    if(next.data.length<100)break;
   }
   if(values.length>=max*100)return {status:'invalid',data:[],complete:false};
  }
  return {status:'read',data:values,complete:true};
 };
 const reviews=await list(PATHS.reviews,3,'review');
 const rulesets=await list(PATHS.rulesets,2,'rules');
 const rulesetDetails={};
 if(rulesets.complete&&rulesets.data.length<=12){
  for(const rule of rulesets.data){
   if(Number.isSafeInteger(rule?.id)&&rule.id>0&&rule.id<1e12)
    rulesetDetails[String(rule.id)]=await readPath(
     '/rulesets/'+rule.id+'?includes_parents=true');
  }
 }else if(rulesets.complete){
  rulesets.status='invalid';rulesets.complete=false;
 }
 const codeowners={};
 for(const name of ['githubCodeowners','rootCodeowners','docsCodeowners'])
  codeowners[name]=await readPath(PATHS[name]);
 const protection=await readPath(PATHS.protection);
 const mainAfter=await readPath(PATHS.main);
 const prAfter=await readPath(PATHS.pr);
 return assessActualReadOnlyHandoff({
  prBefore,prAfter,mainBefore,mainAfter,reviews,rulesets,
  rulesetDetails,codeowners,protection
 });
}
async function main(){
 const args=process.argv.slice(2);
 if(args.length!==1||args[0]!=='--inspect-actual-github-readonly'||
    process.env.GITHUB_ACTIONS==='true')
  throw Error('DC_ONLY_EXPLICIT_HUMAN_OFFICIAL_GITHUB_READS');
 const r=await collectLiveActualGovernance({
  token:process.env.GITHUB_READ_TOKEN??''
 });
 console.log(JSON.stringify(r,null,2));
 // This tool must never return exit 0 based on internal GitHub reviews only:
 // independent legal and production acceptance is still unverified.
 if(!r.officialMainRefAndDraftPrStable||r.productionReleaseAuthorized!==false)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('DC actual independent governance still HOLD:',
   e instanceof Error?e.message:'Unknown');process.exitCode=1;
 });
