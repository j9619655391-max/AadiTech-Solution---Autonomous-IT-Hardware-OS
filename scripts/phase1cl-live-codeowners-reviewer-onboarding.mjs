import {Buffer} from 'node:buffer';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1CL: *REAL official* read-only main-branch CODEOWNERS + requested
// reviewers observation. Does not create owners/reviews, authenticate human
// roles, configure protected main rules, certify GitHub API as signed WORM
// evidence, or override an externally gated production HOLD.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const AUTHOR='j9619655391-max';
const ROOT='/repos/'+REPO;
const API='https://api.github.com';
export const CODEOWNER_PATHS=Object.freeze([
 '.github/CODEOWNERS','CODEOWNERS','docs/CODEOWNERS'
]);
export const ENDPOINTS=Object.freeze({
 codeownersGithub:ROOT+'/contents/.github/CODEOWNERS?ref=main',
 codeownersRoot:ROOT+'/contents/CODEOWNERS?ref=main',
 codeownersDocs:ROOT+'/contents/docs/CODEOWNERS?ref=main',
 requestedReviewers:ROOT+'/pulls/1/requested_reviewers'
});
const KEYS=Object.keys(ENDPOINTS);
const CODEOWNER_KEYS=KEYS.filter(k=>k!=='requestedReviewers');
const SHA=/^[0-9a-f]{40}$/;
const SHA256=/^[0-9a-f]{64}$/;
const USER=/^@[A-Za-z0-9-]{1,39}(?:\/[A-Za-z0-9._-]{1,90})?$/;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const string=x=>typeof x==='string'&&x.length>0;
const MAX_JSON=131072;
const MAX_CODEOWNERS=65536;
const ALLOWED_STATUS=Object.freeze([
 'read','absent_or_hidden','access_denied','unavailable','invalid'
]);
function statusFromHttp(code){
 if(code===200)return 'read';
 if(code===404)return 'absent_or_hidden';
 if(code===401||code===403)return 'access_denied';
 return 'unavailable';
}
function validatedCodeowners(data,path){
 if(!object(data)||data.type!=='file'||data.path!==path||
    data.encoding!=='base64'||!SHA.test(data.sha??'')||
    typeof data.content!=='string'||data.content.length>MAX_CODEOWNERS*2)
  return null;
 const encoded=data.content.replace(/\s/g,'');
 if(!encoded||!/^([A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
  return null;
 const bytes=Buffer.from(encoded,'base64');
 if(bytes.length>MAX_CODEOWNERS||bytes.length<1||
    bytes.toString('base64')!==encoded||data.size!==bytes.length)
  return null;
 const text=bytes.toString('utf8');
 if(!Buffer.from(text,'utf8').equals(bytes)||text.includes('\0'))
  return null;
 let patternRows=0,ownerTokens=0,invalidRows=0;
 let explicitlyProtectsCodeowners=false,hasGlobalPattern=false;
 for(const line of text.split(/\r?\n/)){
  const trimmed=line.trim();
  if(!trimmed||trimmed.startsWith('#'))continue;
  const words=trimmed.split(/\s+/).filter(w=>!w.startsWith('#'));
  const [pattern,...owners]=words;
  if(!pattern||pattern.startsWith('!')||pattern.includes('[')||
     pattern.includes(']')||owners.length<1||owners.some(x=>!USER.test(x))){
   invalidRows++;continue;
  }
  patternRows++;ownerTokens+=owners.length;
  if(pattern==='*')hasGlobalPattern=true;
  if(pattern==='/.github/CODEOWNERS'||pattern==='/.github/'||
     pattern==='/CODEOWNERS'||pattern==='/.github/**')
   explicitlyProtectsCodeowners=true;
 }
 return {
  patternRows,ownerTokens,invalidRows,
  hasGlobalPattern,explicitlyProtectsCodeowners,
  syntacticallyHasAtLeastOneOwner:patternRows>0,
  baseBranchCodeownersOwnersAuthenticated:false,
  githubWritePermissionOfOwnerIndependentlyVerified:false,
  separateSecurityBusinessOwnersVerified:false,
  effectiveCodeOwnerReviewRequiredByMainRules:false
 };
}
function requestedSnapshot(data){
 if(!object(data)||!Array.isArray(data.users)||!Array.isArray(data.teams)||
    data.users.length>100||data.teams.length>100)return null;
 const users=[];
 for(const user of data.users){
  if(!object(user)||!string(user.login)||user.login.length>100||
     !Number.isSafeInteger(user.id)||user.id<=0)return null;
  users.push(user.login);
 }
 const teams=[];
 for(const team of data.teams){
  if(!object(team)||!string(team.slug)||team.slug.length>100||
     !Number.isSafeInteger(team.id)||team.id<=0)return null;
  teams.push(team.slug);
 }
 if(new Set(users).size!==users.length||new Set(teams).size!==teams.length)
  return null;
 return {
  requestedUsers:users.length,requestedTeams:teams.length,
  nonAuthorRequestedUsers:users.filter(login=>login!==AUTHOR).length,
  authorRequested:users.includes(AUTHOR),
  // Requests can be silently ignored/rejected and roles not authenticated.
  distinctSubmittedNonauthorExactHeadApprovalsVerified:0,
  independentSecurityRoleAuthenticated:false,
  independentBusinessRoleAuthenticated:false
 };
}
export async function fetchReadOnlyGithubGovernance(path,token,fetchImpl=fetch){
 if(!Object.values(ENDPOINTS).includes(path))
  throw Error('CL_UNREVIEWED_GITHUB_API_ROUTE');
 if(typeof token!=='string'||token.length<1||token.length>4096)
  return {status:'unavailable',data:null,httpStatus:null};
 const ac=new AbortController();
 const timeout=setTimeout(()=>ac.abort(),6500);
 try{
  const url=API+path;
  const res=await fetchImpl(url,{
   method:'GET',redirect:'error',signal:ac.signal,cache:'no-store',
   headers:{
    Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1CL-Codeowners-HOLD'
   }
  });
  const state=statusFromHttp(res.status);
  if(state!=='read')return {status:state,data:null,httpStatus:res.status};
  if(res.redirected||res.url!==url||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      res.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null,httpStatus:200};
  const len=res.headers?.get?.('content-length');
  if(len!==null&&len!==undefined&&
     (!/^\d+$/.test(len)||Number(len)>MAX_JSON))
   return {status:'invalid',data:null,httpStatus:200};
  const reader=res.body?.getReader();
  if(!reader)return {status:'invalid',data:null,httpStatus:200};
  const chunks=[];let size=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))return {status:'invalid',data:null,httpStatus:200};
   size+=value.byteLength;
   if(size>MAX_JSON)return {status:'invalid',data:null,httpStatus:200};
   chunks.push(Buffer.from(value));
  }
  return {status:'read',data:JSON.parse(Buffer.concat(chunks).toString('utf8')),
   httpStatus:200};
 }catch{
  return {status:'unavailable',data:null,httpStatus:null};
 }finally{clearTimeout(timeout);}
}
export function assessLiveCodeownerOnboarding({
  observations={},priorBy=null,environment={}
}={}){
 const anomalies=new Set(),endpointStatuses={};
 const records={},paths={
  codeownersGithub:CODEOWNER_PATHS[0],
  codeownersRoot:CODEOWNER_PATHS[1],
  codeownersDocs:CODEOWNER_PATHS[2]
 };
 for(const key of KEYS){
  const received=observations?.[key];
  const status=received?.status;
  endpointStatuses[key]=ALLOWED_STATUS.includes(status)?status:'invalid';
  if(status==='read'){
   const record=key==='requestedReviewers'?
    requestedSnapshot(received.data):
    validatedCodeowners(received.data,paths[key]);
   if(!record)endpointStatuses[key]='invalid';
   else records[key]=record;
  }
  if(endpointStatuses[key]!=='read')
   anomalies.add('CL_OFFICIAL_'+key.toUpperCase()+'_NOT_READ');
 }
 const order=CODEOWNER_KEYS;
 const selectedKey=order.find(k=>endpointStatuses[k]==='read')??null;
 const everyCodeownerPathAccessible=order.every(k=>
   endpointStatuses[k]==='read'||endpointStatuses[k]==='absent_or_hidden');
 const selectionKnown=everyCodeownerPathAccessible;
 const selected=selectionKnown&&selectedKey?records[selectedKey]:null;
 if(!selectionKnown)anomalies.add('CL_MAIN_CODEOWNERS_SOURCE_UNKNOWN');
 else if(!selectedKey)anomalies.add('CL_NO_CODEOWNERS_FILE_FOUND_ON_MAIN');
 else if(!selected?.syntacticallyHasAtLeastOneOwner)
  anomalies.add('CL_MAIN_CODEOWNERS_OWNER_MAPPING_EMPTY');
 if(selected?.invalidRows>0)anomalies.add('CL_CODEOWNERS_MALFORMED_ROWS');
 if(selected&&!selected.explicitlyProtectsCodeowners)
  anomalies.add('CL_CODEOWNERS_FILE_NOT_EXPLICITLY_OWNER_PROTECTED');
 const by=priorBy?.snapshotDerived;
 const reportsCorrect=priorBy?.kind==='LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD'&&
   SHA256.test(priorBy.sourceBundleSha256??'')&&
   priorBy.externallySigned===false&&priorBy.independentWorm===false&&
   priorBy.productionReleaseAuthorized===false&&
   priorBy.releaseDecision==='HOLD'&&
   by?.phase==='1BY'&&by?.kind==='READ_ONLY_GITHUB_GOVERNANCE_OBSERVATION'&&
   by?.observedPrDraftAndUnmerged===true&&
   by?.productionReleaseAuthorized===false&&by?.releaseDecision==='HOLD';
 if(!reportsCorrect)anomalies.add('CL_PRECEDING_LIVE_GITHUB_GOVERNANCE_REPORT_INVALID');
 const exactHead=SHA.test(by?.observedDevHeadSha??'')?
  by.observedDevHeadSha:null;
 if(!by?.eventSourceHeadAndBaseMatch||!by?.ciMergeMatchesPrApi)
  anomalies.add('CL_PR_HEAD_MERGE_OR_BASE_GITHUB_API_DRIFT');
 if(by?.reviews?.distinctLatestHeadApprovalCount!==undefined&&
    by.reviews.distinctLatestHeadApprovalCount<2)
  anomalies.add('CL_NO_GENUINE_TWO_APPROVAL_QUORUM');
 if(by?.observableRequiredBranchRulesPresent!==true)
  anomalies.add('CL_EFFECTIVE_REQUIRED_MAIN_BRANCH_RULES_NOT_VERIFIED');
 if(records.requestedReviewers?.authorRequested)
  anomalies.add('CL_PR_AUTHOR_REVIEW_REQUEST_NOT_INDEPENDENT');
 if(!records.requestedReviewers?.nonAuthorRequestedUsers&&
    !records.requestedReviewers?.requestedTeams)
  anomalies.add('CL_NO_INDEPENDENT_REVIEWER_REQUEST_VISIBLE');
 if(environment===null||typeof environment!=='object'||Array.isArray(environment)||
    environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_JOB!=='live-github-governance-hold'||
    environment.GITHUB_REPOSITORY!==REPO||
    environment.GITHUB_REF!=='refs/pull/1/merge'||
    !SHA.test(environment.GITHUB_SHA??'')||
    environment.GITHUB_EXPECTED_PR_HEAD_SHA!==exactHead)
  anomalies.add('CL_CURRENT_GITHUB_WORKLOAD_IDENTITY_INVALID');
 // This job observes a possibly missing/restricted API. It never grants
 // approval based on CODEOWNERS syntax, requested users, or a green CI.
 const blocked=['CL_PRECEDING_LIVE_GITHUB_GOVERNANCE_REPORT_INVALID',
  'CL_CURRENT_GITHUB_WORKLOAD_IDENTITY_INVALID'];
 const structurallyValid=!blocked.some(x=>anomalies.has(x));
 return Object.freeze({
  phase:'1CL',schemaVersion:1,
  kind:'ACTUAL_MAIN_CODEOWNERS_AND_REQUESTED_REVIEWERS_READONLY_HOLD',
  repo:REPO,baseBranch:'main',pr:1,prDraftMustRemain:true,
  observedDevHeadSha:exactHead,
  codeownersSelectionKnown:selectionKnown,
  selectedCodeownersLocation:selectedKey?paths[selectedKey]:null,
  observedCodeownersSummary:selected,
  requestedReviewerSummary:records.requestedReviewers??null,
  endpointStatuses,
  priorRealMainAppliedRuleCount:by?.rules?.observedRuleCount??null,
  priorRealHeadSubmissionCount:by?.reviews?.submittedReviewCount??null,
  priorRealLatestHeadNonauthorApprovalCount:
   by?.reviews?.distinctLatestHeadApprovalCount??null,
  officialPublicObservationStructurallyValid:structurallyValid,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  observedCodeownerTokenDoesNotProveWritePermission:true,
  independentSecurityAndBusinessRoleEnrollmentVerified:false,
  genuineTwoLatestHeadReviewsApproved:false,
  effectiveMainRulesAndNoBypassIndependentlyVerified:false,
  actualMainCodeownerPolicySafelyInstalledAndEnforced:false,
  externalCcaEmudhraMcaWormDrAuthorityVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function readExisting(path){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>1024*1024)
  throw Error('CL_MISSING_UNSAFE_GITHUB_CUSTODY_SOURCE');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CL only runs zero-input read-only --ci-hold');
 const priorBy=readExisting('phase1by-github-readonly-governance-hold.json');
 const observations={};
 for(const [key,path] of Object.entries(ENDPOINTS))
  observations[key]=await fetchReadOnlyGithubGovernance(path,
    process.env.GITHUB_READ_TOKEN);
 const decision=assessLiveCodeownerOnboarding({
  observations,priorBy,environment:process.env
 });
 const out={decision,observationHttpStatus:Object.fromEntries(
  Object.entries(observations).map(([key,value])=>[key,value.httpStatus])),
  sourceExternallySigned:false,reportIndependentlyWormPreserved:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'};
 writeFileSync('phase1cl-live-codeowners-reviewer-onboarding-hold.json',
  JSON.stringify(out,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(out,null,2));
 if(!decision.officialPublicObservationStructurallyValid||
    decision.productionReleaseAuthorized!==false||
    decision.productionReleaseBlocked!==true||
    decision.releaseDecision!=='HOLD')process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(error=>{
  console.error('CL source-bound read-only CODEOWNERS governance held:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
