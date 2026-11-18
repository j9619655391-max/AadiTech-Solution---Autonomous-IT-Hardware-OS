import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1CM: an operator-ready, *not installed* GitHub REST ruleset recipe,
// plus an optional private read-only GitHub permission check for TWO explicitly
// nominated people. This cannot authenticate corporate roles, deploy a rule,
// submit a review, change main, issue signing keys or authorize production.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const AUTHOR='j9619655391-max';
export const RULESET_PROPOSAL='docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json';
export const REQUIRED_JOBS=Object.freeze([
 'baseline','mysql-integration','production-runtime-scope',
 'build-input-provenance','review-vendor-intake-hold',
 'independent-evidence-hold','live-github-governance-hold',
 'source-merge-lineage-hold'
]);
export const EXPECTED_TYPES=Object.freeze([
 'deletion','non_fast_forward','pull_request','required_status_checks'
]);
const GH_LOGIN=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const PERMISSIONS=new Set(['write','maintain','admin']);
const KNOWN_PERMISSIONS=new Set(['read','triage','write','maintain','admin']);
const REPO_API='https://api.github.com/repos/'+REPO;
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const exactly=(x,keys)=>obj(x)&&same(Object.keys(x).sort(),[...keys].sort());
const sha256=x=>createHash('sha256').update(x).digest('hex');
export function assessProposedMainRuleset(payload){
 const problems=new Set();
 if(!obj(payload)){
  problems.add('CM_PROPOSAL_NOT_A_JSON_OBJECT');
  return finish(problems,null);
 }
 if(!exactly(payload,[
   'name','target','enforcement','bypass_actors','conditions','rules'
  ])||typeof payload.name!=='string'||
    payload.name!=='AadiTech main protected two-person review - PROPOSED NOT INSTALLED'||
    payload.target!=='branch'||payload.enforcement!=='active'||
    !Array.isArray(payload.bypass_actors)||payload.bypass_actors.length!==0)
  problems.add('CM_RULESET_IDENTITY_TARGET_ENFORCEMENT_OR_BYPASS_DRIFT');
 if(!exactly(payload.conditions,['ref_name'])||
    !exactly(payload.conditions?.ref_name,['include','exclude'])||
    !same(payload.conditions?.ref_name?.include,['refs/heads/main'])||
    !same(payload.conditions?.ref_name?.exclude,[]))
  problems.add('CM_MAIN_ONLY_REF_MATCH_CHANGED');
 const rules=payload.rules;
 if(!Array.isArray(rules)||rules.length!==EXPECTED_TYPES.length||
    !same(rules.map(x=>x?.type),EXPECTED_TYPES))
  problems.add('CM_REQUIRED_RULE_TYPES_OR_ORDER_CHANGED');
 const [del,force,pr,checks]=Array.isArray(rules)?rules:[];
 if(!exactly(del,['type'])||!exactly(force,['type']))
  problems.add('CM_DELETE_OR_FORCE_PUSH_RULE_MALFORMED');
 const p=pr?.parameters;
 if(!exactly(pr,['type','parameters'])||
    !exactly(p,[
      'allowed_merge_methods','dismiss_stale_reviews_on_push',
      'require_code_owner_review','require_last_push_approval',
      'required_approving_review_count','required_review_thread_resolution'
    ])||
    !same(p?.allowed_merge_methods,['merge','squash','rebase'])||
    p?.dismiss_stale_reviews_on_push!==true||
    p?.require_code_owner_review!==true||
    p?.require_last_push_approval!==true||
    p?.required_approving_review_count!==2||
    p?.required_review_thread_resolution!==true)
  problems.add('CM_TWO_REVIEWER_CODEOWNER_LATEST_PUSH_GATE_WEAKENED');
 const c=checks?.parameters;
 if(!exactly(checks,['type','parameters'])||
    !exactly(c,['do_not_enforce_on_create',
      'strict_required_status_checks_policy','required_status_checks'])||
    c?.do_not_enforce_on_create!==false||
    c?.strict_required_status_checks_policy!==true||
    !Array.isArray(c?.required_status_checks)||
    c.required_status_checks.length!==REQUIRED_JOBS.length||
    c.required_status_checks.some((row,i)=>
      !exactly(row,['context'])||row?.context!==REQUIRED_JOBS[i]))
  problems.add('CM_EIGHT_EXACT_HOSTED_CHECKS_OR_STRICT_POLICY_WEAKENED');
 return finish(problems,payload);
}
function finish(problems,payload){
 return Object.freeze({
  phase:'1CM',schemaVersion:1,
  kind:'UNINSTALLED_OFFICIAL_GITHUB_MAIN_RULESET_ADMIN_HANDOFF_HOLD',
  proposedRulesetName:payload?.name??null,
  proposedTarget:payload?.conditions?.ref_name?.include??null,
  requiredCheckCount:REQUIRED_JOBS.length,
  unreviewedOrWeakenedRulesetRejected:problems.size>0,
  localProposedRestPayloadStructurallySafe:problems.size===0,
  proposalContentSha256:payload&&obj(payload)?
   sha256(JSON.stringify(payload)):null,
  anomalyCodes:[...problems].sort(),
  actualMainRulesetInstalledAndEnforced:false,
  actualNoBypassAdministratorBehaviorVerified:false,
  actualBaseMainCodeownersInstalledAndOwnerAccessVerified:false,
  latestHeadSecurityAndBusinessRoleApprovalsAuthenticated:false,
  signedCIWorkloadProvenanceIndependentlyVerified:false,
  realEmudhraCcaMcaAndWormAuthorityAuthenticated:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function validLogin(value){
 return typeof value==='string'&&GH_LOGIN.test(value)&&
   value.toLowerCase()!==AUTHOR.toLowerCase();
}
export function validateReviewerNominees(securityLogin,businessLogin){
 const problems=[];
 if(!validLogin(securityLogin))problems.push('CM_SECURITY_NOMINEE_INVALID_OR_SELF');
 if(!validLogin(businessLogin))problems.push('CM_BUSINESS_NOMINEE_INVALID_OR_SELF');
 if(validLogin(securityLogin)&&validLogin(businessLogin)&&
    securityLogin.toLowerCase()===businessLogin.toLowerCase())
  problems.push('CM_NOMINEES_NOT_DISTINCT');
 return Object.freeze({valid:problems.length===0,problems});
}
export function proposedCodeowners(securityLogin,businessLogin){
 const review=validateReviewerNominees(securityLogin,businessLogin);
 if(!review.valid)throw Error(review.problems.join(';'));
 // GitHub CODEOWNERS with multiple names does NOT require each name to
 // approve; two total approvals also do not prove both named roles signed.
 // Explicit Security+Business role acceptance remains an external control.
 const owners='@'+securityLogin+' @'+businessLogin;
 const patterns=[
  '*', '/.github/CODEOWNERS','/.github/workflows/',
  '/docs/security/', '/server/security/', '/scripts/',
  '/tests/'
 ];
 const content='# PROPOSAL ONLY: verify two real GitHub write-capable reviewers;\n'+
  '# install on the PR BASE branch main only after authorized admin approval.\n'+
  patterns.map(pattern=>pattern+' '+owners).join('\n')+'\n';
 return Object.freeze({
  content,sha256:sha256(content),
  rolePermissionsVerified:false,
  securityAndBusinessRoleMandatesIndependentlyVerified:false,
  actualMainBaseBranchCodeownersInstalled:false,
  productionReleaseAuthorized:false
 });
}
export function assessActualGithubPermissions({
 securityLogin,businessLogin,securityResponse,businessResponse
}={}){
 const nomination=validateReviewerNominees(securityLogin,businessLogin);
 const problems=[...nomination.problems];
 const grants={};
 for(const [role,resp,login] of [
  ['security',securityResponse,securityLogin],
  ['business',businessResponse,businessLogin]
 ]){
  const status=resp?.status;
  const permission=status==='read'&&
    obj(resp.data)&&
    resp.data.user?.login?.toLowerCase()===login?.toLowerCase()&&
    typeof resp.data.permission==='string'?
    resp.data.permission:null;
  if(!permission||!PERMISSIONS.has(permission))
   problems.push('CM_'+role.toUpperCase()+'_REAL_WRITE_PERMISSION_NOT_VERIFIED');
  grants[role]={sourceStatus:status??'unavailable',
   technicalRepoWritePermissionSeen:PERMISSIONS.has(permission),
   corporateMandateIndependentlyVerified:false};
 }
 return Object.freeze({
  nominationSyntaxAndIndependenceValid:nomination.valid,
  permissions:grants,
  technicalRepoPermissionPreconditionMet:problems.length===0,
  anomalies:problems.sort(),
  bothRolesIndependentlyAuthenticated:false,
  latestHeadGithubApprovalsAuthenticated:false,
  effectiveMainRulesetIndependentlyVerified:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 });
}
export async function readActualGithubPermission(login,token,fetchImpl=fetch){
 if(!validLogin(login))throw Error('CM_INVALID_OR_AUTHOR_LOGIN');
 if(typeof token!=='string'||token.length<1||token.length>4096)
  return {status:'unavailable',data:null};
 const path='/collaborators/'+encodeURIComponent(login)+'/permission';
 const url=REPO_API+path;
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),6500);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:controller.signal,
   headers:{
    Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1CM-Reviewer-ReadOnly-HOLD'
   }
  });
  if(response.status!==200)
   return {status:response.status===403?'access_denied':
    response.status===404?'not_found_or_hidden':'unavailable',data:null};
  if(response.url!==url||response.redirected||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      response.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null};
  const len=response.headers?.get?.('content-length');
  if(len!==null&&len!==undefined&&(!/^\d+$/.test(len)||Number(len)>8192))
   return {status:'invalid',data:null};
  const reader=response.body?.getReader();
  if(!reader)return {status:'invalid',data:null};
  let total=0;const chunks=[];
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))return {status:'invalid',data:null};
   total+=value.byteLength;
   if(total>8192)return {status:'invalid',data:null};
   chunks.push(Buffer.from(value));
  }
  const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if(!obj(raw)||!obj(raw.user)||
     raw.user.login?.toLowerCase()!==login.toLowerCase()||
     typeof raw.permission!=='string'||!KNOWN_PERMISSIONS.has(raw.permission))
   return {status:'invalid',data:null};
  return {status:'read',data:{
   user:{login:raw.user.login},permission:raw.permission
  }};
 }catch{
  // Avoid leaking network errors or tokens in logs.
  return {status:'unavailable',data:null};
 }finally{clearTimeout(timer);}
}
function readProposal(){
 const st=lstatSync(RULESET_PROPOSAL);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>65536)
  throw Error('CM_REVIEWED_PROPOSAL_SOURCE_MISSING_UNSAFE_OR_OVERSIZE');
 return JSON.parse(readFileSync(RULESET_PROPOSAL,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--ci-hold'){
  const assessment=assessProposedMainRuleset(readProposal());
  const report={
   ...assessment,
   noReviewerNomineesCollectedInRepository:true,
   noExternalPermissionsQueriedInCi:true,
   neitherAdminMutationNorPullRequestReviewSubmitted:true,
   actualMainRulesetInstalledAndEnforced:false,
   productionReleaseAuthorized:false,
   productionReleaseBlocked:true,
   releaseDecision:'HOLD'
  };
  writeFileSync('phase1cm-uninstalled-main-ruleset-admin-handoff-hold.json',
   JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
  console.log(JSON.stringify(report,null,2));
  if(!assessment.localProposedRestPayloadStructurallySafe)process.exitCode=1;
  return;
 }
 if(args.length===3&&args[0]==='--prepare-codeowners'){
  const plan=assessProposedMainRuleset(readProposal());
  if(!plan.localProposedRestPayloadStructurallySafe)
   throw Error('CM_ADMIN_RULESET_PROPOSAL_INVALID');
  const proposal=proposedCodeowners(args[1],args[2]);
  console.log(JSON.stringify({kind:'UNINSTALLED_HUMAN_REVIEW_ONLY',
   proposedCodeowners:proposal,
   requiredRulesetProposalPath:RULESET_PROPOSAL,
   actualCodeownersOrRulesetInstalled:false,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'},null,2));
  return;
 }
 if(args.length===3&&args[0]==='--verify-reviewer-permissions'){
  const [securityLogin,businessLogin]=args.slice(1);
  const candidates=validateReviewerNominees(securityLogin,businessLogin);
  if(!candidates.valid)throw Error(candidates.problems.join(';'));
  // A token from an approved operator secrets manager, never CLI/chat/git.
  const token=process.env.GITHUB_READ_TOKEN;
  const [securityResponse,businessResponse]=await Promise.all([
   readActualGithubPermission(securityLogin,token),
   readActualGithubPermission(businessLogin,token)
  ]);
  const result=assessActualGithubPermissions({
   securityLogin,businessLogin,securityResponse,businessResponse
  });
  console.log(JSON.stringify(result,null,2));
  if(!result.technicalRepoPermissionPreconditionMet)process.exitCode=1;
  return;
 }
 throw Error('CM_ONLY_CI_HOLD_OR_EXPLICIT_READONLY_TWO_NOMINEE_OPERATOR_COMMANDS');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('CM ruleset/reviewer admin handoff denied:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 });
