import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,AUTHOR,REQUIRED_JOBS,GITHUB_ACTIONS_INTEGRATION_ID,
 assessProposedMainRuleset,validateReviewerNominees,proposedCodeowners
} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {collectLiveReviewerEvidence}
 from './phase1co-live-exact-head-reviewer-quorum.mjs';
import {collectActualRulesets}
 from './phase1cn-ruleset-bypass-reconciliation.mjs';
import {fetchReadOnlyGithubGovernance,ENDPOINTS}
 from './phase1cl-live-codeowners-reviewer-onboarding.mjs';
import {readOfficialCheckSource}
 from './phase1cp-github-actions-check-app-source.mjs';
import {verifyDualEventReceipt}
 from './phase1ct-dual-event-postrun-governance.mjs';

// Phase 1CU: operator-only independent governance HANDOFF OBSERVATION.
// This aggregates actual GitHub REST read-only checks, never authenticates
// a human corporate role or grants CI/provider/staging/production release.
// Actual main ruleset bypass_actors must be explicitly visible and [].
// GitHub read-only callers often CANNOT see them; unknown means HOLD.
const API='https://api.github.com/repos/'+REPO;
const MAIN='/git/ref/heads/main';
const CODEOWNERS='.github/CODEOWNERS';
const MAX_BYTES=131072;
const SHA=/^[a-f0-9]{40}$/;
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sorted=a=>Array.isArray(a)?[...a].sort():null;
const id=x=>typeof x==='string'&&/^[1-9]\d{0,15}$/.test(x)&&
 Number.isSafeInteger(Number(x));
const sha256=x=>createHash('sha256').update(x).digest('hex');
const stablePr=p=>obj(p)&&p.number===1&&p.state==='open'&&
 p.draft===true&&p.merged===false&&p.user?.login===AUTHOR&&
 p.head?.ref==='chore/phase0-foundation-20261106'&&
 p.base?.ref==='main'&&p.head?.repo?.full_name===REPO&&
 p.base?.repo?.full_name===REPO&&
 SHA.test(p.head?.sha??'')&&SHA.test(p.base?.sha??'')&&
 SHA.test(p.merge_commit_sha??'')&&
 typeof p.updated_at==='string'&&Number.isFinite(Date.parse(p.updated_at));

// No unreviewed URL: this reader accepts precisely one official main ref.
// Existing CP/CL/CN/CO readers retain their own fixed allowlists.
export async function readMainRefOnly(token,fetchImpl=fetch){
 if(typeof token!=='string'||!token||token.length>4096)
  return {status:'missing_token',data:null};
 const url=API+MAIN;
 const ac=new AbortController(),timeout=setTimeout(()=>ac.abort(),6500);
 try{
  const res=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',signal:ac.signal,
   headers:{Accept:'application/vnd.github+json',
    Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'AadiTech-Phase1CU-MainRef-ReadOnly-HOLD'}
  });
  if(res.status!==200)return {status:[401,403].includes(res.status)?
   'access_denied':res.status===404?'not_found_or_hidden':'unavailable',data:null};
  if(res.redirected||res.url!==url||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
     res.headers?.get?.('content-type')??''))
   return {status:'invalid',data:null};
  const sizeHeader=res.headers?.get?.('content-length');
  if(sizeHeader!==null&&sizeHeader!==undefined&&
     (!/^\d+$/.test(sizeHeader)||Number(sizeHeader)>MAX_BYTES))
   return {status:'invalid',data:null};
  const reader=res.body?.getReader();
  if(!reader)return {status:'invalid',data:null};
  const chunks=[];let size=0;
  while(true){
   const next=await reader.read();
   if(next.done)break;
   if(!(next.value instanceof Uint8Array))return {status:'invalid',data:null};
   size+=next.value.byteLength;
   if(size>MAX_BYTES)return {status:'invalid',data:null};
   chunks.push(Buffer.from(next.value));
  }
  const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  return {status:'read',data:raw};
 }catch{return {status:'unavailable',data:null};}
 finally{clearTimeout(timeout);}
}
function sameMainRef(data,expected){
 return obj(data)&&data.ref==='refs/heads/main'&&
  data.object?.type==='commit'&&data.object.sha===expected&&
  data.object.url===API+'/git/commits/'+expected;
}
export function assessExactAppliedMainRuleset(observations,proposal){
 const errors=new Set();
 const cm=assessProposedMainRuleset(proposal);
 if(!cm.localProposedRestPayloadStructurallySafe)
  errors.add('CU_LOCAL_PROPOSED_MAIN_RULESET_UNREVIEWED');
 const list=observations?.listStatus==='read'&&
  observations.listingComplete===true&&Array.isArray(observations.listed)?
  observations.listed:null;
 if(!list||list.length===0)errors.add('CU_ACTUAL_MAIN_RULESET_LIST_MISSING_OR_EMPTY');
 const ids=new Set(),matches=[];
 for(const x of list??[]){
  if(!Number.isSafeInteger(x?.id)||x.id<1||ids.has(x.id)){
   errors.add('CU_RULESET_LIST_ID_DUPLICATE_OR_INVALID');continue;
  }
  ids.add(x.id);
  const r=observations.details?.[String(x.id)];
  if(observations.detailStatus?.[String(x.id)]!=='read'||
     !obj(r)||r.id!==x.id||r.name!==x.name||
     r.target!==x.target||r.enforcement!==x.enforcement){
   errors.add('CU_RULESET_DETAIL_MISSING_OR_LIST_DRIFT');continue;
  }
  if(r.target!=='branch'||r.enforcement!=='active')continue;
  // Only an ACTIVE rule targeting precisely main can satisfy the handoff.
  if(!eq(r.conditions?.ref_name?.include,['refs/heads/main'])||
     !eq(r.conditions?.ref_name?.exclude,[]))continue;
  if(r.name!==proposal?.name)continue;
  matches.push(r);
 }
 if(matches.length!==1)errors.add('CU_EXACT_ONE_ACTIVE_MAIN_RULESET_NOT_OBSERVED');
 const actual=matches.length===1?matches[0]:null;
 const bypass=actual&&Array.isArray(actual.bypass_actors)&&
  actual.bypass_actors.length===0;
 if(!bypass)errors.add('CU_MAIN_RULESET_BYPASS_ACTORS_HIDDEN_OR_NONEMPTY');
 const rules=Array.isArray(actual?.rules)?actual.rules:null;
 if(!rules||rules.length!==4||
    new Set(rules.map(r=>r?.type)).size!==4||
    !eq(sorted(rules.map(r=>r?.type)),
      sorted(proposal?.rules?.map(r=>r?.type))))
  errors.add('CU_MAIN_RULESET_REQUIRED_RULES_MISSING_OR_EXTRA');
 const get=type=>rules?.find(x=>x?.type===type);
 const original=type=>proposal?.rules?.find(x=>x?.type===type);
 const pr=get('pull_request')?.parameters;
 const approved=original('pull_request')?.parameters;
 if(!obj(pr)||!obj(approved)||
    !eq(sorted(pr.allowed_merge_methods),sorted(approved.allowed_merge_methods))||
    !['dismiss_stale_reviews_on_push','require_code_owner_review',
      'require_last_push_approval','required_approving_review_count',
      'required_review_thread_resolution'].every(k=>pr[k]===approved[k]))
  errors.add('CU_MAIN_TWO_PERSON_LATEST_PUSH_CODEOWNER_GATE_DRIFT');
 const checks=get('required_status_checks')?.parameters;
 const expected=original('required_status_checks')?.parameters;
 const contexts=checks?.required_status_checks;
 if(!obj(checks)||!obj(expected)||
    checks.strict_required_status_checks_policy!==true||
    checks.do_not_enforce_on_create!==false||
    !Array.isArray(contexts)||contexts.length!==REQUIRED_JOBS.length||
    new Set(contexts.map(c=>c?.context)).size!==REQUIRED_JOBS.length||
    contexts.some(c=>!obj(c)||c.integration_id!==GITHUB_ACTIONS_INTEGRATION_ID||
      !REQUIRED_JOBS.includes(c.context)))
  errors.add('CU_EIGHT_MAIN_STATUS_CONTEXTS_OR_GITHUB_APP_PIN_DRIFT');
 // Any unread details or incomplete pages are unknowable, not acceptable.
 if(list&&list.length!==Object.keys(observations.details??{}).length)
  errors.add('CU_RULESET_INVENTORY_NOT_FULLY_READ');
 return Object.freeze({
  exactActiveMainRulesetWithNoBypassTechnicallyObserved:errors.size===0,
  activeExactMainRuleCount:matches.length,
  bypassActorsExplicitEmpty:bypass===true,
  appliedRuleCount:rules?.length??null,
  sourceListComplete:list!==null,
  anomalyCodes:[...errors].sort()
 });
}
export function assessNominatedMainCodeowners(record,securityLogin,businessLogin){
 const errors=new Set();
 const valid=validateReviewerNominees(securityLogin,businessLogin);
 if(!valid.valid)errors.add('CU_INVALID_OR_AUTHOR_REVIEWER_NOMINATIONS');
 const raw=record?.status==='read'?record.data:null;
 if(!obj(raw)||raw.type!=='file'||raw.path!==CODEOWNERS||
    raw.encoding!=='base64'||!SHA.test(raw.sha??'')||
    typeof raw.content!=='string'||raw.size<=0||raw.size>65536)
  errors.add('CU_ACTUAL_MAIN_CODEOWNERS_UNAVAILABLE_OR_UNTRUSTED');
 const encoded=typeof raw?.content==='string'?raw.content.replace(/\s/g,''):'';
 if(!encoded||!/^([a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?$/.test(encoded))
  errors.add('CU_MAIN_CODEOWNERS_BASE64_UNTRUSTED');
 let verifiedBlob=false,exactOwners=false;
 if(errors.size===0){
  const bytes=Buffer.from(encoded,'base64');
  const body=bytes.toString('utf8');
  const gitBlob=createHash('sha1').update(
   Buffer.concat([Buffer.from('blob '+bytes.length+'\0'),bytes])).digest('hex');
  verifiedBlob=bytes.length===raw.size&&bytes.toString('base64')===encoded&&
   Buffer.from(body,'utf8').equals(bytes)&&!body.includes('\0')&&
   gitBlob===raw.sha;
  if(verifiedBlob){
   const requested=proposedCodeowners(securityLogin,businessLogin);
   exactOwners=body===requested.content;
  }
 }
 if(!verifiedBlob)errors.add('CU_MAIN_CODEOWNERS_CONTENT_BLOB_NOT_AUTHENTICATED');
 if(!exactOwners)errors.add('CU_NOMINATED_TWO_ROLE_CODEOWNERS_NOT_EXACTLY_INSTALLED');
 return Object.freeze({
  actualBaseMainCodeownersExactNominatedBytesTechnicallyObserved:errors.size===0,
  gitBlobShaMatchesApi:verifiedBlob,
  nominatedPairRequiredOnAllProposedProtectedPaths:exactOwners,
  anomalies:[...errors].sort()
 });
}
export function assessIndependentGovernanceHandoff({
  securityLogin,businessLogin,prBefore=null,prAfter=null,
  mainBefore=null,mainAfter=null,
  mainBeforeStatus='unavailable',mainAfterStatus='unavailable',
  ct=null,co=null,rulesets=null,codeowners=null,proposal=null
}={}){
 const errors=new Set();
 const valid=validateReviewerNominees(securityLogin,businessLogin);
 if(!valid.valid)errors.add('CU_TWO_NOMINATED_NONAUTHOR_ACCOUNTS_INVALID');
 const stable=stablePr(prBefore)&&stablePr(prAfter)&&
  prBefore.head.sha===prAfter.head.sha&&
  prBefore.base.sha===prAfter.base.sha&&
  prBefore.merge_commit_sha===prAfter.merge_commit_sha&&
  prBefore.updated_at===prAfter.updated_at;
 if(!stable)errors.add('CU_OUTER_PR_RACE_OR_DRAFT_IDENTITY_INVALID');
 const head=stable?prBefore.head.sha:null,base=stable?prBefore.base.sha:null;
 const main=base!==null&&mainBeforeStatus==='read'&&
  mainAfterStatus==='read'&&sameMainRef(mainBefore,base)&&
  sameMainRef(mainAfter,base);
 if(!main)errors.add('CU_ACTUAL_BASE_MAIN_REF_NOT_STABLE');
 const dual=ct?.phase==='1CT'&&
  ct.completedTwoEventTechnicalReceiptVerified===true&&
  ct.officialPrUnchangedAcrossAllReads===true&&
  ct.sourceBranchAndPrHeadMatch===true&&
  ct.sourceHeadSha===head&&ct.baseSha===base&&
  ct.productionReleaseAuthorized===false&&ct.releaseDecision==='HOLD'&&
  Number.isSafeInteger(ct.pushRunId)&&ct.pushRunId>0&&
  Number.isSafeInteger(ct.prRunId)&&ct.prRunId>0&&
  ct.pushRunId!==ct.prRunId;
 if(!dual)errors.add('CU_COMPLETED_EXACT_HEAD_PUSH_PR_EVIDENCE_NOT_VERIFIED');
 const reviewers=co?.phase==='1CO'&&
  co.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved===true&&
  co.prReadBeforeAndAfterStable===true&&
  co.actualGithubReviewPaginationComplete===true&&
  co.securityNominatedAccountActuallyApprovedCurrentHead===true&&
  co.businessNominatedAccountActuallyApprovedCurrentHead===true&&
  co.actualNominatedReviewerWritePermissionsObserved===true&&
  co.currentDevHead===head&&co.productionReleaseAuthorized===false&&
  co.releaseDecision==='HOLD';
 if(!reviewers)errors.add('CU_TWO_DISTINCT_NOMINATED_LATEST_HEAD_APPROVALS_NOT_VERIFIED');
 const applied=assessExactAppliedMainRuleset(rulesets,proposal);
 for(const anomaly of applied.anomalyCodes)errors.add(anomaly);
 const owners=assessNominatedMainCodeowners(
  codeowners,securityLogin,businessLogin);
 for(const anomaly of owners.anomalies)errors.add(anomaly);
 const snapshot={
  currentHead:head,verifiedMainBaseSha:main?base:null,
  pushRunId:dual?ct.pushRunId:null,prRunId:dual?ct.prRunId:null,
  appliedExactMainRuleCount:applied.activeExactMainRuleCount,
  nominatedGithubApprovalsTechnicallyObserved:reviewers,
  installedExactCodeownersTechnicallyObserved:
   owners.actualBaseMainCodeownersExactNominatedBytesTechnicallyObserved
 };
 const technicallyObserved=errors.size===0;
 return Object.freeze({
  phase:'1CU',schemaVersion:1,
  kind:'OPERATOR_ONLY_CROSS_SOURCE_REVIEWER_MAIN_PROTECTION_HANDOFF_HOLD',
  repo:REPO,
  currentDevHeadSha:head,
  verifiedMainBaseSha:main?base:null,
  pushRunId:dual?ct.pushRunId:null,prRunId:dual?ct.prRunId:null,
  actualMainBaseStableAcrossAllSources:main,
  exactHeadPushAndPrTechnicalCiReceiptsMatched:dual,
  distinctNominatedLatestHeadTechnicalGithubApprovalsMatched:reviewers,
  exactActiveMainRulesAndNoBypassFieldsObservable:
   applied.exactActiveMainRulesetWithNoBypassTechnicallyObserved,
  installedMainCodeownersExactNominatedBytesMatched:
   owners.actualBaseMainCodeownersExactNominatedBytesTechnicallyObserved,
  technicalGovernanceHandoffPreconditionsObserved:technicallyObserved,
  sourceReviewCodes:Object.freeze([...errors].sort()),
  localUnsignedObservationSha256:sha256(JSON.stringify(snapshot)),
  reviewerLoginNamesOrTokensPersistedInReport:false,
  independentlyMandatedCorporateSecurityBusinessRolesAuthenticated:false,
  independentCryptoSignatureOnReviewerMandatesVerified:false,
  externalCIWorkloadOidcSlsaSignatureVerified:false,
  externalMcaEmudhraCcaWormDrStagingAcceptanceVerified:false,
  independentProductionApprovalGranted:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD'
 });
}
export async function verifyIndependentGovernanceHandoff({
 securityLogin,businessLogin,pushId,prId,token,
 fetchImpl=fetch,proposal
}={}){
 const names=validateReviewerNominees(securityLogin,businessLogin);
 if(!names.valid)throw Error('CU_INVALID_GENUINE_TWO_REVIEWER_NOMINATIONS');
 if(!id(String(pushId))||!id(String(prId))||String(pushId)===String(prId))
  throw Error('CU_INVALID_DISTINCT_FINISHED_RUN_IDS');
 const outerBefore=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 const mainBefore=await readMainRefOnly(token,fetchImpl);
 const ct=await verifyDualEventReceipt({
  pushId,prId,token,fetchImpl,proposal
 });
 const co=await collectLiveReviewerEvidence({
  token,securityLogin,businessLogin,fetchImpl
 });
 const rulesets=await collectActualRulesets({token,fetchImpl});
 const codeowners=await fetchReadOnlyGithubGovernance(
  ENDPOINTS.codeownersGithub,token,fetchImpl);
 const mainAfter=await readMainRefOnly(token,fetchImpl);
 const outerAfter=await readOfficialCheckSource('/pulls/1',token,fetchImpl);
 return assessIndependentGovernanceHandoff({
  securityLogin,businessLogin,
  prBefore:outerBefore.status==='read'?outerBefore.data:null,
  prAfter:outerAfter.status==='read'?outerAfter.data:null,
  mainBefore:mainBefore.data,mainAfter:mainAfter.data,
  mainBeforeStatus:mainBefore.status,mainAfterStatus:mainAfter.status,
  ct,co,rulesets,codeowners,proposal
 });
}
function localProposal(){
 const path='docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json';
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>65536)
  throw Error('CU_REVIEWED_RULESET_PROPOSAL_MISSING_OR_UNSAFE');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(args.length!==5||args[0]!=='--verify-handoff'||
  !id(args[1])||!id(args[2])||args[1]===args[2])
  throw Error('CU_ONLY_--verify-handoff_PUSH_RUN_ID_PR_RUN_ID_SECURITY_LOGIN_BUSINESS_LOGIN');
 if(process.env.GITHUB_ACTIONS==='true')
  throw Error('CU_NAMED_OPERATOR_REVIEWS_FORBIDDEN_IN_GITHUB_ACTIONS');
 const result=await verifyIndependentGovernanceHandoff({
  pushId:Number(args[1]),prId:Number(args[2]),
  securityLogin:args[3],businessLogin:args[4],
  token:process.env.GITHUB_READ_TOKEN,proposal:localProposal()
 });
 console.log(JSON.stringify(result,null,2));
 if(!result.technicalGovernanceHandoffPreconditionsObserved)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(error=>{
  console.error('CU read-only independent governance handoff held:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
}
