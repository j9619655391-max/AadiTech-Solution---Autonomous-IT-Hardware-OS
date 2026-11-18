import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,AUTHOR,validateReviewerNominees,readActualGithubPermission,
 assessActualGithubPermissions
} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {readOfficialGithubEndpoint}
 from './phase1by-github-governance-observer.mjs';

// Phase 1CO: a real, optional human-initiated, read-only verification
// of TWO explicitly authorized nonauthor reviewer usernames against
// GitHub PR #1's LATEST source head, actual review decisions and actual
// repository collaborator permissions. NO usernames/corporate role claims
// are stored in CI. NO reviewer requests, admin actions, signatures or GO.
const ROOT='/repos/'+REPO;
const PR_PATH=ROOT+'/pulls/1';
const REVIEW_PATH=PR_PATH+'/reviews?per_page=100';
const SHA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const OBJ=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const VALID_STATES=new Set([
 'APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED','PENDING'
]);
const exactDate=x=>typeof x==='string'&&
 /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(x)&&
 Number.isFinite(Date.parse(x));
const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
export const MAX_REVIEW_PAGES=3;

export function evaluateLatestSubmittedReviews(reviews,head,author){
 const errors=new Set();
 if(!Array.isArray(reviews)||reviews.length>300||
    !SHA.test(head??'')||typeof author!=='string'){
  errors.add('CO_UNTRUSTED_OR_UNBOUNDED_SUBMITTED_REVIEWS');
  return {valid:false,byLogin:{},counts:{submitted:null,currentHeadApprovals:0},
   anomalies:[...errors]};
 }
 const latest=new Map(),seenIds=new Set();
 let submitted=0,irrelevant=0;
 for(const row of reviews){
  // GitHub lists pending draft reviews without submitted_at;
  // they are not permission to deploy, and never supersede a real
  // submitted approved review. Review state DROPPED/UNKNOWN fails closed.
  const login=row?.user?.login;
  if(!OBJ(row)||!Number.isSafeInteger(row.id)||row.id<=0||
     !OBJ(row.user)||typeof login!=='string'||
     !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(login)||
     !VALID_STATES.has(row.state)){
   errors.add('CO_MALFORMED_OR_UNRECOGNIZED_REVIEW_RECORD');continue;
  }
  if(seenIds.has(row.id)){
   errors.add('CO_DUPLICATE_GITHUB_REVIEW_ID');continue;
  }
  seenIds.add(row.id);
  if(row.state==='PENDING'){
   if(row.submitted_at!==null&&row.submitted_at!==undefined)
    errors.add('CO_PENDING_REVIEW_HAS_SUBMISSION_TIMESTAMP');
   irrelevant++;continue;
  }
  if(!exactDate(row.submitted_at)||!SHA.test(row.commit_id??'')){
   errors.add('CO_SUBMITTED_REVIEW_TIMESTAMP_OR_COMMIT_INVALID');continue;
  }
  submitted++;
  const lower=login.toLowerCase();
  const old=latest.get(lower);
  if(!old||Date.parse(old.submitted_at)<Date.parse(row.submitted_at)||
     (old.submitted_at===row.submitted_at&&old.id<row.id))
   latest.set(lower,row);
 }
 let approvals=0;const byLogin={};
 for(const [lower,row] of latest){
  const accepted=lower!==author.toLowerCase()&&row.state==='APPROVED'&&
   row.commit_id===head;
  if(accepted)approvals++;
  byLogin[lower]={
   lastReviewId:row.id,lastState:row.state,
   latestSubmittedReviewTargetsCurrentHead:row.commit_id===head,
   currentHeadApprovedByThisAccount:accepted
  };
 }
 return {
  valid:errors.size===0,
  byLogin,
  counts:{submitted,currentHeadApprovals:approvals,nonSubmittedPending:irrelevant},
  anomalies:[...errors].sort()
 };
}
function prIdentity(pr){
 return OBJ(pr)&&pr.number===1&&pr.state==='open'&&
  pr.draft===true&&pr.merged===false&&
  pr.user?.login===AUTHOR&&
  pr.head?.ref==='chore/phase0-foundation-20261106'&&
  pr.base?.ref==='main'&&
  pr.head?.repo?.full_name===REPO&&pr.base?.repo?.full_name===REPO&&
  SHA.test(pr.head?.sha??'')&&SHA.test(pr.base?.sha??'');
}
export function assessRealNonauthorApprovalQuorum({
  securityLogin,businessLogin,prBefore,prAfter,
  reviews,reviewPaginationComplete=false,
  securityPermission,businessPermission
}={}){
 const errors=new Set();
 const candidates=validateReviewerNominees(securityLogin,businessLogin);
 if(!candidates.valid)errors.add('CO_REVIEWER_IDENTITY_NOT_TWO_DISTINCT_NONAUTHORS');
 const identityCorrect=prIdentity(prBefore)&&prIdentity(prAfter);
 if(!identityCorrect)errors.add('CO_PR_ACTUAL_BASE_AUTHOR_OR_DRAFT_IDENTITY_INVALID');
 const stable=identityCorrect&&prBefore.head.sha===prAfter.head.sha&&
  prBefore.base.sha===prAfter.base.sha&&
  prBefore.merge_commit_sha===prAfter.merge_commit_sha&&
  prBefore.updated_at===prAfter.updated_at;
 if(!stable)errors.add('CO_PR_CHANGED_DURING_ACTUAL_REVIEW_READ');
 if(reviewPaginationComplete!==true)
  errors.add('CO_GITHUB_REVIEW_PAGINATION_INCOMPLETE');
 const checked=evaluateLatestSubmittedReviews(
  reviews,identityCorrect?prBefore.head.sha:null,AUTHOR);
 for(const e of checked.anomalies)errors.add(e);
 const technical=assessActualGithubPermissions({
  securityLogin,businessLogin,
  securityResponse:securityPermission,businessResponse:businessPermission
 });
 if(!technical.technicalRepoPermissionPreconditionMet)
  errors.add('CO_ACTUAL_REVIEWER_REPOSITORY_WRITE_PERMISSION_NOT_VERIFIED');
 const currentHead=identityCorrect?prBefore.head.sha:null;
 const security=typeof securityLogin==='string'?
  checked.byLogin[securityLogin.toLowerCase()]:null;
 const business=typeof businessLogin==='string'?
  checked.byLogin[businessLogin.toLowerCase()]:null;
 if(!security?.currentHeadApprovedByThisAccount)
  errors.add('CO_SECURITY_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
 if(!business?.currentHeadApprovedByThisAccount)
  errors.add('CO_BUSINESS_NOMINEE_NOT_CURRENT_HEAD_APPROVED');
 const technicallyObserved=errors.size===0;
 return Object.freeze({
  phase:'1CO',schemaVersion:1,
  kind:'REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD',
  repository:REPO,prNumber:1,base:'main',prMustRemainDraft:true,
  currentDevHead:currentHead,prReadBeforeAndAfterStable:stable,
  actualGithubReviewPaginationComplete:reviewPaginationComplete===true,
  observedSubmittedReviewCount:checked.counts.submitted,
  observedDistinctCurrentHeadApprovals:checked.counts.currentHeadApprovals,
  securityNominatedAccountActuallyApprovedCurrentHead:
   security?.currentHeadApprovedByThisAccount===true,
  businessNominatedAccountActuallyApprovedCurrentHead:
   business?.currentHeadApprovedByThisAccount===true,
  actualNominatedReviewerWritePermissionsObserved:
   technical.technicalRepoPermissionPreconditionMet,
  twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:technicallyObserved,
  anomalyCodes:[...errors].sort(),
  // Even verified Github APPROVED entries and write permissions do not
  // authenticate legal/corporate role, no-bypass, genuine external keys.
  realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated:false,
  latestHeadApprovalSignaturesIndependentlyCryptographicallyVerified:false,
  mainCodeownersAndBypassFreeRulesetIndependentlyVerified:false,
  realProviderLegalWormDrAndStagingApprovals:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export async function collectLiveReviewerEvidence({
 token,securityLogin,businessLogin,fetchImpl=fetch
}={}){
 const identity=validateReviewerNominees(securityLogin,businessLogin);
 if(!identity.valid)throw Error('CO_UNVERIFIED_OR_SELF_NOMINATED_GITHUB_ACCOUNTS');
 const fetchSource=path=>readOfficialGithubEndpoint(path,token,{fetchImpl});
 const before=await fetchSource(PR_PATH);
 const reviewResults=[],reviewsFirst=await fetchSource(REVIEW_PATH);
 let complete=reviewsFirst.status==='read'&&Array.isArray(reviewsFirst.data);
 if(complete){
  reviewResults.push(...reviewsFirst.data);
  for(let page=2;page<=MAX_REVIEW_PAGES&&
      reviewResults.length===(page-1)*100;page++){
   const next=await fetchSource(REVIEW_PATH+'&page='+page);
   if(next.status!=='read'||!Array.isArray(next.data)){
    complete=false;break;
   }
   reviewResults.push(...next.data);
  }
  if(reviewResults.length>=300)complete=false;
 }
 const [securityPermission,businessPermission]=await Promise.all([
  readActualGithubPermission(securityLogin,token,fetchImpl),
  readActualGithubPermission(businessLogin,token,fetchImpl)
 ]);
 const after=await fetchSource(PR_PATH);
 const verdict=assessRealNonauthorApprovalQuorum({
  securityLogin,businessLogin,
  prBefore:before.status==='read'?before.data:null,
  prAfter:after.status==='read'?after.data:null,
  reviews:complete?reviewResults:null,
  reviewPaginationComplete:complete,
  securityPermission,businessPermission
 });
 return verdict;
}
export function assessCurrentRunHold({
 byReport,clReport,cnReport,environment={}
}={}){
 const errors=new Set(),anomalies=new Set();
 const by=byReport?.snapshotDerived,cl=clReport?.decision,
  cn=cnReport?.verdict;
 if(byReport?.kind!=='LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD'||
  !HASH.test(byReport?.sourceBundleSha256??'')||
  byReport.productionReleaseAuthorized!==false||
  byReport.releaseDecision!=='HOLD'||
  by?.phase!=='1BY'||by?.observedPrDraftAndUnmerged!==true||
  by?.eventSourceHeadAndBaseMatch!==true||
  by?.ciMergeMatchesPrApi!==true||
  by?.productionReleaseAuthorized!==false||
  by?.releaseDecision!=='HOLD')
  errors.add('CO_BY_LIVE_GITHUB_HEAD_AND_REVIEW_SOURCE_INVALID');
 if(clReport?.sourceExternallySigned!==false||
    clReport?.productionReleaseAuthorized!==false||
    clReport?.releaseDecision!=='HOLD'||
    cl?.phase!=='1CL'||cl?.repo!==REPO||
    cl?.officialPublicObservationStructurallyValid!==true||
    cl?.productionReleaseAuthorized!==false||
    cl?.observedDevHeadSha!==by?.observedDevHeadSha)
  errors.add('CO_CL_MAIN_CODEOWNERS_SOURCE_INVALID');
 if(cnReport?.externallySigned!==false||
    cnReport?.productionReleaseAuthorized!==false||
    cnReport?.releaseDecision!=='HOLD'||
    cn?.phase!=='1CN'||cn?.repo!==REPO||
    cn?.officialReadOnlySourceChainStructurallyValid!==true||
    cn?.productionReleaseAuthorized!==false||
    cn?.sourceHeadSha!==by?.observedDevHeadSha)
  errors.add('CO_CN_ACTUAL_RULESET_SOURCE_INVALID');
 if(environment===null||typeof environment!=='object'||
    environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_JOB!=='live-github-governance-hold'||
    environment.GITHUB_REPOSITORY!==REPO||
    environment.GITHUB_REF!=='refs/pull/1/merge'||
    !SHA.test(environment.GITHUB_SHA??'')||
    by?.observedPrMergeSha!==environment.GITHUB_SHA)
  errors.add('CO_GITHUB_RUN_CHECKOUT_AND_EVENT_BINDING_INVALID');
 if(by?.reviews?.distinctLatestHeadApprovalCount<2)
  anomalies.add('CO_NO_TWO_LATEST_HEAD_GITHUB_APPROVALS_OBSERVED');
 if(!cl?.selectedCodeownersLocation)
  anomalies.add('CO_NO_ACTIVE_BASE_MAIN_CODEOWNERS_OBSERVED');
 if(!cn?.exactProposalMatchingRulesetCount)
  anomalies.add('CO_NO_ACTIVE_MAIN_RULESET_MATCH_OBSERVED');
 if(cn?.rulesetListAndAllBypassFieldsReadable!==true)
  anomalies.add('CO_PRIVILEGED_BYPASS_FIELD_UNAVAILABLE_TO_READONLY_CI');
 return Object.freeze({
  phase:'1CO',schemaVersion:1,
  kind:'LIVE_LATEST_HEAD_REVIEWER_GOVERNANCE_READONLY_HOLD',
  repository:REPO,observedDevHeadSha:by?.observedDevHeadSha??null,
  observedDistinctNonauthorCurrentHeadApprovals:
   by?.reviews?.distinctLatestHeadApprovalCount??null,
  observedBaseMainCodeowners:cl?.selectedCodeownersLocation??null,
  observedExactMainProposalInstalledCount:
   cn?.exactProposalMatchingRulesetCount??null,
  actualCurrentRunSourceStructurallyValid:errors.size===0,
  actualNomineeUsernamesIntentionallyNotStoredInCI:true,
  externalReviewerRoleMandatesAndRealNominatedPermissionsVerified:false,
  actualSecurityBusinessRoleQuorumCryptographicallyAccepted:false,
  mainAdminAppBypassAbsenceIndependentlyVerified:false,
  sourceChainUnsigned:true,
  anomalyCodes:[...errors,...anomalies].sort(),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function read(path,max){
 const st=lstatSync(path);
 if(!st.isFile()||st.isSymbolicLink()||st.size<1||st.size>max)
  throw Error('CO_UNSAFE_OR_MISSING_READONLY_GITHUB_SOURCE');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--ci-hold'){
  const verdict=assessCurrentRunHold({
   byReport:read('phase1by-github-readonly-governance-hold.json',262144),
   clReport:read('phase1cl-live-codeowners-reviewer-onboarding-hold.json',262144),
   cnReport:read('phase1cn-official-ruleset-bypass-reconciliation-hold.json',262144),
   environment:process.env
  });
  const report={verdict,externallySigned:false,independentWorm:false,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'};
  writeFileSync('phase1co-live-exact-head-independent-reviewer-hold.json',
   JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'w'});
  console.log(JSON.stringify(report,null,2));
  if(!verdict.actualCurrentRunSourceStructurallyValid||
     verdict.productionReleaseAuthorized!==false||verdict.releaseDecision!=='HOLD')
   process.exitCode=1;
  return;
 }
 if(args.length===3&&args[0]==='--verify-actual-reviewers'){
  // Only an explicitly authorized human runs this separate CLI with two
  // genuine preappointed nominees and approved GITHUB_READ_TOKEN.
  // No CI runner, source report or public repo artifact stores those names.
  if(process.env.GITHUB_ACTIONS==='true')
   throw Error('CO_REVIEWER_IDENTITIES_FORBIDDEN_IN_AUTOMATED_CI');
  const outcome=await collectLiveReviewerEvidence({
   token:process.env.GITHUB_READ_TOKEN,
   securityLogin:args[1],businessLogin:args[2]
  });
  console.log(JSON.stringify(outcome,null,2));
  if(!outcome.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved)
   process.exitCode=1;
  return;
 }
 throw Error('CO_ONLY_ZERO_INPUT_CI_HOLD_OR_NAMED_READONLY_OPERATOR_VERIFY');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(error=>{
  console.error('CO independent reviewer evidence restricted:',
   error instanceof Error?error.message:'Unknown');
  process.exitCode=1;
 });
}
