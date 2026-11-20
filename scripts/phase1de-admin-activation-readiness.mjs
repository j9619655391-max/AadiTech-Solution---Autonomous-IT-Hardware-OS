import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 REPO,AUTHOR,REQUIRED_JOBS,RULESET_PROPOSAL,
 assessProposedMainRuleset,validateReviewerNominees,proposedCodeowners,
 assessActualGithubPermissions,readActualGithubPermission
} from './phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {collectLiveActualGovernance,EXTERNAL_GATES}
 from './phase1dc-live-external-governance-readiness.mjs';
import {assessIndependentOperatorHandoff}
 from './phase1dd-authorized-human-handoff.mjs';

// Phase 1DE: a READ-ONLY proposed admin activation *preflight*.
// No synthetic corporate roles, GitHub POST/PATCH/PUT/DELETE, reviewer
// approval, branch change, or production actions are ever performed.
export const ACTION_STAGES=Object.freeze([
 'APPOINT_REAL_CORPORATE_SECURITY_AND_BUSINESS_REVIEWERS',
 'VERIFY_NOMINEE_GITHUB_WRITE_PERMISSIONS_WITH_APPROVED_READ_TOKEN',
 'AUTHORIZE_ADMIN_PROTECTED_MAIN_CODEOWNERS_CHANGE',
 'AUTHORIZE_ADMIN_NO_BYPASS_MAIN_RULESET_CHANGE',
 'REVERIFY_EFFECTIVE_MAIN_POLICY_AND_EXACT_HEAD_REVIEW_QUORUM',
 'INDEPENDENTLY_ACCEPT_EXTERNAL_CA_MCA_PROVIDER_CAS_WORM_DR_OIDC_STAGING'
]);
const SHA=/^[0-9a-f]{40}$/;
const own=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const deny=(x)=>!x||x.productionReleaseAuthorized!==false||
 x.releaseDecision!=='HOLD';
export function assessAdminActivationPreflight({
 github=null,proposal=null,securityLogin=null,businessLogin=null,
 securityPermission=null,businessPermission=null
}={}){
 const problems=new Set();
 const validSource=github?.phase==='1DC'&&github?.repository===REPO&&
  github?.kind==='ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD'&&
  github?.officialMainRefAndDraftPrStable===true&&
  SHA.test(github?.currentDevelopmentHeadSha??'')&&
  SHA.test(github?.currentMainBaseSha??'')&&
  !deny(github);
 if(!validSource)problems.add('DE_LIVE_GITHUB_PR_MAIN_STABILITY_UNVERIFIED');
 const ruleset=assessProposedMainRuleset(proposal);
 if(!ruleset.localProposedRestPayloadStructurallySafe)
  problems.add('DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
 const nominees=validateReviewerNominees(securityLogin,businessLogin);
 if(!nominees.valid)problems.add('DE_AUTHORIZED_HUMAN_REVIEWER_NOMINATIONS_NOT_SUPPLIED');
 const perms=assessActualGithubPermissions({
  securityLogin,businessLogin,securityResponse:securityPermission,
  businessResponse:businessPermission
 });
 if(!perms.technicalRepoPermissionPreconditionMet)
  problems.add('DE_NOMINEE_WRITE_PERMISSIONS_NOT_OBSERVED');
 let owners=null;
 if(nominees.valid){
  try{owners=proposedCodeowners(securityLogin,businessLogin);}
  catch{problems.add('DE_CODEOWNERS_PROPOSAL_CANNOT_BE_PREPARED');}
 }
 const reviewObserved=validSource&&
  github.observedDistinctCurrentHeadNonauthorApprovals>=2&&
  github.officialSubmittedReviewPaginationComplete===true;
 const ownerObserved=validSource&&
  github.strictRootCoverageCodeownersFiles>0;
 const rulesObserved=validSource&&
  github.observedStrictBypassFreeMainRulesetCount>0&&
  github.directMainBranchProtectionStatus==='read'&&
  github.directMainBranchProtectionExplicitly403===false;
 if(!reviewObserved)problems.add('DE_NO_TWO_REAL_EXACT_HEAD_APPROVALS_OBSERVED');
 if(!ownerObserved)problems.add('DE_BASE_MAIN_CODEOWNERS_NOT_VERIFIABLY_EFFECTIVE');
 if(!rulesObserved)problems.add('DE_ENFORCED_MAIN_RULES_AND_PROTECTION_UNVERIFIED');
 // Explicitly forbid using "2 GitHub users with write access" as proof
 // those specific people have legally delegated Security/Business roles.
 const technical=validSource&&ruleset.localProposedRestPayloadStructurallySafe&&
  nominees.valid&&perms.technicalRepoPermissionPreconditionMet;
 const rows=[
  {stage:ACTION_STAGES[0],status:'HUMAN_CORPORATE_MANDATE_REQUIRED',
   office:'CORPORATE_OWNER_LEGAL_SECURITY'},
  {stage:ACTION_STAGES[1],status:perms.technicalRepoPermissionPreconditionMet?
    'TECHNICAL_GITHUB_ACCESS_ONLY_NOT_ROLE_AUTHORITY':'GITHUB_PERMISSION_CHECK_REQUIRED',
   office:'AUTHORIZED_GITHUB_REPO_ADMIN'},
  {stage:ACTION_STAGES[2],status:ownerObserved?
    'BASE_MAIN_TECHNICALLY_VISIBLE_NOT_LEGALLY_ACCEPTED':'ADMIN_CHANGE_OR_READBACK_REQUIRED',
   office:'AUTHORIZED_GITHUB_REPO_ADMIN'},
  {stage:ACTION_STAGES[3],status:rulesObserved?
    'RULESET_TECHNICALLY_VISIBLE_NOT_LEGALLY_ACCEPTED':'ADMIN_RULESET_REVIEW_OR_ACCESS_REQUIRED',
   office:'AUTHORIZED_GITHUB_ORG_ADMIN'},
  {stage:ACTION_STAGES[4],status:reviewObserved?
    'TWO_TECHNICAL_APPROVALS_ONLY_NO_ROLE_MANDATE':'INDEPENDENT_CURRENT_HEAD_REVIEWS_PENDING',
   office:'APPOINTED_NONAUTHOR_SECURITY_BUSINESS'},
  {stage:ACTION_STAGES[5],status:'REAL_EXTERNAL_PROVIDER_AND_HUMAN_ACCEPTANCE_PENDING',
   office:'LEGAL_SECURITY_PROVIDER_OPS_OWNER'}
 ];
 return Object.freeze({
  phase:'1DE',schemaVersion:1,
  kind:'AUTHORIZED_ADMIN_ACTIVATION_READONLY_PREFLIGHT_HARD_HOLD',
  repository:REPO,
  currentDevelopmentHeadSha:validSource?github.currentDevelopmentHeadSha:null,
  currentMainBaseSha:validSource?github.currentMainBaseSha:null,
  officialGithubSourcePrAndMainStable:validSource,
  proposedMainRulesetStructurallyValidOnly:
   ruleset.localProposedRestPayloadStructurallySafe,
  proposedMainRulesetPayloadSha256:ruleset.proposalContentSha256,
  candidateReviewerSyntaxAndIndependenceValid:nominees.valid,
  technicalReviewerWritePermissionsObservedOnly:
   perms.technicalRepoPermissionPreconditionMet,
  proposedCodeownersContentSha256:owners?.sha256??null,
  proposedCodeownersNotInstalled:true,
  officialMainCodeownersVisible:ownerObserved,
  officialMainRulesAndProtectionVisible:rulesObserved,
  observedTwoNonauthorExactHeadGithubReviewsOnly:reviewObserved,
  candidateAdminPreparationInputsMathematicallyConsistentOnly:technical,
  numberOfMandatoryHostedCheckContexts:REQUIRED_JOBS.length,
  independentExternalGateCount:EXTERNAL_GATES.length,
  reviewOfCorporateRoleAppointmentsAuthenticated:false,
  approvedActualAdminWriteOrPolicyInstallation:false,
  trustedExternalOfficerProviderAndCaMandatesAuthenticated:false,
  finalIndependentProductionAcceptance:false,
  canInstallOrChangeMainGovernance:false,
  canRequestOrSubmitReviewOrMerge:false,
  canActivateExternalProvidersOrDeploy:false,
  requiredHumanActions:Object.freeze(rows),
  anomalyCodes:Object.freeze([...problems].sort()),
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
function loadReviewedProposal(){
 const file=lstatSync(RULESET_PROPOSAL);
 if(!file.isFile()||file.isSymbolicLink()||
    file.size<1||file.size>65536)
  throw Error('DE_UNAPPLIED_PROPOSAL_MISSING_UNSAFE_OR_OVERSIZE');
 return JSON.parse(readFileSync(RULESET_PROPOSAL,'utf8'));
}
async function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||
    ![1,3].includes(args.length)||
    args[0]!=='--inspect-admin-readonly')
  throw Error('DE_EXPLICIT_HUMAN_READONLY_GITHUB_OPERATOR_ONLY');
 const github=await collectLiveActualGovernance({
  token:process.env.GITHUB_READ_TOKEN??''
 });
 let securityLogin=null,businessLogin=null,
  securityPermission=null,businessPermission=null;
 if(args.length===3){
  [securityLogin,businessLogin]=args.slice(1);
  const valid=validateReviewerNominees(securityLogin,businessLogin);
  if(valid.valid){
   const t=process.env.GITHUB_READ_TOKEN??'';
   [securityPermission,businessPermission]=await Promise.all([
    readActualGithubPermission(securityLogin,t),
    readActualGithubPermission(businessLogin,t)
   ]);
  }
 }
 const outcome=assessAdminActivationPreflight({
  github,proposal:loadReviewedProposal(),
  securityLogin,businessLogin,securityPermission,businessPermission
 });
 console.log(JSON.stringify(outcome,null,2));
 if(!outcome.officialGithubSourcePrAndMainStable||
    !outcome.proposedMainRulesetStructurallyValidOnly)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('DE protected-main genuine human approvals still HOLD:',
   e instanceof Error?e.message:'Unknown');process.exitCode=1;
 });
