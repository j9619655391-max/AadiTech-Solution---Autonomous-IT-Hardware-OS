import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Phase 1DF: manually invoked, read-only correlation of REAL GitHub
// observations. Technical GitHub approvals are not corporate appointments.
// This script never writes GitHub, authorizes a release or stores logins.
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const SHA=/^[0-9a-f]{40}$/;
const held=x=>x?.productionReleaseAuthorized===false&&
 x?.productionReleaseBlocked===true&&x?.releaseDecision==='HOLD';
const nonnegative=x=>Number.isSafeInteger(x)&&x>=0&&x<=100000;
function governanceValid(g){
 return g?.phase==='1DC'&&g?.schemaVersion===1&&
  g?.kind==='ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD'&&
  g?.repository===REPO&&g?.officialMainRefAndDraftPrStable===true&&
  SHA.test(g?.currentDevelopmentHeadSha??'')&&
  SHA.test(g?.currentMainBaseSha??'')&&held(g)&&
  g?.officialSubmittedReviewPaginationComplete===true&&
  nonnegative(g?.observedDistinctCurrentHeadNonauthorApprovals)&&
  nonnegative(g?.observedSubmittedReviewCount)&&
  nonnegative(g?.strictRootCoverageCodeownersFiles)&&
  nonnegative(g?.observedStrictBypassFreeMainRulesetCount)&&
  ['read','access_denied','absent_or_hidden','unavailable','invalid']
   .includes(g?.directMainBranchProtectionStatus)&&
  (g?.directMainBranchProtectionExplicitly403!==true||
   g?.directMainBranchProtectionStatus==='access_denied');
}
function roleQuorumValid(q,head){
 return q?.phase==='1CO'&&q?.schemaVersion===1&&
  q?.kind==='REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD'&&
  q?.repository===REPO&&q?.prNumber===1&&q?.base==='main'&&
  q?.prMustRemainDraft===true&&q?.currentDevHead===head&&
  q?.prReadBeforeAndAfterStable===true&&
  q?.actualGithubReviewPaginationComplete===true&&
  nonnegative(q?.observedSubmittedReviewCount)&&
  nonnegative(q?.observedDistinctCurrentHeadApprovals)&&
  q?.observedDistinctCurrentHeadApprovals>=2&&
  q?.securityNominatedAccountActuallyApprovedCurrentHead===true&&
  q?.businessNominatedAccountActuallyApprovedCurrentHead===true&&
  q?.actualNominatedReviewerWritePermissionsObserved===true&&
  q?.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved===true&&
  Array.isArray(q?.anomalyCodes)&&q.anomalyCodes.length===0&&
  q?.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated===false&&
  q?.mainCodeownersAndBypassFreeRulesetIndependentlyVerified===false&&held(q);
}

/**
 * Check two separate real GitHub reviewer reads against main/pr readbacks.
 * Input objects are technical observations only, never external attestation.
 * No usernames, token, PII, mock signatures or mutation instructions leak.
 */
export function assessRoleBoundReadOnlyReconciliation({
  governanceBefore=null,roleQuorumFirst=null,roleQuorumSecond=null,
  governanceAfter=null
}={}){
 const problems=new Set();
 const gb=governanceValid(governanceBefore),
  ga=governanceValid(governanceAfter);
 if(!gb||!ga)problems.add('DF_OFFICIAL_GITHUB_READONLY_SNAPSHOT_INVALID_OR_INCOMPLETE');
 const stable=gb&&ga&&
  governanceBefore.currentDevelopmentHeadSha===governanceAfter.currentDevelopmentHeadSha&&
  governanceBefore.currentMainBaseSha===governanceAfter.currentMainBaseSha;
 if(!stable)problems.add('DF_PR_SOURCE_OR_MAIN_CHANGED_ACROSS_READS');
 const head=stable?governanceBefore.currentDevelopmentHeadSha:null;
 const first=roleQuorumValid(roleQuorumFirst,head),
  second=roleQuorumValid(roleQuorumSecond,head);
 if(!first||!second)problems.add('DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
 const repeat=first&&second&&
  roleQuorumFirst.currentDevHead===roleQuorumSecond.currentDevHead&&
  roleQuorumFirst.observedSubmittedReviewCount===roleQuorumSecond.observedSubmittedReviewCount&&
  roleQuorumFirst.observedDistinctCurrentHeadApprovals===roleQuorumSecond.observedDistinctCurrentHeadApprovals;
 if(!repeat)problems.add('DF_REVIEW_DISMISSAL_OR_RACE_NOT_RULED_OUT');
 const githubCounts=stable&&first&&second&&repeat&&
  governanceBefore.observedDistinctCurrentHeadNonauthorApprovals>=2&&
  governanceBefore.observedDistinctCurrentHeadNonauthorApprovals===
   governanceAfter.observedDistinctCurrentHeadNonauthorApprovals&&
  governanceBefore.observedDistinctCurrentHeadNonauthorApprovals===
   roleQuorumFirst.observedDistinctCurrentHeadApprovals&&
  governanceBefore.observedSubmittedReviewCount>=2&&
  governanceBefore.observedSubmittedReviewCount===
   governanceAfter.observedSubmittedReviewCount&&
  governanceBefore.observedSubmittedReviewCount===
   roleQuorumFirst.observedSubmittedReviewCount;
 if(!githubCounts)problems.add('DF_INDEPENDENT_GITHUB_REVIEW_COUNTS_NOT_CORROBORATED');
 // A head can be unchanged while a review is dismissed. Re-reading CO
 // reduces that window, but never proves that reviews cannot change later.
 const noMain403=stable&&
  governanceBefore.directMainBranchProtectionExplicitly403===false&&
  governanceAfter.directMainBranchProtectionExplicitly403===false&&
  governanceBefore.directMainBranchProtectionStatus==='read'&&
  governanceAfter.directMainBranchProtectionStatus==='read';
 const visibleMain=stable&&noMain403&&
  governanceBefore.strictRootCoverageCodeownersFiles>0&&
  governanceAfter.strictRootCoverageCodeownersFiles>0&&
  governanceBefore.observedStrictBypassFreeMainRulesetCount>0&&
  governanceAfter.observedStrictBypassFreeMainRulesetCount>0;
 if(!visibleMain)problems.add('DF_EFFECTIVE_MAIN_POLICY_AND_ADMIN_READBACK_NOT_VERIFIED');
 const checks=stable&&first&&second&&repeat&&githubCounts;
 return Object.freeze({
  phase:'1DF',schemaVersion:1,
  kind:'TWO_ACTUAL_GITHUB_ROLE_SPECIFIC_REVIEW_READS_UNTRUSTED_HUMAN_HANDOFF_HOLD',
  repository:REPO,
  currentDevelopmentHeadSha:head,
  currentMainBaseSha:stable?governanceBefore.currentMainBaseSha:null,
  exactSourceAndMainStableAcrossOfficialReadsOnly:stable,
  twoDistinctNominatedRolesApprovedExactHeadOnBothReadsOnly:first&&second,
  repeatReviewerReadCountAndSourceUnchangedOnly:repeat,
  independentGithubSummaryCountsCorroboratedOnly:githubCounts,
  effectiveBaseMainGovernanceReadableOnly:visibleMain,
  branchProtection403MeansUnknown:stable&&(
   governanceBefore.directMainBranchProtectionExplicitly403===true||
   governanceAfter.directMainBranchProtectionExplicitly403===true),
  candidateCrossSourceTechnicalApprovalJoinOnly:checks,
  reviewerNamesAndTokensExcludedFromReport:true,
  githubReviewCannotIndependentlyProveCorporateRoleMandate:true,
  independentSecurityBusinessCorporateAppointmentsAuthenticated:false,
  authorizedProtectedMainAdminPolicyInstallationApproved:false,
  externallyVerifiedCaMcaProviderCasWormDrAndSignedStaging:false,
  canInstallMainPolicyOrSubmitReviewsOrMerge:false,
  canIssueQuotesDispatchStockPostFinanceOrDeploy:false,
  anomalyCodes:Object.freeze([...problems].sort()),
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}

async function main(){
 const args=process.argv.slice(2);
 if(process.env.GITHUB_ACTIONS==='true'||args.length!==3||
    args[0]!=='--inspect-role-approvals-readonly')
  throw Error('DF_HUMAN_ONLY_EXPLICIT_READONLY_COMMAND');
 const [securityLogin,businessLogin]=args.slice(1);
 const {validateReviewerNominees}=await import('./phase1cm-admin-ruleset-reviewer-handoff.mjs');
 if(!validateReviewerNominees(securityLogin,businessLogin).valid)
  throw Error('DF_INVALID_DISTINCT_NONAUTHOR_NOMINEE_INPUT');
 const token=process.env.GITHUB_READ_TOKEN??'';
 if(typeof token!=='string'||token.length<1||token.length>4096)
  throw Error('DF_APPROVED_READONLY_OPERATOR_TOKEN_REQUIRED');
 const {collectLiveActualGovernance}=await import('./phase1dc-live-external-governance-readiness.mjs');
 const {collectLiveReviewerEvidence}=await import('./phase1co-live-exact-head-reviewer-quorum.mjs');
 const governanceBefore=await collectLiveActualGovernance({token});
 const roleQuorumFirst=await collectLiveReviewerEvidence({token,securityLogin,businessLogin});
 const roleQuorumSecond=await collectLiveReviewerEvidence({token,securityLogin,businessLogin});
 const governanceAfter=await collectLiveActualGovernance({token});
 const verdict=assessRoleBoundReadOnlyReconciliation({
  governanceBefore,roleQuorumFirst,roleQuorumSecond,governanceAfter
 });
 console.log(JSON.stringify(verdict,null,2));
 if(!verdict.candidateCrossSourceTechnicalApprovalJoinOnly||
    !verdict.effectiveBaseMainGovernanceReadableOnly)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(()=>{
  // Never echo user-supplied login, endpoint data, tokens or raw errors.
  console.error('DF_READONLY_ROLE_RECONCILIATION_HOLD');
  process.exitCode=1;
 });
