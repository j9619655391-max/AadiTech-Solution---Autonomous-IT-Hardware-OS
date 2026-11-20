// Phase 1DI: terminal GitHub reviewer/main-policy race revalidation.
// The independent operator's earlier 1DF and pinned 1DG observations
// can become stale while the two CODEOWNERS reads are in progress.
// This is a readonly *technical* snapshot join, NEVER production GO.
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const SHA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const held=x=>x?.productionReleaseAuthorized===false&&
 x?.productionReleaseBlocked===true&&x?.releaseDecision==='HOLD';
const int=x=>Number.isSafeInteger(x)&&x>=0&&x<=100000;
const CODEOWNERS=new Set(['.github/CODEOWNERS','CODEOWNERS','docs/CODEOWNERS']);
const same=(x,y)=>x===y;
const requiredPolicyFields=Object.freeze([
 'unsignedMainPolicyReadbackSha256',
 'observedSubmittedReviewCount',
 'observedDistinctCurrentHeadNonauthorApprovals',
 'strictRootCoverageCodeownersFiles',
 'observedStrictBypassFreeMainRulesetCount',
 'directMainBranchProtectionStatus',
 'directMainBranchProtectionExplicitly403'
]);
export function validFinalGovernanceSnapshot(g,head,main){
 return g?.phase==='1DC'&&g?.schemaVersion===1&&
  g?.kind==='ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD'&&
  g?.repository===REPO&&g?.prNumber===1&&held(g)&&
  SHA.test(head??'')&&SHA.test(main??'')&&
  g.currentDevelopmentHeadSha===head&&g.currentMainBaseSha===main&&
  g.officialMainRefAndDraftPrStable===true&&
  g.officialSubmittedReviewPaginationComplete===true&&
  g.technicallyObservedGithubPrerequisitesOnly===true&&
  HASH.test(g.unsignedMainPolicyReadbackSha256??'')&&
  HASH.test(g.unsignedSubmittedReviewHistorySha256??'')&&
  int(g.observedSubmittedReviewCount)&&g.observedSubmittedReviewCount>=2&&
  int(g.observedDistinctCurrentHeadNonauthorApprovals)&&
  g.observedDistinctCurrentHeadNonauthorApprovals>=2&&
  int(g.strictRootCoverageCodeownersFiles)&&
  g.strictRootCoverageCodeownersFiles>0&&
  int(g.observedStrictBypassFreeMainRulesetCount)&&
  g.observedStrictBypassFreeMainRulesetCount>0&&
  g.directMainBranchProtectionStatus==='read'&&
  g.directMainBranchProtectionExplicitly403===false&&
  Array.isArray(g.anomalyCodes)&&g.anomalyCodes.length===0&&
  g.legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated===false&&
  g.externallyAuthorizedTrustProviderMandateAndKeyEnrollment===false;
}
function validOriginalJoin(join){
 return join?.phase==='1DF'&&join?.schemaVersion===1&&
  join?.kind==='TWO_ACTUAL_GITHUB_ROLE_SPECIFIC_REVIEW_READS_UNTRUSTED_HUMAN_HANDOFF_HOLD'&&
  join?.repository===REPO&&held(join)&&
  join.exactSourceAndMainStableAcrossOfficialReadsOnly===true&&
  join.candidateCrossSourceTechnicalApprovalJoinOnly===true&&
  join.twoDistinctNominatedRolesApprovedExactHeadOnBothReadsOnly===true&&
  join.independentGithubSummaryCountsCorroboratedOnly===true&&
  join.effectiveBaseMainGovernanceReadableOnly===true&&
  SHA.test(join.currentDevelopmentHeadSha??'')&&
  SHA.test(join.currentMainBaseSha??'')&&
  join.independentSecurityBusinessCorporateAppointmentsAuthenticated===false&&
  join.authorizedProtectedMainAdminPolicyInstallationApproved===false;
}
function validPinnedOwners(owners,join){
 return owners?.phase==='1DG'&&owners?.schemaVersion===1&&
  owners?.kind==='EXACT_BASE_MAIN_CODEOWNERS_PRECEDENCE_NOMINEE_MATCH_READONLY_HOLD'&&
  owners?.repository===REPO&&held(owners)&&
  owners.pinnedBaseMainSha===join?.currentMainBaseSha&&
  owners.currentDevelopmentHeadSha===join?.currentDevelopmentHeadSha&&
  CODEOWNERS.has(owners.effectiveCodeownersPath)&&
  SHA.test(owners.effectiveGitBlobSha??'')&&
  owners.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly===true&&
  owners.exactTwoNominatedAccountsInEachAcceptedRuleOnly===true&&
  Array.isArray(owners.anomalyCodes)&&owners.anomalyCodes.length===0&&
  owners.independentlyAuthenticatedCorporateSecurityBusinessMandates===false&&
  owners.effectiveMainRulesetOrAdminNonbypassApproved===false;
}
function validTerminalNominatedReview(q,head){
 return q?.phase==='1CO'&&q?.schemaVersion===1&&
  q?.kind==='REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD'&&
  q?.repository===REPO&&q?.prNumber===1&&q?.base==='main'&&
  q?.prMustRemainDraft===true&&q?.currentDevHead===head&&held(q)&&
  q?.prReadBeforeAndAfterStable===true&&
  q?.actualGithubReviewPaginationComplete===true&&
  q?.securityNominatedAccountActuallyApprovedCurrentHead===true&&
  q?.businessNominatedAccountActuallyApprovedCurrentHead===true&&
  q?.actualNominatedReviewerWritePermissionsObserved===true&&
  q?.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved===true&&
  int(q?.observedDistinctCurrentHeadApprovals)&&
  q.observedDistinctCurrentHeadApprovals>=2&&
  int(q?.observedSubmittedReviewCount)&&q.observedSubmittedReviewCount>=2&&
  Array.isArray(q?.anomalyCodes)&&q.anomalyCodes.length===0&&
  q?.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated===false;
}

/**
 * 1DC/1CO terminal observations are made AFTER 1DG's two pinned-owner reads.
 * The second terminal governance read is AFTER the role-specific review read.
 * An unsigned SHA-256 fingerprint of full official policy readbacks makes
 * same-count rule swaps detectable; still no atomic cross-API snapshot.
 */
export function assessTerminalReadOnlyMainAndReviewRecheck({
 roleJoin=null,pinnedOwners=null,initialGovernanceBefore=null,
 initialGovernanceAfter=null,terminalGovernanceBefore=null,
 terminalNominatedReview=null,terminalGovernanceAfter=null
}={}){
 const anomalies=new Set();
 const original=Boolean(validOriginalJoin(roleJoin));
 if(!original)anomalies.add('DI_INITIAL_REAL_ROLE_BOUND_JOIN_NOT_VERIFIED');
 const pinned=Boolean(validPinnedOwners(pinnedOwners,roleJoin));
 if(!pinned)anomalies.add('DI_EXACT_PINNED_MAIN_CODEOWNERS_NOT_VERIFIED');
 const head=original?roleJoin.currentDevelopmentHeadSha:null;
 const main=original?roleJoin.currentMainBaseSha:null;
 const reports=[
  initialGovernanceBefore,initialGovernanceAfter,
  terminalGovernanceBefore,terminalGovernanceAfter
 ];
 const valid=reports.map(g=>validFinalGovernanceSnapshot(g,head,main));
 const allSourcesValid=valid.every(Boolean);
 if(!allSourcesValid)
  anomalies.add('DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
 const consistent=allSourcesValid&&requiredPolicyFields.every(key=>
  reports.every(g=>same(g[key],reports[0][key])));
 if(!consistent)
  anomalies.add('DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
 // 1DK: same-count review decision swaps must not pass. The four
 // official 1DC reads bracket both the nominated reviewer and owner reads.
 const historyStable=allSourcesValid&&reports.every(g=>
  g.unsignedSubmittedReviewHistorySha256===
   reports[0].unsignedSubmittedReviewHistorySha256);
 if(!historyStable)
  anomalies.add('DK_OFFICIAL_SUBMITTED_REVIEW_HISTORY_CHANGED_OR_UNREADABLE');
 const reviewers=Boolean(validTerminalNominatedReview(terminalNominatedReview,head));
 if(!reviewers)
  anomalies.add('DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
 const counts=Boolean(reviewers&&allSourcesValid&&consistent&&
  terminalNominatedReview.observedSubmittedReviewCount===
    initialGovernanceBefore.observedSubmittedReviewCount&&
  terminalNominatedReview.observedDistinctCurrentHeadApprovals===
    initialGovernanceBefore.observedDistinctCurrentHeadNonauthorApprovals);
 if(!counts)anomalies.add('DI_FINAL_ROLE_APPROVAL_COUNTS_DO_NOT_MATCH_LIVE_GITHUB');
 const technicallyStable=Boolean(original&&pinned&&allSourcesValid&&
  consistent&&historyStable&&reviewers&&counts);
 return Object.freeze({
  phase:'1DI',schemaVersion:1,
  kind:'TERMINAL_REAL_GITHUB_MAIN_POLICY_AND_NOMINEE_RECHECK_UNSIGNED_HOLD',
  repository:REPO,
  checkedSourceHeadSha:head,
  checkedBaseMainSha:main,
  terminalSourceMainShaStayedStableOnly:allSourcesValid,
  fullUnsignedMainPolicyFingerprintUnchangedAcrossFourReadsOnly:
   consistent&&allSourcesValid,
  exactHeadNominatedApprovalsStillPresentAtTerminalReadOnly:reviewers,
  reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly:historyStable,
  unsignedReviewHistoryFingerprint:technicallyStable?
   initialGovernanceBefore.unsignedSubmittedReviewHistorySha256:null,
  terminalNominatedReviewCountsMatchedOfficialSourceOnly:counts,
  wholeOperatorReadWindowTechnicallyConsistentOnly:technicallyStable,
  unsignedPolicyFingerprint:technicallyStable?
   initialGovernanceBefore.unsignedMainPolicyReadbackSha256:null,
  cannotProveNoInterveningEquivocationOrChangesAfterFinalRead:true,
  cannotVerifyCorporateRoleMandatesOrAdminAuthorization:true,
  cannotAuthenticateSignedExternalWormProviderMcaCcaCrLOcsp:true,
  noReviewerUsernamesOrOperatorTokenRetained:true,
  canWriteMainRequestReviewMergeOrDeploy:false,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  independentSecurityAndBusinessCorporateMandatesVerified:false,
  realProviderWormDrOidcSlsaStagingAcceptanceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
