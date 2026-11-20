import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {assessRoleBoundReadOnlyReconciliation} from '../scripts/phase1df-role-bound-readonly-reconciliation.mjs';
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const HEAD='a'.repeat(40),MAIN='b'.repeat(40);
const g=()=>({phase:'1DC',schemaVersion:1,
 kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
 repository:REPO,currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
 officialMainRefAndDraftPrStable:true,officialSubmittedReviewPaginationComplete:true,
 observedDistinctCurrentHeadNonauthorApprovals:2,observedSubmittedReviewCount:2,
 strictRootCoverageCodeownersFiles:1,observedStrictBypassFreeMainRulesetCount:1,
 directMainBranchProtectionStatus:'read',directMainBranchProtectionExplicitly403:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
const q=()=>({phase:'1CO',schemaVersion:1,
 kind:'REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD',
 repository:REPO,prNumber:1,base:'main',prMustRemainDraft:true,
 currentDevHead:HEAD,prReadBeforeAndAfterStable:true,
 actualGithubReviewPaginationComplete:true,observedSubmittedReviewCount:2,
 observedDistinctCurrentHeadApprovals:2,
 securityNominatedAccountActuallyApprovedCurrentHead:true,
 businessNominatedAccountActuallyApprovedCurrentHead:true,
 actualNominatedReviewerWritePermissionsObserved:true,
 twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:true,
 anomalyCodes:[],realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated:false,
 mainCodeownersAndBypassFreeRulesetIndependentlyVerified:false,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
const input=()=>({governanceBefore:g(),roleQuorumFirst:q(),roleQuorumSecond:q(),governanceAfter:g()});
const run=f=>{const v=input();f?.(v);return assessRoleBoundReadOnlyReconciliation(v);};
function hold(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.independentSecurityBusinessCorporateAppointmentsAuthenticated,false);
 assert.equal(r.authorizedProtectedMainAdminPolicyInstallationApproved,false);
 assert.equal(r.externallyVerifiedCaMcaProviderCasWormDrAndSignedStaging,false);
 assert.equal(r.canInstallMainPolicyOrSubmitReviewsOrMerge,false);
 assert.equal(r.canIssueQuotesDispatchStockPostFinanceOrDeploy,false);
 assert.equal(r.reviewerNamesAndTokensExcludedFromReport,true);
}
function deny(fn,code){const x=run(fn);hold(x);assert.ok(x.anomalyCodes.includes(code),x.anomalyCodes.join(','));return x;}
test('DF: even all mocked technical indicators passing never authorize corporate roles or GO',()=>{
 const x=run();hold(x);assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,true);
 assert.equal(x.effectiveBaseMainGovernanceReadableOnly,true);
 assert.deepEqual(x.anomalyCodes,[]);
});
test('DF: no source observations defaults to HOLD',()=>{
 const x=assessRoleBoundReadOnlyReconciliation();hold(x);
 assert.equal(x.currentDevelopmentHeadSha,null);
 assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,false);
});
test('DF: missing first or second distinct current-head role approval report fails',()=>{
 deny(x=>{x.roleQuorumFirst=null},'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
 deny(x=>{x.roleQuorumSecond=null},'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: security and business approvals cannot be pooled from unrelated users',()=>{
 for(const key of ['securityNominatedAccountActuallyApprovedCurrentHead','businessNominatedAccountActuallyApprovedCurrentHead'])
  deny(x=>{x.roleQuorumSecond[key]=false},'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: total two Github approvals alone never implies two nominated roles',()=>{
 deny(x=>{x.roleQuorumFirst.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved=false},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: stale submitted review and PR head not stable across read fails',()=>{
 deny(x=>{x.roleQuorumSecond.prReadBeforeAndAfterStable=false},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
 deny(x=>{x.roleQuorumFirst.currentDevHead='c'.repeat(40)},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: repeated approval report cannot silently shrink or change count',()=>{
 deny(x=>{x.roleQuorumSecond.observedSubmittedReviewCount=3},
  'DF_REVIEW_DISMISSAL_OR_RACE_NOT_RULED_OUT');
 deny(x=>{x.roleQuorumSecond.observedDistinctCurrentHeadApprovals=3},
  'DF_REVIEW_DISMISSAL_OR_RACE_NOT_RULED_OUT');
});
test('DF: review pagination ambiguity, nonexistent permission and submitted incomplete denied',()=>{
 deny(x=>{x.roleQuorumSecond.actualGithubReviewPaginationComplete=false},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
 deny(x=>{x.roleQuorumFirst.actualNominatedReviewerWritePermissionsObserved=false},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: 1CO contradictory GO, legal-role acceptance or nonempty anomaly denied',()=>{
 for(const fn of [
  x=>{x.roleQuorumFirst.productionReleaseAuthorized=true},
  x=>{x.roleQuorumSecond.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated=true},
  x=>{x.roleQuorumFirst.anomalyCodes=['CO_BAD_SOURCE']}
 ])deny(fn,'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
});
test('DF: GitHub head drift and base drift between 1DC snapshots denied',()=>{
 deny(x=>{x.governanceAfter.currentDevelopmentHeadSha='c'.repeat(40)},
  'DF_PR_SOURCE_OR_MAIN_CHANGED_ACROSS_READS');
 deny(x=>{x.governanceBefore.currentMainBaseSha='c'.repeat(40)},
  'DF_PR_SOURCE_OR_MAIN_CHANGED_ACROSS_READS');
});
test('DF: invalid 1DC repository, phase, control or HEAD refused',()=>{
 for(const fn of [
  x=>{x.governanceBefore.repository='other/repo'},
  x=>{x.governanceAfter.officialMainRefAndDraftPrStable=false},
  x=>{x.governanceBefore.currentDevelopmentHeadSha='bad'},
  x=>{x.governanceAfter.productionReleaseAuthorized=true},
  x=>{x.governanceBefore.kind='FAKE_OBSERVATION'}
 ])deny(fn,'DF_OFFICIAL_GITHUB_READONLY_SNAPSHOT_INVALID_OR_INCOMPLETE');
});
test('DF: 1DC counts and independent reviewer counts must corroborate',()=>{
 deny(x=>{x.governanceBefore.observedDistinctCurrentHeadNonauthorApprovals=0},
  'DF_INDEPENDENT_GITHUB_REVIEW_COUNTS_NOT_CORROBORATED');
 deny(x=>{x.governanceAfter.observedSubmittedReviewCount=1},
  'DF_INDEPENDENT_GITHUB_REVIEW_COUNTS_NOT_CORROBORATED');
});
test('DF: branch protection 403 must remain UNKNOWN even with two role-specific reviews',()=>{
 const x=deny(v=>{
  v.governanceBefore.directMainBranchProtectionStatus='access_denied';
  v.governanceBefore.directMainBranchProtectionExplicitly403=true;
 },'DF_EFFECTIVE_MAIN_POLICY_AND_ADMIN_READBACK_NOT_VERIFIED');
 assert.equal(x.branchProtection403MeansUnknown,true);
 assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,true);
});
test('DF: invalid protection 403 disguised as read rejected',()=>{
 deny(x=>{x.governanceAfter.directMainBranchProtectionExplicitly403=true},
  'DF_OFFICIAL_GITHUB_READONLY_SNAPSHOT_INVALID_OR_INCOMPLETE');
});
test('DF: no CODEOWNERS and no main ruleset never count as installed',()=>{
 deny(x=>{x.governanceBefore.strictRootCoverageCodeownersFiles=0},
  'DF_EFFECTIVE_MAIN_POLICY_AND_ADMIN_READBACK_NOT_VERIFIED');
 deny(x=>{x.governanceAfter.observedStrictBypassFreeMainRulesetCount=0},
  'DF_EFFECTIVE_MAIN_POLICY_AND_ADMIN_READBACK_NOT_VERIFIED');
});
test('DF: wrong GitHub repository, release flags, duplicate receipts are not authority',()=>{
 deny(x=>{x.roleQuorumSecond.repository='attacker/repo'},
  'DF_BOTH_ROLE_BOUND_REVIEWER_RECEIPTS_REQUIRED');
 deny(x=>{x.governanceBefore.releaseDecision='GO'},
  'DF_OFFICIAL_GITHUB_READONLY_SNAPSHOT_INVALID_OR_INCOMPLETE');
});
test('DF: invalid negative, unbounded, floating counters not verified',()=>{
 for(const val of [-1,1.5,100001,null,'2'])
  deny(x=>{x.governanceBefore.observedSubmittedReviewCount=val},
   'DF_OFFICIAL_GITHUB_READONLY_SNAPSHOT_INVALID_OR_INCOMPLETE');
});
test('DF: partial role observation with one current HEAD role is not technical join',()=>{
 const x=run(v=>{v.roleQuorumFirst.businessNominatedAccountActuallyApprovedCurrentHead=false;});
 hold(x);assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,false);
});
test('DF: present real-world zero-review, zero-rules and protection 403 is HARD HOLD',()=>{
 const x=run(v=>{
  for(const y of [v.governanceBefore,v.governanceAfter]){
   y.observedDistinctCurrentHeadNonauthorApprovals=0;
   y.observedSubmittedReviewCount=0;
   y.strictRootCoverageCodeownersFiles=0;
   y.observedStrictBypassFreeMainRulesetCount=0;
   y.directMainBranchProtectionStatus='access_denied';
   y.directMainBranchProtectionExplicitly403=true;
  }
  for(const y of [v.roleQuorumFirst,v.roleQuorumSecond]){
   y.observedDistinctCurrentHeadApprovals=0;
   y.observedSubmittedReviewCount=0;
   y.securityNominatedAccountActuallyApprovedCurrentHead=false;
   y.businessNominatedAccountActuallyApprovedCurrentHead=false;
   y.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved=false;
  }
 });
 hold(x);assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,false);
 assert.equal(x.branchProtection403MeansUnknown,true);
 assert.ok(x.anomalyCodes.length>=3);
});
test('DF: report deliberately excludes reviewer names and secrets',()=>{
 const x=run();const s=JSON.stringify(x);
 assert.equal(s.includes('GITHUB_READ_TOKEN'),false);
 assert.equal(s.includes('candidate-security'),false);
 assert.equal(s.includes('candidate-business'),false);
});
test('DF: operator CLI is explicit, rejects GitHub Actions and is read-only',()=>{
 const text=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1df-role-bound-readonly-reconciliation.mjs'),'utf8');
 for(const pattern of ["process.env.GITHUB_ACTIONS==='true'","--inspect-role-approvals-readonly",
   'collectLiveActualGovernance','collectLiveReviewerEvidence','console.log(JSON.stringify(verdict'])
  assert.equal(text.includes(pattern),true,pattern);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(text),false);
});
