import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 assessTerminalReadOnlyMainAndReviewRecheck,validFinalGovernanceSnapshot,REPO
} from '../scripts/phase1di-terminal-main-review-recheck.mjs';
import {digestGithubMainPolicyReadbacks}
 from '../scripts/phase1dc-live-external-governance-readiness.mjs';

const HEAD='a'.repeat(40),MAIN='b'.repeat(40),HASH='f'.repeat(64);
const held={productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'};
function role(){
 return {phase:'1DF',schemaVersion:1,
  kind:'TWO_ACTUAL_GITHUB_ROLE_SPECIFIC_REVIEW_READS_UNTRUSTED_HUMAN_HANDOFF_HOLD',
  repository:REPO,currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
  exactSourceAndMainStableAcrossOfficialReadsOnly:true,
  candidateCrossSourceTechnicalApprovalJoinOnly:true,
  twoDistinctNominatedRolesApprovedExactHeadOnBothReadsOnly:true,
  independentGithubSummaryCountsCorroboratedOnly:true,
  effectiveBaseMainGovernanceReadableOnly:true,
  independentSecurityBusinessCorporateAppointmentsAuthenticated:false,
  authorizedProtectedMainAdminPolicyInstallationApproved:false,...held};
}
function owners(){
 return {phase:'1DG',schemaVersion:1,
  kind:'EXACT_BASE_MAIN_CODEOWNERS_PRECEDENCE_NOMINEE_MATCH_READONLY_HOLD',
  repository:REPO,pinnedBaseMainSha:MAIN,currentDevelopmentHeadSha:HEAD,
  effectiveCodeownersPath:'.github/CODEOWNERS',effectiveGitBlobSha:'c'.repeat(40),
  effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly:true,
  exactTwoNominatedAccountsInEachAcceptedRuleOnly:true,
  anomalyCodes:[],
  independentlyAuthenticatedCorporateSecurityBusinessMandates:false,
  effectiveMainRulesetOrAdminNonbypassApproved:false,...held};
}
function gov(){
 return {phase:'1DC',schemaVersion:1,
  kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
  repository:REPO,prNumber:1,currentDevelopmentHeadSha:HEAD,
  currentMainBaseSha:MAIN,officialMainRefAndDraftPrStable:true,
  officialSubmittedReviewPaginationComplete:true,
  technicallyObservedGithubPrerequisitesOnly:true,
  observedSubmittedReviewCount:2,
  observedDistinctCurrentHeadNonauthorApprovals:2,
  strictRootCoverageCodeownersFiles:1,
  observedStrictBypassFreeMainRulesetCount:1,
  directMainBranchProtectionStatus:'read',
  directMainBranchProtectionExplicitly403:false,
  unsignedMainPolicyReadbackSha256:HASH,
  unsignedSubmittedReviewHistorySha256:'d'.repeat(64),anomalyCodes:[],
  legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated:false,
  externallyAuthorizedTrustProviderMandateAndKeyEnrollment:false,...held};
}
function lastRole(){
 return {phase:'1CO',schemaVersion:1,
  kind:'REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD',
  repository:REPO,prNumber:1,base:'main',prMustRemainDraft:true,
  currentDevHead:HEAD,prReadBeforeAndAfterStable:true,
  actualGithubReviewPaginationComplete:true,
  securityNominatedAccountActuallyApprovedCurrentHead:true,
  businessNominatedAccountActuallyApprovedCurrentHead:true,
  actualNominatedReviewerWritePermissionsObserved:true,
  twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:true,
  observedSubmittedReviewCount:2,observedDistinctCurrentHeadApprovals:2,
  anomalyCodes:[],
  realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated:false,...held};
}
const inputs=()=>({
 roleJoin:role(),pinnedOwners:owners(),
 initialGovernanceBefore:gov(),initialGovernanceAfter:gov(),
 terminalGovernanceBefore:gov(),terminalNominatedReview:lastRole(),
 terminalGovernanceAfter:gov()
});
const run=f=>{const i=inputs();f?.(i);return assessTerminalReadOnlyMainAndReviewRecheck(i);};
function hold(v){
 assert.equal(v.productionReleaseAuthorized,false);
 assert.equal(v.productionReleaseBlocked,true);
 assert.equal(v.releaseDecision,'HOLD');
 assert.equal(v.independentSecurityAndBusinessCorporateMandatesVerified,false);
 assert.equal(v.realProviderWormDrOidcSlsaStagingAcceptanceVerified,false);
 assert.equal(v.canWriteMainRequestReviewMergeOrDeploy,false);
 assert.equal(v.noReviewerUsernamesOrOperatorTokenRetained,true);
 assert.equal(v.cannotProveNoInterveningEquivocationOrChangesAfterFinalRead,true);
}
function deny(change,anomaly){
 const x=run(change);hold(x);
 assert.equal(x.wholeOperatorReadWindowTechnicallyConsistentOnly,false);
 assert.ok(x.anomalyCodes.includes(anomaly),
  anomaly+' not in '+x.anomalyCodes.join(','));
 return x;
}
test('DI: all synthetic readback conditions match: transient technical yes is permanent production HOLD',()=>{
 const r=run();hold(r);
 assert.equal(r.wholeOperatorReadWindowTechnicallyConsistentOnly,true);
 assert.equal(r.unsignedPolicyFingerprint,HASH);
 assert.deepEqual(r.anomalyCodes,[]);
});
test('DI: missing input is not success and has Boolean false indicators',()=>{
 const r=assessTerminalReadOnlyMainAndReviewRecheck();hold(r);
 assert.equal(r.wholeOperatorReadWindowTechnicallyConsistentOnly,false);
 assert.equal(r.terminalNominatedReviewCountsMatchedOfficialSourceOnly,false);
 assert.equal(r.exactHeadNominatedApprovalsStillPresentAtTerminalReadOnly,false);
 assert.equal(r.unsignedPolicyFingerprint,null);
});
test('DI: original role-specific verification must have its full exact real source chain',()=>{
 deny(x=>{x.roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly=false},
  'DI_INITIAL_REAL_ROLE_BOUND_JOIN_NOT_VERIFIED');
 deny(x=>{x.roleJoin.currentDevelopmentHeadSha='bad'},
  'DI_INITIAL_REAL_ROLE_BOUND_JOIN_NOT_VERIFIED');
});
test('DI: 1DG must match same original source/base and actual pinned Git blob',()=>{
 deny(x=>{x.pinnedOwners.pinnedBaseMainSha='d'.repeat(40)},
  'DI_EXACT_PINNED_MAIN_CODEOWNERS_NOT_VERIFIED');
 deny(x=>{x.pinnedOwners.effectiveGitBlobSha='malformed'},
  'DI_EXACT_PINNED_MAIN_CODEOWNERS_NOT_VERIFIED');
 deny(x=>{x.pinnedOwners.effectiveCodeownersPath='docs/NOT-CODEOWNERS'},
  'DI_EXACT_PINNED_MAIN_CODEOWNERS_NOT_VERIFIED');
});
test('DI: main moved after pinned CODEOWNERS read is denied',()=>{
 deny(x=>{x.terminalGovernanceBefore.currentMainBaseSha='d'.repeat(40)},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
 deny(x=>{x.terminalGovernanceAfter.currentMainBaseSha='d'.repeat(40)},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
});
test('DI: source HEAD moved after initial approval or after final nominee recheck denied',()=>{
 deny(x=>{x.terminalGovernanceBefore.currentDevelopmentHeadSha='d'.repeat(40)},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
 deny(x=>{x.terminalNominatedReview.currentDevHead='d'.repeat(40)},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
});
test('DI: same-count ruleset detail changed terminal policy digest is caught',()=>{
 deny(x=>{x.terminalGovernanceAfter.unsignedMainPolicyReadbackSha256='d'.repeat(64)},
  'DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
 deny(x=>{x.terminalGovernanceBefore.unsignedMainPolicyReadbackSha256='e'.repeat(64)},
  'DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
});
test('DI: review dismissal changing approval count is detected even with same HEAD',()=>{
 deny(x=>{x.terminalGovernanceAfter.observedDistinctCurrentHeadNonauthorApprovals=1},
  'DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
 deny(x=>{x.terminalNominatedReview.businessNominatedAccountActuallyApprovedCurrentHead=false},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
});
test('DI: terminal role nominee permission revoked with two unrelated approvals is not quorum',()=>{
 deny(x=>{x.terminalNominatedReview.actualNominatedReviewerWritePermissionsObserved=false},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
 deny(x=>{x.terminalNominatedReview.securityNominatedAccountActuallyApprovedCurrentHead=false},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
});
test('DI: counts same across GitHub snapshots but terminal submitted count drift is denied',()=>{
 deny(x=>{x.terminalNominatedReview.observedSubmittedReviewCount=3},
  'DI_FINAL_ROLE_APPROVAL_COUNTS_DO_NOT_MATCH_LIVE_GITHUB');
 deny(x=>{x.terminalNominatedReview.observedDistinctCurrentHeadApprovals=3},
  'DI_FINAL_ROLE_APPROVAL_COUNTS_DO_NOT_MATCH_LIVE_GITHUB');
});
test('DI: 403 branch protection remains UNKNOWN and cannot be accepted as no bypass',()=>{
 deny(x=>{x.terminalGovernanceAfter.directMainBranchProtectionStatus='access_denied';
  x.terminalGovernanceAfter.directMainBranchProtectionExplicitly403=true},
 'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
});
test('DI: newly missing base main CODEOWNERS/ruleset never means still active',()=>{
 deny(x=>{x.terminalGovernanceBefore.strictRootCoverageCodeownersFiles=0},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
 deny(x=>{x.terminalGovernanceAfter.observedStrictBypassFreeMainRulesetCount=0},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
});
test('DI: changed rule detail with same count requires policy fingerprint equality',()=>{
 const f=inputs();
 f.terminalGovernanceBefore.unsignedMainPolicyReadbackSha256='e'.repeat(64);
 const x=assessTerminalReadOnlyMainAndReviewRecheck(f);
 hold(x);assert.equal(x.wholeOperatorReadWindowTechnicallyConsistentOnly,false);
});
test('DI: source unsigned digest missing, malformed or stale fails',()=>{
 for(const value of [null,'f'.repeat(63),'fake',false])
  deny(x=>{x.terminalGovernanceAfter.unsignedMainPolicyReadbackSha256=value},
   'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
});
test('DI: fake GO or spoofed corporate role claim is never accepted',()=>{
 deny(x=>{x.terminalGovernanceAfter.productionReleaseAuthorized=true},
  'DI_COMPLETE_ACTUAL_MAIN_PR_POLICY_READBACKS_REQUIRED');
 deny(x=>{x.terminalNominatedReview.realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated=true},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
 deny(x=>{x.roleJoin.authorizedProtectedMainAdminPolicyInstallationApproved=true},
  'DI_INITIAL_REAL_ROLE_BOUND_JOIN_NOT_VERIFIED');
});
test('DI: changed submitted total in one official read is a race',()=>{
 deny(x=>{x.initialGovernanceAfter.observedSubmittedReviewCount=3},
  'DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
});
test('DI: terminal reviewer source must remain stable, with full pagination and no anomalies',()=>{
 deny(x=>{x.terminalNominatedReview.prReadBeforeAndAfterStable=false},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
 deny(x=>{x.terminalNominatedReview.actualGithubReviewPaginationComplete=false},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
 deny(x=>{x.terminalNominatedReview.anomalyCodes=['MALFORMED']},
  'DI_TERMINAL_DISTINCT_ROLE_SPECIFIC_APPROVALS_NOT_VERIFIED');
});
test('DI: full policy digest changes when ruleset bypass actor changes but counts stay same',()=>{
 const src={
  rulesets:{status:'read',data:[{id:1,target:'branch'}],complete:true},
  rulesetDetails:{'1':{status:'read',data:{id:1,bypass_actors:[]}}},
  codeowners:{
   githubCodeowners:{status:'read',data:{path:'.github/CODEOWNERS',content:'base64'}},
   rootCodeowners:{status:'absent_or_hidden',data:null},
   docsCodeowners:{status:'absent_or_hidden',data:null}
  },
  protection:{status:'read',data:{enforce_admins:{enabled:true}}}
 };
 const a=digestGithubMainPolicyReadbacks(src);
 assert.match(a,/^[0-9a-f]{64}$/);
 src.rulesetDetails['1'].data.bypass_actors.push({actor_type:'OrganizationAdmin'});
 const b=digestGithubMainPolicyReadbacks(src);
 assert.match(b,/^[0-9a-f]{64}$/);
 assert.notEqual(a,b);
});
test('DI: full policy digest detects CODEOWNERS text swap and branch protection toggle',()=>{
 const x={
  rulesets:{status:'read',data:[],complete:true},
  rulesetDetails:{},
  codeowners:{
   githubCodeowners:{status:'read',data:{sha:'a',content:'old'}},
   rootCodeowners:{status:'absent_or_hidden',data:null},
   docsCodeowners:{status:'absent_or_hidden',data:null}
  },
  protection:{status:'read',data:{enforce_admins:{enabled:true}}}
 };
 const a=digestGithubMainPolicyReadbacks(x);
 x.codeowners.githubCodeowners.data.content='new';
 const b=digestGithubMainPolicyReadbacks(x);
 x.protection.data.enforce_admins.enabled=false;
 const c=digestGithubMainPolicyReadbacks(x);
 assert.notEqual(a,b);assert.notEqual(b,c);
});
test('DI: malformed, incomplete or circular policy sources fail SHA generation',()=>{
 assert.equal(digestGithubMainPolicyReadbacks({}),null);
 const x={rulesets:{},rulesetDetails:{},codeowners:{
   githubCodeowners:{},rootCodeowners:{},docsCodeowners:{}
  },protection:{}};
 x.rulesets.self=x;
 assert.equal(digestGithubMainPolicyReadbacks(x),null);
});
test('DI: fingerprints disclose no reviewer identities, token, policy JSON or actual approval',()=>{
 const output=JSON.stringify(run());
 for(const needle of ['Bearer ','GITHUB_READ_TOKEN','officer-security','private-policy-content'])
  assert.equal(output.includes(needle),false);
 const a=run();assert.equal(a.canWriteMainRequestReviewMergeOrDeploy,false);
});
test('DI: 1DG operator after pinned CODEOWNERS explicitly invokes final 1DC/1CO/1DC reads; no HTTP writes',()=>{
 const file=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dg-effective-codeowners.mjs'),'utf8');
 const pos=file.indexOf('const observedFirst=await take(),observedSecond=await take();');
 const after=file.indexOf('const terminalGovernanceBefore=await collectLiveActualGovernance');
 const reviewer=file.indexOf('const terminalNominatedReview=await collectLiveReviewerEvidence');
 const end=file.indexOf('const terminalGovernanceAfter=await collectLiveActualGovernance');
 assert.ok(pos>0&&after>pos&&reviewer>after&&end>reviewer);
 assert.match(file,/terminal\.wholeOperatorReadWindowTechnicallyConsistentOnly/);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(file),false);
});
