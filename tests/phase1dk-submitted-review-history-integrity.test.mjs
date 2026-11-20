import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 digestOfficialSubmittedReviewHistory,MAX_REVIEW_EVENTS,
 MAX_REVIEW_CANONICAL_BYTES,REVIEW_HISTORY_DOMAIN
} from '../scripts/phase1dk-submitted-review-history-integrity.mjs';
import {assessActualReadOnlyHandoff}
 from '../scripts/phase1dc-live-external-governance-readiness.mjs';
import {assessTerminalReadOnlyMainAndReviewRecheck,REPO}
 from '../scripts/phase1di-terminal-main-review-recheck.mjs';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),H='d'.repeat(64),PH='f'.repeat(64);
const held={productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'};
function reviews(){
 return {status:'read',complete:true,data:[
  {id:100,user:{login:'security-appointee'},state:'APPROVED',commit_id:HEAD,
   submitted_at:'2026-11-20T06:00:00Z',body:'never expose free text'},
  {id:101,user:{login:'business-appointee'},state:'APPROVED',commit_id:HEAD,
   submitted_at:'2026-11-20T06:01:00Z'},
  {id:102,user:{login:'incidental-reviewer'},state:'COMMENTED',commit_id:HEAD,
   submitted_at:'2026-11-20T06:02:00Z'}
 ]};
}
const digest=r=>digestOfficialSubmittedReviewHistory({reviews:r,head:HEAD});
function preflight(r){
 const v=assessActualReadOnlyHandoff({
  prBefore:{status:'read',data:{head:{sha:HEAD}}},
  reviews:r
 });
 assert.equal(v.productionReleaseAuthorized,false);
 assert.equal(v.productionReleaseBlocked,true);
 assert.equal(v.releaseDecision,'HOLD');
 return v;
}
function role(){
 return {phase:'1DF',schemaVersion:1,
  kind:'TWO_ACTUAL_GITHUB_ROLE_SPECIFIC_REVIEW_READS_UNTRUSTED_HUMAN_HANDOFF_HOLD',
  repository:REPO,currentDevelopmentHeadSha:HEAD,currentMainBaseSha:BASE,
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
  repository:REPO,pinnedBaseMainSha:BASE,currentDevelopmentHeadSha:HEAD,
  effectiveCodeownersPath:'.github/CODEOWNERS',
  effectiveGitBlobSha:'c'.repeat(40),
  effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly:true,
  exactTwoNominatedAccountsInEachAcceptedRuleOnly:true,
  anomalyCodes:[],
  independentlyAuthenticatedCorporateSecurityBusinessMandates:false,
  effectiveMainRulesetOrAdminNonbypassApproved:false,...held};
}
function governance(){
 return {phase:'1DC',schemaVersion:1,
  kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
  repository:REPO,prNumber:1,currentDevelopmentHeadSha:HEAD,
  currentMainBaseSha:BASE,officialMainRefAndDraftPrStable:true,
  officialSubmittedReviewPaginationComplete:true,
  technicallyObservedGithubPrerequisitesOnly:true,
  observedSubmittedReviewCount:3,
  observedDistinctCurrentHeadNonauthorApprovals:2,
  strictRootCoverageCodeownersFiles:1,
  observedStrictBypassFreeMainRulesetCount:1,
  directMainBranchProtectionStatus:'read',
  directMainBranchProtectionExplicitly403:false,
  unsignedMainPolicyReadbackSha256:PH,
  unsignedSubmittedReviewHistorySha256:H,
  anomalyCodes:[],
  legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated:false,
  externallyAuthorizedTrustProviderMandateAndKeyEnrollment:false,...held};
}
function terminal(){
 return {phase:'1CO',schemaVersion:1,
  kind:'REAL_EXPLICIT_TWO_GITHUB_REVIEWER_CURRENT_HEAD_TECHNICAL_RECEIPT_HOLD',
  repository:REPO,prNumber:1,base:'main',prMustRemainDraft:true,
  currentDevHead:HEAD,prReadBeforeAndAfterStable:true,
  actualGithubReviewPaginationComplete:true,
  securityNominatedAccountActuallyApprovedCurrentHead:true,
  businessNominatedAccountActuallyApprovedCurrentHead:true,
  actualNominatedReviewerWritePermissionsObserved:true,
  twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:true,
  observedSubmittedReviewCount:3,observedDistinctCurrentHeadApprovals:2,
  anomalyCodes:[],
  realLegalSecurityAndBusinessMandatesIndependentlyAuthenticated:false,...held};
}
const positive=()=>({
 roleJoin:role(),pinnedOwners:owners(),
 initialGovernanceBefore:governance(),initialGovernanceAfter:governance(),
 terminalGovernanceBefore:governance(),terminalNominatedReview:terminal(),
 terminalGovernanceAfter:governance()
});
function hold(v){
 assert.equal(v.productionReleaseAuthorized,false);
 assert.equal(v.productionReleaseBlocked,true);
 assert.equal(v.releaseDecision,'HOLD');
}
function bad(change,code='DK_OFFICIAL_SUBMITTED_REVIEW_HISTORY_CHANGED_OR_UNREADABLE'){
 const x=positive();change(x);
 const r=assessTerminalReadOnlyMainAndReviewRecheck(x);
 hold(r);
 assert.equal(r.wholeOperatorReadWindowTechnicallyConsistentOnly,false);
 assert.equal(r.unsignedReviewHistoryFingerprint,null);
 assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join('|'));
}
test('DK canonical exact-HEAD 3-review fingerprint is a SHA-256 digest, never a signature',()=>{
 const hash=digest(reviews());
 assert.match(hash,/^[0-9a-f]{64}$/);
 assert.equal(hash.length,64);
 assert.equal(hash.includes('security-appointee'),false);
 assert.equal(REVIEW_HISTORY_DOMAIN.startsWith('AADI-1DK-'),true);
});
test('DK identical review events in different GitHub pagination order hash identically',()=>{
 const a=reviews(),b=reviews();
 b.data.reverse();
 assert.equal(digest(a),digest(b));
});
test('DK same submitted and current-head approval counts, COMMENTED->DISMISSED changes digest',()=>{
 const a=reviews(),b=reviews();
 b.data[2].state='DISMISSED';
 assert.notEqual(digest(a),digest(b));
 assert.equal(a.data.length,b.data.length);
});
test('DK same count and approvals but unrelated review commit SHA changes digest',()=>{
 const a=reviews(),b=reviews();
 b.data[2].commit_id='9'.repeat(40);
 assert.notEqual(digest(a),digest(b));
});
test('DK same count/approvals but review submission timestamp changes digest',()=>{
 const a=reviews(),b=reviews();
 b.data[2].submitted_at='2026-11-20T06:05:00Z';
 assert.notEqual(digest(a),digest(b));
});
test('DK same count/approvals but third reviewer identity changes digest',()=>{
 const a=reviews(),b=reviews();
 b.data[2].user.login='different-reviewer';
 assert.notEqual(digest(a),digest(b));
});
test('DK same count/approvals but GitHub review ID changes digest',()=>{
 const a=reviews(),b=reviews();
 b.data[2].id=500;
 assert.notEqual(digest(a),digest(b));
});
test('DK response text / review prose is excluded; decision history still bound',()=>{
 const a=reviews(),b=reviews();
 b.data[0].body='text that must not enter the hash preimage';
 assert.equal(digest(a),digest(b));
});
test('DK case-insensitive GitHub username canonicalization avoids false drift',()=>{
 const a=reviews(),b=reviews();
 b.data[1].user.login='BUSINESS-APPOINTEE';
 assert.equal(digest(a),digest(b));
});
test('DK adding a pending review changes full event history even if approved count unchanged',()=>{
 const a=reviews(),b=reviews();
 b.data.push({id:300,user:{login:'pending-reviewer'},state:'PENDING',
  submitted_at:null,commit_id:null});
 assert.notEqual(digest(a),digest(b));
});
test('DK exact HEAD changes digest for otherwise identical history',()=>{
 const a=digest(reviews());
 const b=digestOfficialSubmittedReviewHistory({
  reviews:reviews(),head:'9'.repeat(40)
 });
 assert.match(b,/^[0-9a-f]{64}$/);
 assert.notEqual(a,b);
});
test('DK 403 UNKNOWN, truncated pagination and unavailable status never become signed proof',()=>{
 for(const mutate of [
  r=>r.status='access_denied',
  r=>r.status='unavailable',
  r=>r.complete=false,
  r=>r.data=null
 ]){const r=reviews();mutate(r);assert.equal(digest(r),null);}
});
test('DK untrusted or malformed HEAD cannot be treated as current review source',()=>{
 for(const head of [null,'bad','f'.repeat(39),'F'.repeat(40)]){
  assert.equal(digestOfficialSubmittedReviewHistory({reviews:reviews(),head}),null);
 }
});
test('DK duplicate GitHub review ID denied before canonical projection',()=>{
 const r=reviews();r.data[2].id=r.data[1].id;
 assert.equal(digest(r),null);
});
test('DK invalid review state, unknown account and missing user fail closed',()=>{
 for(const mutate of [
  r=>{r.data[2].state='INSTANT_APPROVED';},
  r=>{r.data[2].user.login='bad user';},
  r=>{delete r.data[2].user;},
  r=>{r.data[2].state='PENDING';r.data[2].submitted_at='2026-11-20T00:00:00Z';}
 ]){const r=reviews();mutate(r);assert.equal(digest(r),null);}
});
test('DK malformed timestamp or commit ID never yields valid SHA',()=>{
 for(const mutate of [
  r=>{r.data[2].commit_id='not-sha';},
  r=>{r.data[2].submitted_at='yesterday';},
  r=>{r.data[2].submitted_at=null;}
 ]){const r=reviews();mutate(r);assert.equal(digest(r),null);}
});
test('DK malformed metadata, missing or oversize event array denied',()=>{
 assert.equal(digestOfficialSubmittedReviewHistory({}),null);
 assert.equal(digest({status:'read',complete:true,data:{}}),null);
 assert.equal(digest({status:'read',complete:true,data:Array.from({length:300},(_,i)=>({
  id:i+1,user:{login:'test-'+i},state:'PENDING',
  submitted_at:null,commit_id:null
 }))}),null);
 assert.equal(MAX_REVIEW_EVENTS,299);
 assert.equal(MAX_REVIEW_CANONICAL_BYTES,131072);
});
test('DK actual 1DC report includes exact review digest with permanent HOLD',()=>{
 const x=reviews(),f=preflight(x);
 assert.equal(f.unsignedSubmittedReviewHistorySha256,digest(x));
 hold(f);
 assert.equal(f.technicallyObservedGithubPrerequisitesOnly,false);
});
test('DK 1DC report changes fingerprint despite identical submitted/approval counts',()=>{
 const a=reviews(),b=reviews();b.data[2].state='DISMISSED';
 const r1=preflight(a),r2=preflight(b);
 assert.equal(r1.observedSubmittedReviewCount,r2.observedSubmittedReviewCount);
 assert.equal(r1.observedDistinctCurrentHeadNonauthorApprovals,
  r2.observedDistinctCurrentHeadNonauthorApprovals);
 assert.notEqual(r1.unsignedSubmittedReviewHistorySha256,
  r2.unsignedSubmittedReviewHistorySha256);
});
test('DK four-source synthetic perfect technical receipt is still HOLD, no corporate mandate',()=>{
 const r=assessTerminalReadOnlyMainAndReviewRecheck(positive());hold(r);
 assert.equal(r.wholeOperatorReadWindowTechnicallyConsistentOnly,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly,true);
 assert.equal(r.unsignedReviewHistoryFingerprint,H);
 assert.equal(r.independentSecurityAndBusinessCorporateMandatesVerified,false);
});
test('DK same-count changed review history in first post CODEOWNERS read fails',()=>{
 bad(x=>{x.terminalGovernanceBefore.unsignedSubmittedReviewHistorySha256='e'.repeat(64)});
});
test('DK same-count changed review history in final governance read fails',()=>{
 bad(x=>{x.terminalGovernanceAfter.unsignedSubmittedReviewHistorySha256='e'.repeat(64)});
});
test('DK same-count swapped history in earlier first governance read fails',()=>{
 bad(x=>{x.initialGovernanceBefore.unsignedSubmittedReviewHistorySha256='e'.repeat(64)});
});
test('DK same-count swapped history in earlier second governance read fails',()=>{
 bad(x=>{x.initialGovernanceAfter.unsignedSubmittedReviewHistorySha256='e'.repeat(64)});
});
test('DK missing/invalid unsigned historical digest triggers fail-closed 1DI receipt',()=>{
 for(const v of [null,undefined,'bad','f'.repeat(63),false])
  bad(x=>{x.terminalGovernanceAfter.unsignedSubmittedReviewHistorySha256=v});
});
test('DK a changed policy SHA is still independently rejected even when reviews stable',()=>{
 bad(x=>{x.terminalGovernanceAfter.unsignedMainPolicyReadbackSha256='e'.repeat(64)},
  'DI_MAIN_POLICY_DIGEST_OR_HEAD_APPROVAL_COUNTS_CHANGED');
});
test('DK reported receipt omits raw review usernames, bodies and operator secrets',()=>{
 const output=JSON.stringify(assessTerminalReadOnlyMainAndReviewRecheck(positive()));
 for(const secret of ['security-appointee','business-appointee','never expose free text','GITHUB_READ_TOKEN'])
  assert.equal(output.includes(secret),false);
});
test('DK no source/workflow writes or independent authority spoof introduced',()=>{
 const here=dirname(fileURLToPath(import.meta.url));
 for(const file of [
  '../scripts/phase1dk-submitted-review-history-integrity.mjs',
  '../scripts/phase1di-terminal-main-review-recheck.mjs'
 ]){
  const src=readFileSync(resolve(here,file),'utf8');
  assert.equal(/method:\s*['"](?:POST|PATCH|PUT|DELETE)['"]/.test(src),false);
 }
 const v=assessTerminalReadOnlyMainAndReviewRecheck(positive());
 hold(v);assert.equal(v.canWriteMainRequestReviewMergeOrDeploy,false);
});
