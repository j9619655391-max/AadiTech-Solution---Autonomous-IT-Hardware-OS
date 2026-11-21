import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 deriveEphemeralReviewerRoleBinding,
 assessEphemeralReviewerHandoffContinuity,DOMAIN
} from '../scripts/phase1dl-ephemeral-reviewer-handoff-continuity.mjs';
import {assessRealNonauthorApprovalQuorum}
 from '../scripts/phase1co-live-exact-head-reviewer-quorum.mjs';
import {assessRoleBoundReadOnlyReconciliation}
 from '../scripts/phase1df-role-bound-readonly-reconciliation.mjs';
import {assessPinnedMainCodeowners,CODEOWNERS_PRECEDENCE}
 from '../scripts/phase1dg-effective-codeowners.mjs';
import {assessTerminalReadOnlyMainAndReviewRecheck}
 from '../scripts/phase1di-terminal-main-review-recheck.mjs';
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const HEAD='a'.repeat(40),MAIN='b'.repeat(40),MERGE='c'.repeat(40);
const KEY=Buffer.alloc(32,0x11),ALT=Buffer.alloc(32,0x22);
const SEC='security-reviewer',BUS='business-reviewer';
const held={productionReleaseAuthorized:false,
 productionReleaseBlocked:true,releaseDecision:'HOLD'};
const p=(login)=>({status:'read',data:{user:{login},permission:'write'}});
const PR=()=>({
 number:1,state:'open',draft:true,merged:false,
 user:{login:'j9619655391-max'},merge_commit_sha:MERGE,
 updated_at:'2026-11-20T13:00:00Z',
 head:{ref:'chore/phase0-foundation-20261106',
  sha:HEAD,repo:{full_name:REPO}},
 base:{ref:'main',sha:MAIN,repo:{full_name:REPO}}
});
const review=(login,id,time)=>({
 id,state:'APPROVED',commit_id:HEAD,
 submitted_at:time,user:{login}
});
const q=(key=KEY,sec=SEC,bus=BUS)=>assessRealNonauthorApprovalQuorum({
 securityLogin:sec,businessLogin:bus,
 prBefore:PR(),prAfter:PR(),
 reviews:[review(SEC,11,'2026-11-20T12:00:00Z'),
  review(BUS,12,'2026-11-20T12:01:00Z')],
 reviewPaginationComplete:true,
 securityPermission:p(sec),businessPermission:p(bus),
 nomineeSessionKey:key
});
const gov=()=>({
 phase:'1DC',schemaVersion:1,
 kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
 repository:REPO,prNumber:1,
 officialMainRefAndDraftPrStable:true,
 currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
 officialSubmittedReviewPaginationComplete:true,
 technicallyObservedGithubPrerequisitesOnly:true,
 observedSubmittedReviewCount:2,
 observedDistinctCurrentHeadNonauthorApprovals:2,
 strictRootCoverageCodeownersFiles:1,
 observedStrictBypassFreeMainRulesetCount:1,
 directMainBranchProtectionStatus:'read',
 directMainBranchProtectionExplicitly403:false,
 unsignedMainPolicyReadbackSha256:'d'.repeat(64),
 unsignedSubmittedReviewHistorySha256:'e'.repeat(64),
 anomalyCodes:[],
 legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated:false,
 externallyAuthorizedTrustProviderMandateAndKeyEnrollment:false,...held
});
function owners(join){
 const ownerText='* @security-reviewer @business-reviewer\n'+
  '/.github/CODEOWNERS @security-reviewer @business-reviewer\n';
 const blob=(path)=>{
  const bytes=Buffer.from(ownerText);
  return {status:'read',data:{
   type:'file',path,encoding:'base64',size:bytes.length,
   sha:createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0'))
    .update(bytes).digest('hex'),
   content:bytes.toString('base64')
  }};
 };
 const first=Object.fromEntries(CODEOWNERS_PRECEDENCE.map(path=>[
  path,path==='.github/CODEOWNERS'?blob(path):
   {status:'absent_or_hidden',data:null}
 ]));
 return assessPinnedMainCodeowners({
  roleJoin:join,securityLogin:SEC,businessLogin:BUS,
  observedFirst:first,observedSecond:structuredClone(first)
 });
}
function full(){
 const roleQuorumFirst=q(),roleQuorumSecond=q();
 const gb=gov(),ga=gov();
 const roleJoin=assessRoleBoundReadOnlyReconciliation({
  governanceBefore:gb,roleQuorumFirst,roleQuorumSecond,governanceAfter:ga,
  requireRoleContinuity:true
 });
 const pinnedOwners=owners(roleJoin);
 const terminalNominatedReview=q();
 const terminalReadback=assessTerminalReadOnlyMainAndReviewRecheck({
  roleJoin,pinnedOwners,
  initialGovernanceBefore:gb,initialGovernanceAfter:ga,
  terminalGovernanceBefore:gov(),terminalNominatedReview,
  terminalGovernanceAfter:gov()
 });
 return {sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  roleQuorumFirst,roleQuorumSecond,roleJoin,pinnedOwners,
  terminalNominatedReview,terminalReadback};
}
const evaluate=(change)=>{
 const x=full();
 // Source assessors freeze their authentic receipts. Adversarial tests
 // explicitly clone those receipts before simulating tampering.
 for(const k of ['roleQuorumFirst','roleQuorumSecond','roleJoin',
  'pinnedOwners','terminalNominatedReview','terminalReadback'])
  x[k]={...x[k]};
 change?.(x);
 return assessEphemeralReviewerHandoffContinuity(x);
};
function hold(v){
 assert.equal(v.productionReleaseAuthorized,false);
 assert.equal(v.productionReleaseBlocked,true);
 assert.equal(v.releaseDecision,'HOLD');
 if(v.phase==='1DL'){
  assert.equal(v.independentCorporateOfficerAppointmentsOrMandatesAuthenticated,false);
  assert.equal(v.externalSignerKeysAndMcaCaWormDrOidcStagingVerified,false);
  assert.equal(v.canInstallMainPolicyRequestReviewsMergeOrDeploy,false);
  assert.equal(v.opaqueSessionKeyAndReviewerIdentityExcludedFromOutput,true);
 }
}
function reject(change,code){
 const v=evaluate(change);hold(v);
 assert.equal(v.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly,false);
 assert.ok(v.anomalyCodes.includes(code),v.anomalyCodes.join(' | '));
 return v;
}
test('DL operator-session SHA-256 HMAC is 64 hex, raw usernames not in digest',()=>{
 const h=deriveEphemeralReviewerRoleBinding({
  sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN
 });
 assert.match(h,/^[0-9a-f]{64}$/);
 assert.equal(h.includes(SEC),false);
 assert.equal(DOMAIN.startsWith('AADI-1DL-'),true);
});
test('DL identical logins case variants yield stable in-session binding',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 const a=deriveEphemeralReviewerRoleBinding(args);
 const b=deriveEphemeralReviewerRoleBinding({
  ...args,securityLogin:SEC.toUpperCase(),businessLogin:BUS.toUpperCase()
 });
 assert.equal(a,b);
});
test('DL swapped Security and Business roles do not share the same binding',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 assert.notEqual(deriveEphemeralReviewerRoleBinding(args),
  deriveEphemeralReviewerRoleBinding({
   ...args,securityLogin:BUS,businessLogin:SEC
  }));
});
test('DL different operator sessions create unlinkable commitments',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 assert.notEqual(deriveEphemeralReviewerRoleBinding(args),
  deriveEphemeralReviewerRoleBinding({...args,sessionKey:ALT}));
});
test('DL source HEAD drift changes nominee commitment even if names unchanged',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 assert.notEqual(deriveEphemeralReviewerRoleBinding(args),
  deriveEphemeralReviewerRoleBinding({...args,currentDevHeadSha:'f'.repeat(40)}));
});
test('DL base main drift changes nominee commitment even if PR head unchanged',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 assert.notEqual(deriveEphemeralReviewerRoleBinding(args),
  deriveEphemeralReviewerRoleBinding({...args,currentMainBaseSha:'f'.repeat(40)}));
});
test('DL malformed/non-32-byte/weak key or bad reviewer identity returns null',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 for(const v of [null,'33'.repeat(32),Buffer.alloc(31),
  Buffer.alloc(33),new Uint8Array(32)]){
  assert.equal(deriveEphemeralReviewerRoleBinding({...args,sessionKey:v}),null);
 }
 for(const [a,b] of [[SEC,SEC],[SEC,SEC.toUpperCase()],
  ['j9619655391-max',BUS],['bad login',BUS],['',BUS]]){
  assert.equal(deriveEphemeralReviewerRoleBinding({
   ...args,securityLogin:a,businessLogin:b
  }),null);
 }
});
test('DL malformed/uppercase SHA source or base fails before HMAC creation',()=>{
 const args={sessionKey:KEY,securityLogin:SEC,businessLogin:BUS,
  currentDevHeadSha:HEAD,currentMainBaseSha:MAIN};
 for(const sha of ['',null,'a'.repeat(39),'A'.repeat(40)]){
  assert.equal(deriveEphemeralReviewerRoleBinding({...args,currentDevHeadSha:sha}),null);
  assert.equal(deriveEphemeralReviewerRoleBinding({...args,currentMainBaseSha:sha}),null);
 }
});
test('DL 1CO actual signed-in technical reviewer evaluator returns role binding only when operator key present',()=>{
 const original=q();hold(original);
 assert.equal(original.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,true);
 assert.match(original.opaqueReviewerRoleSessionHmacSha256,/^[a-f0-9]{64}$/);
 const noKey=q(null);hold(noKey);
 assert.equal(noKey.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,true);
 assert.equal(noKey.opaqueReviewerRoleSessionHmacSha256,null);
});
test('DL 1CO disapproved nominated review never yields a technical HMAC',()=>{
 const r=assessRealNonauthorApprovalQuorum({
  securityLogin:SEC,businessLogin:BUS,
  prBefore:PR(),prAfter:PR(),reviews:[review(SEC,11,'2026-11-20T12:00:00Z')],
  reviewPaginationComplete:true,
  securityPermission:p(SEC),businessPermission:p(BUS),nomineeSessionKey:KEY
 });
 assert.equal(r.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved,false);
 assert.equal(r.opaqueReviewerRoleSessionHmacSha256,null);
 hold(r);
});
test('DL 1DF strict human-role gate rejects same-count second read with different session binding',()=>{
 const one=q(),two=q(ALT);
 const x=assessRoleBoundReadOnlyReconciliation({
  governanceBefore:gov(),roleQuorumFirst:one,roleQuorumSecond:two,
  governanceAfter:gov(),requireRoleContinuity:true
 });
 hold(x);
 assert.equal(x.roleBoundNomineeContinuityOnly,false);
 assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,false);
 assert.ok(x.anomalyCodes.includes('DL_TWO_REAL_ROLE_APPROVAL_READS_NOT_SAME_NOMINEE_SESSION'));
});
test('DL 1DF strict human-role gate requires actual opaque binding and denies old unbound booleans',()=>{
 const one=q(null),two=q(null);
 const x=assessRoleBoundReadOnlyReconciliation({
  governanceBefore:gov(),roleQuorumFirst:one,roleQuorumSecond:two,
  governanceAfter:gov(),requireRoleContinuity:true
 });
 hold(x);assert.equal(x.candidateCrossSourceTechnicalApprovalJoinOnly,false);
 assert.equal(x.opaqueReviewerRoleSessionHmacSha256,null);
});
test('DL valid synthetic 1CO/1DF/1DG/1DI chain remains entirely untrusted corporate HOLD',()=>{
 const f=full();
 assert.equal(f.roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly,true,
  f.roleJoin.anomalyCodes.join(','));
 assert.equal(f.pinnedOwners.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,true,
  f.pinnedOwners.anomalyCodes.join(','));
 assert.equal(f.terminalReadback.wholeOperatorReadWindowTechnicallyConsistentOnly,true,
  f.terminalReadback.anomalyCodes.join(','));
 const a=assessEphemeralReviewerHandoffContinuity(f);hold(a);
 assert.equal(a.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly,true,
  a.anomalyCodes.join(','));
 assert.equal(a.operatorSessionNomineePairBoundAcrossReadsOnly,true);
 assert.equal(a.cannotBeIndependentlyReplayedWithoutOriginalSessionKey,true);
 assert.deepEqual(a.anomalyCodes,[]);
});
test('DL missing operator key refuses all forged booleans and technically passing snapshots',()=>{
 reject(x=>{x.sessionKey=null},
  'DL_DISTINCT_AUTHORIZED_ROLE_PAIR_OR_SESSION_KEY_INVALID');
});
test('DL mismatched session key is not rescued by identical review decision counts',()=>{
 reject(x=>{x.sessionKey=ALT},'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL swapped role inputs are not rescued by CODEOWNERS wildcard membership',()=>{
 reject(x=>{x.securityLogin=BUS;x.businessLogin=SEC},
  'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL different terminal Security/Business pair is denied despite same approvals',()=>{
 reject(x=>{x.terminalNominatedReview.opaqueReviewerRoleSessionHmacSha256=
  deriveEphemeralReviewerRoleBinding({sessionKey:KEY,
   securityLogin:BUS,businessLogin:SEC,
   currentDevHeadSha:HEAD,currentMainBaseSha:MAIN})},
  'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL first-role receipt substituted from earlier operator session denied',()=>{
 reject(x=>{x.roleQuorumFirst.opaqueReviewerRoleSessionHmacSha256=q(ALT).opaqueReviewerRoleSessionHmacSha256},
  'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL second-role receipt substituted from another operator session denied',()=>{
 reject(x=>{x.roleQuorumSecond.opaqueReviewerRoleSessionHmacSha256=q(ALT).opaqueReviewerRoleSessionHmacSha256},
  'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL original 1DF role-join substituted with different HMAC denied',()=>{
 reject(x=>{x.roleJoin.opaqueReviewerRoleSessionHmacSha256='f'.repeat(64)},
  'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
});
test('DL terminal fake approvals/no actual write permission fail even if HMAC equal',()=>{
 reject(x=>{x.terminalNominatedReview.businessNominatedAccountActuallyApprovedCurrentHead=false},
  'DL_ALL_THREE_SOURCE_BOUND_NOMINEE_READS_REQUIRED');
 reject(x=>{x.terminalNominatedReview.actualNominatedReviewerWritePermissionsObserved=false},
  'DL_ALL_THREE_SOURCE_BOUND_NOMINEE_READS_REQUIRED');
});
test('DL stale or head-substituted terminal reviewer evidence cannot pass role binding',()=>{
 reject(x=>{x.terminalNominatedReview.currentDevHead='f'.repeat(40)},
  'DL_ALL_THREE_SOURCE_BOUND_NOMINEE_READS_REQUIRED');
 reject(x=>{x.terminalNominatedReview.prReadBeforeAndAfterStable=false},
  'DL_ALL_THREE_SOURCE_BOUND_NOMINEE_READS_REQUIRED');
});
test('DL invalid 1DF role-join or missing main protection cannot pass',()=>{
 reject(x=>{x.roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly=false},
  'DL_INITIAL_ROLE_BOUND_HANDOFF_MISSING');
 reject(x=>{x.roleJoin.effectiveBaseMainGovernanceReadableOnly=false},
  'DL_INITIAL_ROLE_BOUND_HANDOFF_MISSING');
});
test('DL pinned CODEOWNERS different source/main or missing effective coverage fails',()=>{
 reject(x=>{x.pinnedOwners.currentDevelopmentHeadSha='f'.repeat(40)},
  'DL_PINNED_CODEOWNER_NOMINEE_BINDING_NOT_VERIFIED');
 reject(x=>{x.pinnedOwners.exactTwoNominatedAccountsInEachAcceptedRuleOnly=false},
  'DL_PINNED_CODEOWNER_NOMINEE_BINDING_NOT_VERIFIED');
});
test('DL terminal 1DI policy/review-history/MAIN consistency is mandatory',()=>{
 reject(x=>{x.terminalReadback.reviewDecisionHistoryFingerprintStableAcrossFourReadsOnly=false},
  'DL_FINAL_MAIN_POLICY_REVIEW_HISTORY_HOLD_MISSING');
 reject(x=>{x.terminalReadback.wholeOperatorReadWindowTechnicallyConsistentOnly=false},
  'DL_FINAL_MAIN_POLICY_REVIEW_HISTORY_HOLD_MISSING');
 reject(x=>{x.terminalReadback.checkedBaseMainSha='f'.repeat(40)},
  'DL_FINAL_MAIN_POLICY_REVIEW_HISTORY_HOLD_MISSING');
});
test('DL producer HMAC format validation denies malformed, uppercase and absent receipts',()=>{
 for(const value of [null,'bad','f'.repeat(63),'F'.repeat(64)]){
  reject(x=>{x.terminalNominatedReview.opaqueReviewerRoleSessionHmacSha256=value},
   'DL_NOMINEE_ROLE_PAIR_CHANGED_OR_UNBOUND');
 }
});
test('DL no real corporate Security/Business mandate or external authority can be derived from passing mock',()=>{
 const v=evaluate();hold(v);
 assert.equal(v.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly,true);
 assert.equal(v.independentCorporateOfficerAppointmentsOrMandatesAuthenticated,false);
 assert.equal(v.externalSignerKeysAndMcaCaWormDrOidcStagingVerified,false);
});
test('DL HMAC key, raw logins, review bodies, Bearer token excluded from receipt',()=>{
 const f=full(),v=assessEphemeralReviewerHandoffContinuity(f);
 const out=JSON.stringify(v);
 for(const x of [SEC,BUS,'Bearer','GITHUB_READ_TOKEN','security-reviewer','business-reviewer'])
  assert.equal(out.includes(x),false);
 assert.equal(out.includes(KEY.toString('hex')),false);
});
test('DL human 1DG entrypoint uses same ephemeral key for three actual reviewer reads and terminal no-GO',()=>{
 const file=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dg-effective-codeowners.mjs'),'utf8');
 assert.ok(file.includes('const sessionKey=randomBytes(32)'));
 assert.ok(file.includes('requireRoleContinuity:true'));
 assert.ok(file.includes('assessEphemeralReviewerHandoffContinuity({'));
 assert.ok(file.includes('!continuity.technicalSameNomineesAcrossEntireOperatorReadOnlySessionOnly'));
 const count=(file.match(/nomineeSessionKey:sessionKey/g)||[]).length;
 assert.equal(count,3);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(file),false);
});

test('DL stand-alone human 1DF report removes opaque HMAC before logging',()=>{
 const src=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1df-role-bound-readonly-reconciliation.mjs'),'utf8');
 assert.ok(src.includes('opaqueReviewerRoleSessionHmacSha256:_privateBinding'));
 assert.ok(src.includes('console.log(JSON.stringify(safeReceipt,null,2))'));
 assert.equal(src.includes('console.log(JSON.stringify(verdict,null,2))'),false);
});
