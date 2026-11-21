import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {REPO,proposedCodeowners}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {
 assessExactAppliedMainRuleset,assessNominatedMainCodeowners,
 assessIndependentGovernanceHandoff,readMainRefOnly,
 verifyIndependentGovernanceHandoff
} from '../scripts/phase1cu-independent-governance-handoff.mjs';

const A='security-operator',B='business-operator';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const API='https://api.github.com/repos/'+REPO;
const PROPOSAL=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const fakePr=()=>({
 number:1,state:'open',draft:true,merged:false,
 updated_at:'2026-11-19T00:00:00Z',merge_commit_sha:MERGE,
 user:{login:'j9619655391-max'},
 head:{ref:'chore/phase0-foundation-20261106',sha:HEAD,
  repo:{full_name:REPO}},
 base:{ref:'main',sha:BASE,repo:{full_name:REPO}}
});
function base64File(body){
 const buffer=Buffer.from(body,'utf8');
 return {status:'read',data:{
  type:'file',path:'.github/CODEOWNERS',encoding:'base64',
  size:buffer.byteLength,content:buffer.toString('base64'),
  sha:createHash('sha1').update(
   Buffer.concat([Buffer.from('blob '+buffer.length+'\0'),buffer])).digest('hex')
 }};
}
const ref=()=>({ref:'refs/heads/main',
 object:{type:'commit',sha:BASE,url:API+'/git/commits/'+BASE}});
function fixture(){
 const pr=fakePr();
 const content=proposedCodeowners(A,B).content;
 const details={id:500,name:PROPOSAL.name,target:'branch',
  enforcement:'active',conditions:structuredClone(PROPOSAL.conditions),
  bypass_actors:[],rules:structuredClone(PROPOSAL.rules)};
 return {
  securityLogin:A,businessLogin:B,
  prBefore:structuredClone(pr),prAfter:structuredClone(pr),
  mainBefore:ref(),mainAfter:ref(),
  mainBeforeStatus:'read',mainAfterStatus:'read',
  ct:{
   phase:'1CT',completedTwoEventTechnicalReceiptVerified:true,
   officialPrUnchangedAcrossAllReads:true,sourceBranchAndPrHeadMatch:true,
   sourceHeadSha:HEAD,baseSha:BASE,pushRunId:111,prRunId:222,
   productionReleaseAuthorized:false,releaseDecision:'HOLD'
  },
  co:{
   phase:'1CO',twoDistinctNominatedLatestHeadTechnicalApprovalsObserved:true,
   prReadBeforeAndAfterStable:true,actualGithubReviewPaginationComplete:true,
   securityNominatedAccountActuallyApprovedCurrentHead:true,
   businessNominatedAccountActuallyApprovedCurrentHead:true,
   actualNominatedReviewerWritePermissionsObserved:true,
   currentDevHead:HEAD,productionReleaseAuthorized:false,releaseDecision:'HOLD'
  },
  rulesets:{
   listStatus:'read',listingComplete:true,
   listed:[{id:500,name:details.name,target:'branch',enforcement:'active'}],
   detailStatus:{'500':'read'},details:{'500':details}
  },
  codeowners:base64File(content),proposal:structuredClone(PROPOSAL)
 };
}
const assess=change=>{
 const f=fixture();change?.(f);return assessIndependentGovernanceHandoff(f);
};
const blocked=(change,code)=>{
 const r=assess(change);
 assert.equal(r.technicalGovernanceHandoffPreconditionsObserved,false);
 assert.ok(r.sourceReviewCodes.includes(code),r.sourceReviewCodes.join(';'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
};
test('CU: synthetic complete technical handoff never grants legal mandate, OIDC or release',()=>{
 const r=assess();
 assert.equal(r.technicalGovernanceHandoffPreconditionsObserved,true,
  r.sourceReviewCodes.join(';'));
 assert.equal(r.actualMainBaseStableAcrossAllSources,true);
 assert.equal(r.verifiedMainBaseSha,BASE);
 assert.equal(r.pushRunId,111);
 assert.equal(r.prRunId,222);
 assert.equal(r.installedMainCodeownersExactNominatedBytesMatched,true);
 assert.equal(r.exactActiveMainRulesAndNoBypassFieldsObservable,true);
 assert.equal(r.distinctNominatedLatestHeadTechnicalGithubApprovalsMatched,true);
 assert.match(r.localUnsignedObservationSha256,/^[a-f0-9]{64}$/);
 assert.equal(r.reviewerLoginNamesOrTokensPersistedInReport,false);
 assert.equal(JSON.stringify(r).includes(A),false);
 assert.equal(JSON.stringify(r).includes(B),false);
 for(const key of [
  'independentlyMandatedCorporateSecurityBusinessRolesAuthenticated',
  'independentCryptoSignatureOnReviewerMandatesVerified',
  'externalCIWorkloadOidcSlsaSignatureVerified',
  'externalMcaEmudhraCcaWormDrStagingAcceptanceVerified',
  'independentProductionApprovalGranted','productionReleaseAuthorized'
 ])assert.equal(r[key],false,key);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CU: actual main ruleset missing or source incomplete is never assumed installed',()=>{
 blocked(f=>{f.rulesets.listed=[];f.rulesets.details={}},
  'CU_ACTUAL_MAIN_RULESET_LIST_MISSING_OR_EMPTY');
 blocked(f=>{f.rulesets.listStatus='access_denied'},
  'CU_ACTUAL_MAIN_RULESET_LIST_MISSING_OR_EMPTY');
 blocked(f=>{f.rulesets.listingComplete=false},
  'CU_ACTUAL_MAIN_RULESET_LIST_MISSING_OR_EMPTY');
 blocked(f=>{f.rulesets.detailStatus['500']='access_denied'},
  'CU_RULESET_DETAIL_MISSING_OR_LIST_DRIFT');
});
test('CU: concealed bypass actor field is NOT same as empty array',()=>{
 for(const value of [undefined,null,[{actor_id:1}],{}]){
  blocked(f=>{f.rulesets.details['500'].bypass_actors=value},
   'CU_MAIN_RULESET_BYPASS_ACTORS_HIDDEN_OR_NONEMPTY');
 }
});
test('CU: non-main, disabled, evaluate or duplicate main ruleset cannot count',()=>{
 for(const change of [
  f=>{f.rulesets.details['500'].conditions.ref_name.include=['refs/heads/develop']},
  f=>{f.rulesets.details['500'].conditions.ref_name.exclude=['refs/heads/main']},
  f=>{f.rulesets.details['500'].name='fake other rule'},
  f=>{f.rulesets.details['500'].enforcement='evaluate';f.rulesets.listed[0].enforcement='evaluate'},
  f=>{f.rulesets.details['500'].target='repository';f.rulesets.listed[0].target='repository'}
 ])blocked(change,'CU_EXACT_ONE_ACTIVE_MAIN_RULESET_NOT_OBSERVED');
 blocked(f=>{
  f.rulesets.listed.push({...f.rulesets.listed[0],id:501});
  f.rulesets.details['501']={...structuredClone(f.rulesets.details['500']),id:501};
  f.rulesets.detailStatus['501']='read';
 },'CU_EXACT_ONE_ACTIVE_MAIN_RULESET_NOT_OBSERVED');
});
test('CU: any deletion/non-fast-forward or extra rule changes exact main gate',()=>{
 for(const change of [
  f=>f.rulesets.details['500'].rules.pop(),
  f=>f.rulesets.details['500'].rules.push({type:'workflow',parameters:{}}),
  f=>f.rulesets.details['500'].rules[0].type='pull_request'
 ])blocked(change,'CU_MAIN_RULESET_REQUIRED_RULES_MISSING_OR_EXTRA');
});
test('CU: weakened two-reviewer latest-push or codeowner policy is held',()=>{
 for(const change of [
  r=>r.required_approving_review_count=1,
  r=>r.require_last_push_approval=false,
  r=>r.require_code_owner_review=false,
  r=>r.dismiss_stale_reviews_on_push=false,
  r=>r.required_review_thread_resolution=false,
  r=>r.allowed_merge_methods=['squash']
 ]){
  blocked(f=>change(f.rulesets.details['500'].rules.find(x=>x.type==='pull_request').parameters),
   'CU_MAIN_TWO_PERSON_LATEST_PUSH_CODEOWNER_GATE_DRIFT');
 }
});
test('CU: unpinned or weakened mandatory eight exact checks are rejected',()=>{
 for(const change of [
  r=>r.required_status_checks[0].integration_id=1,
  r=>r.required_status_checks[0].context='fake-green',
  r=>r.required_status_checks.pop(),
  r=>r.required_status_checks[1].context=r.required_status_checks[0].context,
  r=>r.strict_required_status_checks_policy=false,
  r=>r.do_not_enforce_on_create=true
 ]){
  blocked(f=>change(f.rulesets.details['500'].rules.find(x=>x.type==='required_status_checks').parameters),
   'CU_EIGHT_MAIN_STATUS_CONTEXTS_OR_GITHUB_APP_PIN_DRIFT');
 }
});
test('CU: unknown, forged, truncated or alternative CODEOWNERS cannot establish owner authority',()=>{
 const bads=[
  f=>f.codeowners.status='not_found_or_hidden',
  f=>f.codeowners.data.path='CODEOWNERS',
  f=>f.codeowners.data.sha='f'.repeat(40),
  f=>f.codeowners.data.size+=1,
  f=>f.codeowners.data.content='Zm9v=',
  f=>f.codeowners.data.encoding='utf8',
  f=>f.codeowners.data.type='symlink'
 ];
 for(const change of bads){
  const r=assess(change);
  assert.equal(r.installedMainCodeownersExactNominatedBytesMatched,false);
  assert.equal(r.technicalGovernanceHandoffPreconditionsObserved,false);
 }
});
test('CU: on-disk valid Git blob with only one owner is insufficient',()=>{
 blocked(f=>{
  f.codeowners=base64File('/* @'+A+'\n/.github/CODEOWNERS @'+A+'\n');
 },'CU_NOMINATED_TWO_ROLE_CODEOWNERS_NOT_EXACTLY_INSTALLED');
});
test('CU: proposed owner pair must exactly agree with distinct nominated real reviews',()=>{
 blocked(f=>{f.businessLogin=A},'CU_TWO_NOMINATED_NONAUTHOR_ACCOUNTS_INVALID');
 blocked(f=>{f.securityLogin='j9619655391-max'},
  'CU_TWO_NOMINATED_NONAUTHOR_ACCOUNTS_INVALID');
 blocked(f=>{f.securityLogin='different-security'},
  'CU_NOMINATED_TWO_ROLE_CODEOWNERS_NOT_EXACTLY_INSTALLED');
});
test('CU: false, stale, non-current PR reviewer approvals or missing write access block',()=>{
 for(const change of [
  f=>f.co.currentDevHead='f'.repeat(40),
  f=>f.co.businessNominatedAccountActuallyApprovedCurrentHead=false,
  f=>f.co.securityNominatedAccountActuallyApprovedCurrentHead=false,
  f=>f.co.actualNominatedReviewerWritePermissionsObserved=false,
  f=>f.co.actualGithubReviewPaginationComplete=false,
  f=>f.co.twoDistinctNominatedLatestHeadTechnicalApprovalsObserved=false
 ])blocked(change,'CU_TWO_DISTINCT_NOMINATED_LATEST_HEAD_APPROVALS_NOT_VERIFIED');
});
test('CU: green PR cannot mask missing push or prior source',()=>{
 for(const change of [
  f=>f.ct.completedTwoEventTechnicalReceiptVerified=false,
  f=>f.ct.sourceHeadSha='f'.repeat(40),
  f=>f.ct.baseSha='e'.repeat(40),
  f=>f.ct.productionReleaseAuthorized=true,
  f=>f.ct.sourceBranchAndPrHeadMatch=false
 ])blocked(change,'CU_COMPLETED_EXACT_HEAD_PUSH_PR_EVIDENCE_NOT_VERIFIED');
});
test('CU: main branch changed after subsource reads is HARD HOLD',()=>{
 for(const change of [
  f=>f.mainAfter.object.sha='d'.repeat(40),
  f=>f.mainBefore.object.url='https://evil.invalid/commit',
  f=>f.mainBeforeStatus='access_denied',
  f=>f.mainAfterStatus='not_found_or_hidden',
  f=>f.mainBefore.ref='refs/heads/develop'
 ])blocked(change,'CU_ACTUAL_BASE_MAIN_REF_NOT_STABLE');
});
test('CU: a PR head/base/merge/update/draft mutation is detected',()=>{
 for(const change of [
  f=>f.prAfter.head.sha='d'.repeat(40),
  f=>f.prAfter.base.sha='e'.repeat(40),
  f=>f.prAfter.merge_commit_sha='f'.repeat(40),
  f=>f.prAfter.updated_at='2026-11-19T03:00:00Z',
  f=>f.prAfter.draft=false,
  f=>f.prAfter.user.login='other-user'
 ])blocked(change,'CU_OUTER_PR_RACE_OR_DRAFT_IDENTITY_INVALID');
});
test('CU: proposal drift or spoofed matching name does not pass actual rule verification',()=>{
 blocked(f=>{f.proposal.rules[2].parameters.required_approving_review_count=1},
  'CU_LOCAL_PROPOSED_MAIN_RULESET_UNREVIEWED');
 blocked(f=>{f.rulesets.listed[0].name='unexpected'},
  'CU_RULESET_DETAIL_MISSING_OR_LIST_DRIFT');
});
test('CU: main-ref GET uses only exact official URL, bounded JSON and no redirects',async()=>{
 const url=API+'/git/ref/heads/main';
 const data=ref(),calls=[];
 const response=(json,status=200,path=url,contentType='application/json')=>{
  const r=new Response(JSON.stringify(json),{status,headers:{'content-type':contentType}});
  Object.defineProperty(r,'url',{value:path});
  return r;
 };
 const good=await readMainRefOnly('test',async(actual,init)=>{
  calls.push(actual);
  assert.equal(actual,url);
  assert.equal(init.method,'GET');
  assert.equal(init.redirect,'error');
  assert.equal(init.headers.Authorization,'Bearer test');
  return response(data);
 });
 assert.equal(good.status,'read');
 assert.deepEqual(good.data,data);
 assert.deepEqual(calls,[url]);
 assert.equal((await readMainRefOnly('test',async()=>response({},403))).status,
  'access_denied');
 assert.equal((await readMainRefOnly('test',async()=>response({},200,url,'text/html'))).status,
  'invalid');
 assert.equal((await readMainRefOnly('test',async()=>response({},200,'https://evil.invalid'))).status,
  'invalid');
 assert.equal((await readMainRefOnly('test',async()=>new Response('x',{
  headers:{'content-length':'999999','content-type':'application/json'}}))).status,
  'invalid');
});
test('CU: no approved read token means zero remote operations and no simulated GO',async()=>{
 let called=0;
 const r=await verifyIndependentGovernanceHandoff({
  securityLogin:A,businessLogin:B,pushId:111,prId:222,
  proposal:structuredClone(PROPOSAL),token:'',
  fetchImpl:async()=>{called++;throw Error('no remote access expected');}
 });
 assert.equal(called,0);
 assert.equal(r.technicalGovernanceHandoffPreconditionsObserved,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CU: self/duplicate reviewer nominees or duplicate/invalid run IDs rejected preflight',async()=>{
 for(const props of [
  {securityLogin:A,businessLogin:A,pushId:111,prId:222},
  {securityLogin:'j9619655391-max',businessLogin:B,pushId:111,prId:222},
  {securityLogin:A,businessLogin:B,pushId:111,prId:111},
  {securityLogin:A,businessLogin:B,pushId:-1,prId:222}
 ])await assert.rejects(()=>verifyIndependentGovernanceHandoff({
  ...props,token:'test',proposal:structuredClone(PROPOSAL),
  fetchImpl:async()=>{throw Error('unexpected GET');}
 }),/CU_INVALID_/);
});
