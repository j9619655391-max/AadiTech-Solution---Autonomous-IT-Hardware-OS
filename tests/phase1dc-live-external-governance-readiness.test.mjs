import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {REPO,AUTHOR,REQUIRED_JOBS}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {
 API,PATHS,EXTERNAL_GATES,protectedMainRuleset,allowedPath,
 readActualGithubPath,assessActualReadOnlyHandoff,collectLiveActualGovernance
} from '../scripts/phase1dc-live-external-governance-readiness.mjs';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const stamp='2026-11-20T08:00:00Z';
const read=data=>({status:'read',data,httpStatus:200});
const refused={status:'access_denied',data:null,httpStatus:403};
const missing={status:'absent_or_hidden',data:null,httpStatus:404};
const protection=()=>({
 enforce_admins:{enabled:true},
 required_pull_request_reviews:{
  required_approving_review_count:2,
  dismiss_stale_reviews:true,
  require_code_owner_reviews:true
 },
 required_status_checks:{strict:true,contexts:[...REQUIRED_JOBS]}
});
const pr=()=>({
 number:1,state:'open',draft:true,merged:false,
 user:{login:AUTHOR},head:{ref:'chore/phase0-foundation-20261106',
  repo:{full_name:REPO},sha:HEAD},
 base:{ref:'main',repo:{full_name:REPO},sha:BASE},
 merge_commit_sha:MERGE,updated_at:stamp
});
const ruleset=()=>({
 id:21,enforcement:'active',target:'branch',bypass_actors:[],
 conditions:{ref_name:{include:['refs/heads/main'],exclude:[]}},
 rules:[
  {type:'deletion'},{type:'non_fast_forward'},
  {type:'pull_request',parameters:{
   required_approving_review_count:2,dismiss_stale_reviews_on_push:true,
   require_code_owner_review:true,require_last_push_approval:true,
   required_review_thread_resolution:true
  }},
  {type:'required_status_checks',parameters:{
   strict_required_status_checks_policy:true,
   do_not_enforce_on_create:false,
   required_status_checks:REQUIRED_JOBS.map(context=>({
    context,integration_id:15368
   }))
  }}
 ]
});
const owner=data=>({
 type:'file',path:'.github/CODEOWNERS',
 sha:'d'.repeat(40),encoding:'base64',
 content:Buffer.from(data,'utf8').toString('base64'),
 size:Buffer.byteLength(data,'utf8')
});
const review=(login,id,opts={})=>({
 id,user:{login},state:'APPROVED',commit_id:HEAD,
 submitted_at:'2026-11-20T08:01:00Z',...opts
});
function fixture(){
 const r=ruleset();
 return {
  prBefore:read(pr()),prAfter:read(pr()),
  mainBefore:read({ref:'refs/heads/main',object:{sha:BASE,type:'commit'}}),
  mainAfter:read({ref:'refs/heads/main',object:{sha:BASE,type:'commit'}}),
  reviews:{status:'read',complete:true,data:[
   review('security-reviewer',1),
   review('business-reviewer',2)
  ]},
  rulesets:{status:'read',complete:true,data:[{id:21,target:'branch',enforcement:'active'}]},
  rulesetDetails:{'21':read(r)},
  codeowners:{githubCodeowners:read(owner('* @security-reviewer @business-reviewer\n')),
   rootCodeowners:missing,docsCodeowners:missing},
  protection:read(protection())
 };
}
const assess=edit=>{let f=fixture();edit?.(f);return assessActualReadOnlyHandoff(f)};
function denied(edit,code){
 const r=assess(edit);
 assert.ok(r.anomalyCodes.includes(code),
  'expected '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.technicallyObservedGithubPrerequisitesOnly,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('DC: even complete synthetic *technical* GitHub fixtures never constitute independent officer/CA approval',()=>{
 const r=assess();
 assert.equal(r.technicallyObservedGithubPrerequisitesOnly,true,r.anomalyCodes.join('|'));
 assert.equal(r.officialMainRefAndDraftPrStable,true);
 assert.equal(r.observedDistinctCurrentHeadNonauthorApprovals,2);
 assert.equal(r.strictRootCoverageCodeownersFiles,1);
 assert.equal(r.observedStrictBypassFreeMainRulesetCount,1);
 assert.equal(r.directMainBranchProtectionStatus,'read');
 assert.equal(r.outstandingExternalPrerequisiteKeys.length,9);
 for(const k of [
  'legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated',
  'externallyAuthorizedTrustProviderMandateAndKeyEnrollment',
  'independentlyVerifiedCcaRcaiEmudhraMcaCrLOcsp',
  'actualExternalWormCasAndDrVerified',
  'actualIndependentOidcSlsaAndStagingAcceptance',
  'productionReleaseAuthorized'
 ])assert.equal(r[k],false,k);
 assert.equal(r.releaseDecision,'HOLD');
});
test('DC: real current blocker observation 0 reviews, 0 rules, missing CODEOWNERS and 403 protection never READY',()=>{
 const r=assess(f=>{
  f.reviews.data=[];
  f.rulesets.data=[];f.rulesetDetails={};
  f.codeowners.githubCodeowners=missing;
  f.protection=refused;
 });
 assert.equal(r.observedDistinctCurrentHeadNonauthorApprovals,0);
 assert.equal(r.observedActiveBranchRulesetCount,0);
 assert.equal(r.observedCodeownersFileCount,0);
 assert.equal(r.directMainBranchProtectionStatus,'access_denied');
 assert.equal(r.directMainBranchProtectionExplicitly403,true);
 assert.ok(r.anomalyCodes.includes('DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK'));
 assert.equal(r.releaseDecision,'HOLD');
});
test('DC: 403 branch protection is unknown, not proof of zero or false',()=>{
 denied(f=>{f.protection=refused},'DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK');
 const r=assess(f=>{f.protection=refused});
 assert.equal(r.directMainBranchProtectionStatus,'access_denied');
 assert.equal(r.directMainBranchProtectionExplicitly403,true);
});
test('DC: 404 protection, timeout and missing status are not silently accepted',()=>{
 for(const state of [missing,{status:'unavailable'},null,{status:'read',data:{}}])
  denied(f=>{f.protection=state},'DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK');
});
test('DC: branch protection must enforce admin, 2 approvals, owner reviews and strict checks',()=>{
 for(const edit of [
  p=>{p.enforce_admins.enabled=false},
  p=>{p.required_pull_request_reviews.required_approving_review_count=1},
  p=>{p.required_pull_request_reviews.dismiss_stale_reviews=false},
  p=>{p.required_pull_request_reviews.require_code_owner_reviews=false},
  p=>{p.required_status_checks.strict=false}
 ])denied(f=>edit(f.protection.data),'DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK');
});
test('DC: main SHA changed between read snapshots or PR base disagreeing fail closed',()=>{
 denied(f=>{f.mainAfter.data.object.sha='f'.repeat(40)},
  'DC_MAIN_BASE_REF_CHANGED_OR_UNREADABLE');
 denied(f=>{f.mainBefore.data.object.sha='e'.repeat(40)},
  'DC_MAIN_BASE_REF_CHANGED_OR_UNREADABLE');
 denied(f=>{f.prBefore.data.base.sha='0'.repeat(40)},
  'DC_MAIN_BASE_REF_CHANGED_OR_UNREADABLE');
});
test('DC: PR head, merge SHA, updated time or draft state changed between reads',()=>{
 for(const edit of [
  f=>{f.prAfter.data.head.sha='e'.repeat(40)},
  f=>{f.prAfter.data.merge_commit_sha='0'.repeat(40)},
  f=>{f.prAfter.data.updated_at='2026-11-20T09:00:00Z'},
  f=>{f.prAfter.data.draft=false},
  f=>{f.prBefore.data.user.login='impostor'},
  f=>{f.prBefore.data.merged=true}
 ])denied(edit,'DC_LIVE_PR_TOUCHED_DURING_EVIDENCE_READ');
});
test('DC: no submitted reviews or incomplete pagination denies technical quorum',()=>{
 denied(f=>{f.reviews.data=[]},
  'DC_TWO_DISTINCT_NONAUTHOR_LATEST_HEAD_APPROVALS_NOT_OBSERVED');
 denied(f=>{f.reviews.complete=false},'DC_SUBMITTED_REVIEW_PAGINATION_MISSING');
 denied(f=>{f.reviews.status='access_denied'},'DC_SUBMITTED_REVIEW_PAGINATION_MISSING');
});
test('DC: stale approvals or author self approval are not latest-head independent reviewers',()=>{
 denied(f=>{f.reviews.data[1].commit_id='0'.repeat(40)},
  'DC_TWO_DISTINCT_NONAUTHOR_LATEST_HEAD_APPROVALS_NOT_OBSERVED');
 denied(f=>{f.reviews.data[0].user.login=AUTHOR},
  'DC_TWO_DISTINCT_NONAUTHOR_LATEST_HEAD_APPROVALS_NOT_OBSERVED');
});
test('DC: latest CHANGES_REQUESTED supersedes earlier approved review',()=>{
 denied(f=>{f.reviews.data.push(review('security-reviewer',3,{
  state:'CHANGES_REQUESTED',submitted_at:'2026-11-20T08:02:00Z'
 }))},'DC_TWO_DISTINCT_NONAUTHOR_LATEST_HEAD_APPROVALS_NOT_OBSERVED');
});
test('DC: duplicate review ID or malformed reviewer state is untrusted',()=>{
 denied(f=>{f.reviews.data[1].id=1},'DC_SUBMITTED_GITHUB_REVIEWS_UNTRUSTED');
 denied(f=>{f.reviews.data[1].state='AUTO_APPROVED'},
  'DC_SUBMITTED_GITHUB_REVIEWS_UNTRUSTED');
});
test('DC: empty CODEOWNERS on main is not equivalent to protected path coverage',()=>{
 denied(f=>{f.codeowners.githubCodeowners=missing},
  'DC_MAIN_CODEOWNERS_NOT_VERIFIABLY_INSTALLED');
 denied(f=>{f.codeowners.githubCodeowners=refused},
  'DC_CODEOWNERS_SOURCE_ACCESS_UNKNOWN');
});
test('DC: strict CODEOWNERS one wildcard rule, two distinct nonauthor owners required',()=>{
 for(const file of [
  '* @security-reviewer',
  '* @security-reviewer @security-reviewer',
  '* @security-reviewer @'+AUTHOR,
  '/scripts/ @security-reviewer @business-reviewer',
  '* @security-reviewer @business-reviewer\n/src/ @any-other-owner',
  '* @team/security @team/business'
 ])denied(f=>{f.codeowners.githubCodeowners=read(owner(file+'\n'))},
  'DC_CODEOWNERS_EXISTS_BUT_STRICT_MAIN_COVERAGE_NOT_PROVEN_githubCodeowners');
});
test('DC: invalid CODEOWNERS content encoding, SHA/path, oversize and base64 rejected',()=>{
 for(const edit of [
  o=>{o.encoding='utf8'},o=>{o.sha='bad'},
  o=>{o.path='docs/WRONG'},o=>{o.size++},
  o=>{o.content='not base64!!!'},
  o=>{o.size=90000}
 ])denied(f=>edit(f.codeowners.githubCodeowners.data),
  'DC_MAIN_CODEOWNERS_NOT_VERIFIABLY_INSTALLED');
});
test('DC: active rule is insufficient without explicitly visible empty bypass list',()=>{
 denied(f=>{delete f.rulesetDetails['21'].data.bypass_actors},
  'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
 denied(f=>{f.rulesetDetails['21'].data.bypass_actors=[{
  actor_id:1,actor_type:'OrganizationAdmin',bypass_mode:'always'
 }]},'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
});
test('DC: evaluated, disabled, wrong branch or tag rules do not protect main',()=>{
 for(const edit of [
  r=>{r.enforcement='evaluate'},
  r=>{r.target='tag'},
  r=>{r.conditions.ref_name.include=['refs/heads/development']},
  r=>{r.conditions.ref_name.exclude=['refs/heads/main']}
 ])denied(f=>edit(f.rulesetDetails['21'].data),
  'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
});
test('DC: main ruleset must prevent deletion, rewrites and have strict PR controls',()=>{
 for(const edit of [
  r=>{r.rules.shift()},
  r=>{r.rules[1].type='unknown'},
  r=>{r.rules[2].parameters.required_approving_review_count=1},
  r=>{delete r.rules[2].parameters.required_approving_review_count},
  r=>{r.rules[2].parameters.dismiss_stale_reviews_on_push=false},
  r=>{r.rules[2].parameters.require_code_owner_review=false},
  r=>{r.rules[2].parameters.require_last_push_approval=false},
  r=>{r.rules[2].parameters.required_review_thread_resolution=false}
 ])denied(f=>edit(f.rulesetDetails['21'].data),
  'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
});
test('DC: required checks must be eight exact GitHub Actions app-bound jobs',()=>{
 for(const edit of [
  r=>{r.rules[3].parameters.required_status_checks.pop()},
  r=>{r.rules[3].parameters.required_status_checks[0].context='not-baseline'},
  r=>{r.rules[3].parameters.required_status_checks[0].integration_id=0},
  r=>{r.rules[3].parameters.strict_required_status_checks_policy=false},
  r=>{r.rules[3].parameters.do_not_enforce_on_create=true},
  r=>{r.rules[3].parameters.required_status_checks[0].context=
   r.rules[3].parameters.required_status_checks[1].context}
 ])denied(f=>edit(f.rulesetDetails['21'].data),
  'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET');
});
test('DC: missing ruleset list or inaccessible detail is UNKNOWN and HOLD',()=>{
 denied(f=>{f.rulesets={status:'access_denied',complete:false,data:[]}},
  'DC_OFFICIAL_RULESET_LIST_UNVERIFIED_OR_INCOMPLETE');
 denied(f=>{f.rulesets.complete=false},
  'DC_OFFICIAL_RULESET_LIST_UNVERIFIED_OR_INCOMPLETE');
 denied(f=>{f.rulesetDetails['21']=refused},
  'DC_MAIN_RULESET_DETAIL_OR_BYPASS_VISIBILITY_UNKNOWN');
});
test('DC: duplicate ID or incomplete pagination cannot be a valid ruleset observation',()=>{
 denied(f=>{f.rulesets.data.push({id:21,target:'branch',enforcement:'active'})},
  'DC_OFFICIAL_RULESET_LIST_UNVERIFIED_OR_INCOMPLETE');
 denied(f=>{f.rulesets.complete=false},'DC_OFFICIAL_RULESET_LIST_UNVERIFIED_OR_INCOMPLETE');
});
test('DC: route allowlist strictly read-only; no arbitrary GitHub path or alternate domain',()=>{
 for(const p of Object.values(PATHS))assert.equal(allowedPath(p),true,p);
 for(const p of [
  '/issues/2/comments','/git/refs/heads/main','/rulesets/21',
  '/repos/other/repo','https://attacker.example/api','/pulls/1/merge',
  '/pulls/1/reviews?per_page=100&page=999','/rulesets/0?includes_parents=true'
 ])assert.equal(allowedPath(p),false,p);
 assert.equal(allowedPath('/rulesets/21?includes_parents=true'),true);
});
test('DC: invalid token and disallowed route must not create a network request',async()=>{
 let invoked=0;
 const fake=async()=>{invoked++;throw Error('Network must not run');};
 await assert.rejects(readActualGithubPath('/issues/2',{
  token:'dummy',fetchImpl:fake}),/DC_REJECTED_NON_ALLOWLISTED_GITHUB_PATH/);
 const r=await readActualGithubPath(PATHS.pr,{
  token:'x'.repeat(4097),fetchImpl:fake});
 assert.equal(r.status,'invalid');
 assert.equal(invoked,0);
});
test('DC: official 403 and 404 preserve denied versus absent status and never leak token',async()=>{
 const observed=[];
 const fetchImpl=async(url,opts)=>{
  observed.push({url,opts});
  return {status:url.includes('protection')?403:404};
 };
 const r1=await readActualGithubPath(PATHS.protection,{
  token:'private-not-in-report',fetchImpl});
 const r2=await readActualGithubPath(PATHS.githubCodeowners,{
  token:'private-not-in-report',fetchImpl});
 assert.equal(r1.status,'access_denied');
 assert.equal(r2.status,'absent_or_hidden');
 assert.equal(r1.httpStatus,403);
 assert.equal(r2.httpStatus,404);
 assert.equal(observed.length,2);
 assert.ok(observed.every(x=>x.opts.method==='GET'&&x.opts.redirect==='error'));
 assert.ok(observed.every(x=>x.url.startsWith(API+'/')));
 assert.equal(JSON.stringify(r1).includes('private-not-in-report'),false);
});
test('DC: 200 response requires no redirect, exact official URL, JSON and bounded body',async()=>{
 const base=API+PATHS.pr;
 const mk=(url,data,extras={})=>{
  const content=Buffer.from(JSON.stringify(data),'utf8');let called=false;
  return {
   status:200,url,redirected:false,
   headers:{get:k=>k==='content-type'?'application/json':
    k==='content-length'?String(content.length):null},
   body:{getReader:()=>({read:async()=>{
    if(called)return {done:true};
    called=true;return {done:false,value:new Uint8Array(content)};
   }})},...extras
  };
 };
 const ok=await readActualGithubPath(PATHS.pr,{
  fetchImpl:async()=>mk(base,pr())
 });
 assert.equal(ok.status,'read');
 const wrong=await readActualGithubPath(PATHS.pr,{
  fetchImpl:async()=>mk('https://evil.example',pr())
 });
 assert.equal(wrong.status,'invalid');
 const redirect=await readActualGithubPath(PATHS.pr,{
  fetchImpl:async()=>mk(base,pr(),{redirected:true})
 });
 assert.equal(redirect.status,'invalid');
});
test('DC: live collector reads only official allowlisted GET endpoints and keeps permanent HOLD',async()=>{
 const f=fixture(),accessed=[];
 const transport=async(url,opts)=>{
  assert.ok(url.startsWith(API+'/'));
  assert.equal(opts.method,'GET');
  assert.equal(opts.redirect,'error');
  const path=url.slice(API.length);
  assert.equal(allowedPath(path),true);
  accessed.push(path);
  const detail=path==='/rulesets/21?includes_parents=true'?
   f.rulesetDetails['21']:null;
  const content=path===PATHS.pr?f.prBefore.data:
   path===PATHS.main?f.mainBefore.data:
   path===PATHS.reviews?f.reviews.data:
   path===PATHS.rulesets?f.rulesets.data:
   path===PATHS.githubCodeowners?f.codeowners.githubCodeowners.data:
   path===PATHS.protection?f.protection.data:
   detail?.data;
  if(content===undefined)return {status:404};
  const bytes=Buffer.from(JSON.stringify(content));
  let done=false;
  return {status:200,url,redirected:false,
   headers:{get:key=>key==='content-type'?'application/json':
    key==='content-length'?String(bytes.length):null},
   body:{getReader:()=>({read:async()=>done?{done:true}:
    (done=true,{done:false,value:new Uint8Array(bytes)})})}
  };
 };
 const report=await collectLiveActualGovernance({token:'test-only',fetchImpl:transport});
 assert.equal(report.technicallyObservedGithubPrerequisitesOnly,true,
  report.anomalyCodes.join('|'));
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.releaseDecision,'HOLD');
 assert.equal(accessed.filter(x=>x===PATHS.pr).length,2);
 assert.equal(accessed.filter(x=>x===PATHS.main).length,2);
 assert.equal(accessed.filter(x=>x===PATHS.protection).length,1);
 assert.equal(accessed.length,11);
});
