import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 REPO,AUTHOR,RULESET_PROPOSAL,REQUIRED_JOBS,
 assessProposedMainRuleset,validateReviewerNominees,proposedCodeowners,
 assessActualGithubPermissions,readActualGithubPermission
} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
const recipe=JSON.parse(readFileSync(RULESET_PROPOSAL,'utf8'));
const review=x=>assessProposedMainRuleset(x??recipe);
const clone=x=>structuredClone(x);
const has=(out,code)=>assert.ok(out.anomalyCodes.includes(code),out.anomalyCodes.join(';'));
const repoUrl='https://api.github.com/repos/'+REPO;
const response=(url,body,{status=200,mime='application/json',len}={})=>{
 const headers={'content-type':mime};
 if(len!==undefined)headers['content-length']=String(len);
 const result=new Response(body,{status,headers});
 Object.defineProperty(result,'url',{value:url});
 return result;
};
const data=(login,permission)=>({user:{login},permission});
test('CM: official REST-compatible reviewed main ruleset is only PROPOSED, not installed or release GO',()=>{
 const r=review();
 assert.equal(r.localProposedRestPayloadStructurallySafe,true,r.anomalyCodes.join(';'));
 assert.deepEqual(recipe.conditions.ref_name,{include:['refs/heads/main'],exclude:[]});
 assert.equal(r.requiredCheckCount,8);
 assert.deepEqual(recipe.rules[3].parameters.required_status_checks.map(x=>x.context),REQUIRED_JOBS);
 assert.equal(r.actualMainRulesetInstalledAndEnforced,false);
 assert.equal(r.latestHeadSecurityAndBusinessRoleApprovalsAuthenticated,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CM: deleting safeguards or injecting hidden ruleset bypass actor is denied',()=>{
 for(const mutate of [
  x=>x.bypass_actors=[{actor_id:1,actor_type:'RepositoryRole',bypass_mode:'always'}],
  x=>x.enforcement='evaluate',
  x=>x.enforcement='disabled',
  x=>x.target='tag',
  x=>x.name='ACTIVATED ALREADY',
  x=>x.extra='unreviewed'
 ]){
  const r=clone(recipe);mutate(r);
  has(review(r),'CM_RULESET_IDENTITY_TARGET_ENFORCEMENT_OR_BYPASS_DRIFT');
 }
});
test('CM: main-only matching cannot be changed to all branches or accidentally excluded',()=>{
 for(const mutate of [
  x=>x.conditions.ref_name.include=['~ALL'],
  x=>x.conditions.ref_name.include=['refs/heads/dev*'],
  x=>x.conditions.ref_name.exclude=['refs/heads/main'],
  x=>x.conditions.ref_name.include=['refs/heads/main','refs/heads/production'],
  x=>x.conditions.ref_name.ignore='none'
 ]){
  const r=clone(recipe);mutate(r);
  has(review(r),'CM_MAIN_ONLY_REF_MATCH_CHANGED');
 }
});
test('CM: both force-push and deletion preventions remain present',()=>{
 for(const mutate of [
  x=>x.rules.splice(0,1),
  x=>x.rules[1].type='creation',
  x=>x.rules[0].parameters={enabled:false},
  x=>x.rules.push({type:'update',parameters:{update_allows_fetch_and_merge:true}})
 ]){
  const r=clone(recipe);mutate(r);
  assert.equal(review(r).localProposedRestPayloadStructurallySafe,false);
 }
});
test('CM: no fewer than two latest-push/stale-dismiss/code-owner reviews and resolved conversations',()=>{
 for(const mutate of [
  x=>x.rules[2].parameters.required_approving_review_count=1,
  x=>x.rules[2].parameters.required_approving_review_count=0,
  x=>x.rules[2].parameters.require_code_owner_review=false,
  x=>x.rules[2].parameters.require_last_push_approval=false,
  x=>x.rules[2].parameters.dismiss_stale_reviews_on_push=false,
  x=>x.rules[2].parameters.required_review_thread_resolution=false,
  x=>x.rules[2].parameters.reviewers='unapproved'
 ]){
  const r=clone(recipe);mutate(r);
  has(review(r),'CM_TWO_REVIEWER_CODEOWNER_LATEST_PUSH_GATE_WEAKENED');
 }
});
test('CM: required-hosted-context list cannot be reduced, renamed, widened or duplicated',()=>{
 for(const mutate of [
  x=>x.rules[3].parameters.required_status_checks.pop(),
  x=>x.rules[3].parameters.required_status_checks[0].context='never-heard-of-it',
  x=>x.rules[3].parameters.required_status_checks[1].context='baseline',
  x=>x.rules[3].parameters.required_status_checks[0].integration_id=123,
  x=>x.rules[3].parameters.required_status_checks.push({context:'bypass'})
 ]){
  const r=clone(recipe);mutate(r);
  has(review(r),'CM_EIGHT_EXACT_HOSTED_CHECKS_OR_STRICT_POLICY_WEAKENED');
 }
});
test('CM: required status checks must be strict and cannot be disabled during branch creation',()=>{
 for(const mutate of [
  x=>x.rules[3].parameters.strict_required_status_checks_policy=false,
  x=>x.rules[3].parameters.do_not_enforce_on_create=true,
  x=>x.rules[3].parameters.required_status_checks='not array',
  x=>x.rules[3].parameters.unknown='ignore'
 ]){
  const r=clone(recipe);mutate(r);
  has(review(r),'CM_EIGHT_EXACT_HOSTED_CHECKS_OR_STRICT_POLICY_WEAKENED');
 }
});
test('CM: no unreviewed human identity is baked into main CODEOWNERS rule proposal',()=>{
 assert.equal(JSON.stringify(recipe).includes('@security'),false);
 assert.equal(JSON.stringify(recipe).includes('@business'),false);
 assert.deepEqual(recipe.bypass_actors,[]);
 assert.equal(review(null).productionReleaseAuthorized,false);
});
test('CM: two explicitly nominated different valid GitHub logins render CODEOWNERS for manual review ONLY',()=>{
 const r=proposedCodeowners('real-security','business-auth');
 assert.match(r.content,/\* @real-security @business-auth/);
 assert.match(r.content,/\/\.github\/CODEOWNERS @real-security @business-auth/);
 assert.match(r.sha256,/^[a-f0-9]{64}$/);
 assert.equal(r.actualMainBaseBranchCodeownersInstalled,false);
 assert.equal(r.rolePermissionsVerified,false);
 assert.equal(r.securityAndBusinessRoleMandatesIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CM: both nominees must be nonauthor and distinct, case-insensitive',()=>{
 for(const [security,business] of [
  [AUTHOR,'approved-other'],['approved-other',AUTHOR],
  ['same-person','SAME-PERSON'],['','eligible'],['good',''],
  ['bad/name','good'],['abc;rm -rf','safe'],['a'.repeat(40),'good'],
  ['-leading','good'],['trailing-','good']
 ]){
  const r=validateReviewerNominees(security,business);
  assert.equal(r.valid,false,security+' '+business);
  assert.throws(()=>proposedCodeowners(security,business));
 }
});
test('CM: codeowner syntax cannot certify role split even with two real nonauthor accounts',()=>{
 const plan=proposedCodeowners('security-person','business-person');
 assert.equal(plan.rolePermissionsVerified,false);
 assert.equal(plan.securityAndBusinessRoleMandatesIndependentlyVerified,false);
 assert.equal(plan.actualMainBaseBranchCodeownersInstalled,false);
 assert.equal(plan.productionReleaseAuthorized,false);
});
test('CM: two REAL official write permission snapshots are not an organizational Security+Business mandate',()=>{
 const r=assessActualGithubPermissions({
  securityLogin:'security-user',businessLogin:'business-user',
  securityResponse:{status:'read',data:data('security-user','write')},
  businessResponse:{status:'read',data:data('business-user','maintain')}
 });
 assert.equal(r.technicalRepoPermissionPreconditionMet,true,r.anomalies.join(','));
 assert.equal(r.bothRolesIndependentlyAuthenticated,false);
 assert.equal(r.latestHeadGithubApprovalsAuthenticated,false);
 assert.equal(r.effectiveMainRulesetIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CM: read-only/triage or different user cannot satisfy GitHub write-permission prerequisite',()=>{
 for(const [security,business] of [
  [{status:'read',data:data('security-user','read')},
   {status:'read',data:data('business-user','write')}],
  [{status:'read',data:data('wrong-user','admin')},
   {status:'read',data:data('business-user','write')}],
  [{status:'unavailable',data:null},{status:'read',data:data('business-user','admin')}],
  [{status:'read',data:data('security-user','triage')},
   {status:'read',data:data('business-user','write')}]
 ]){
  const r=assessActualGithubPermissions({
   securityLogin:'security-user',businessLogin:'business-user',
   securityResponse:security,businessResponse:business
  });
  assert.equal(r.technicalRepoPermissionPreconditionMet,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CM: fixed official collaborator permission route uses only GET, bounded response, no redirect',async()=>{
 const login='security-owner',url=repoUrl+'/collaborators/'+login+'/permission';
 const r=await readActualGithubPermission(login,'read-token',async (u,opts)=>{
  assert.equal(u,url);assert.equal(opts.method,'GET');
  assert.equal(opts.redirect,'error');assert.equal(opts.cache,'no-store');
  assert.equal(opts.headers.Authorization,'Bearer read-token');
  return response(url,JSON.stringify(data(login,'write')));
 });
 assert.equal(r.status,'read');
 assert.equal(r.data.permission,'write');
 await assert.rejects(()=>readActualGithubPermission('../hack','read-token'),
  /CM_INVALID_OR_AUTHOR_LOGIN/);
 await assert.rejects(()=>readActualGithubPermission(AUTHOR,'read-token'),
  /CM_INVALID_OR_AUTHOR_LOGIN/);
});
test('CM: permission API absent token, denied, hidden, wrong origin, wrong MIME and oversize fail closed',async()=>{
 const login='security-owner',url=repoUrl+'/collaborators/'+login+'/permission';
 assert.equal((await readActualGithubPermission(login,'',async()=>{throw Error('token absent');})).status,'unavailable');
 for(const [res,want] of [
  [response(url,'{}',{status:403}),'access_denied'],
  [response(url,'{}',{status:404}),'not_found_or_hidden'],
  [response(url,'{}',{status:429}),'unavailable'],
  [response('https://evil.example','{}'),'invalid'],
  [response(url,'{}',{mime:'text/html'}),'invalid'],
  [response(url,'{}',{len:1000000}),'invalid'],
  [response(url,JSON.stringify(data(login,'write')).padEnd(12000,' ')),'invalid']
 ]){
  const out=await readActualGithubPermission(login,'token',async()=>res);
  assert.equal(out.status,want);
 }
});
test('CM: forged permission with another login or unrecognized role is never accepted',async()=>{
 const login='security-owner',url=repoUrl+'/collaborators/'+login+'/permission';
 for(const value of [data('someone-else','write'),data(login,'owner'),
  {permission:'write'},{user:{login},permission:null}]){
  const r=await readActualGithubPermission(login,'token',
   async()=>response(url,JSON.stringify(value)));
  assert.equal(r.status,'invalid');
 }
});
test('CM: unknown repo permission source cannot be turned into latest-head security authorization',()=>{
 const result=assessActualGithubPermissions({
  securityLogin:AUTHOR,businessLogin:'real-business',
  securityResponse:{status:'read',data:data(AUTHOR,'admin')},
  businessResponse:{status:'read',data:data('real-business','write')}
 });
 assert.equal(result.nominationSyntaxAndIndependenceValid,false);
 assert.equal(result.technicalRepoPermissionPreconditionMet,false);
 assert.equal(result.bothRolesIndependentlyAuthenticated,false);
 assert.equal(result.productionReleaseAuthorized,false);
});
