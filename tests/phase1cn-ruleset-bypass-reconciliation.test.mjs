import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 rulesetListPath,rulesetDetailPath,readOfficialRulesets,collectActualRulesets,
 assessActualRulesetReconciliation
} from '../scripts/phase1cn-ruleset-bypass-reconciliation.mjs';
import {REPO} from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
const proposal=JSON.parse(readFileSync(
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json','utf8'));
const byReport={
 kind:'LIVE_READONLY_SOURCE_BOUND_UNSIGNED_HOLD',
 sourceBundleSha256:'d'.repeat(64),
 productionReleaseAuthorized:false,releaseDecision:'HOLD',
 snapshotDerived:{
  phase:'1BY',observedPrDraftAndUnmerged:true,
  eventSourceHeadAndBaseMatch:true,ciMergeMatchesPrApi:true,
  observedDevHeadSha:HEAD,observedBaseSha:BASE,
  observedPrMergeSha:MERGE,
  rules:{observedRuleCount:0},
  reviews:{distinctLatestHeadApprovalCount:0},
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const clReport={
 sourceExternallySigned:false,
 productionReleaseAuthorized:false,releaseDecision:'HOLD',
 decision:{
  phase:'1CL',repo:REPO,officialPublicObservationStructurallyValid:true,
  observedDevHeadSha:HEAD,selectedCodeownersLocation:null,
  requestedReviewerSummary:{requestedUsers:0,requestedTeams:0},
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 }
};
const env={
 GITHUB_ACTIONS:'true',GITHUB_JOB:'live-github-governance-hold',
 GITHUB_REPOSITORY:REPO,GITHUB_REF:'refs/pull/1/merge',
 GITHUB_SHA:MERGE
};
const base=()=>({
 observations:{listStatus:'read',listingComplete:true,listed:[],
  details:{},detailStatus:{},httpStatus:200},
 proposal:structuredClone(proposal),
 byReport:structuredClone(byReport),clReport:structuredClone(clReport),
 environment:{...env}
});
const evaluate=x=>assessActualRulesetReconciliation(x);
const check=(r,c)=>assert.ok(r.anomalyCodes.includes(c),r.anomalyCodes.join('; '));
const example=(id=42,includeBypass=false)=>({
 id,name:proposal.name,target:'branch',enforcement:'active',
 source_type:'Repository',source:REPO,
 conditions:structuredClone(proposal.conditions),
 rules:structuredClone(proposal.rules),
 ...(includeBypass?{bypass_actors:[]}:{})
});
const fixtureWithRule=(includeBypass=false)=>{
 const x=base();const item=example(42,includeBypass);
 x.observations.listed=[{id:item.id,name:item.name,
  target:item.target,enforcement:item.enforcement}];
 x.observations.details={'42':item};
 x.observations.detailStatus={'42':'read'};
 return x;
};
const response=(url,body,{status=200,mime='application/json',len}={})=>{
 const headers={'content-type':mime};
 if(len!==undefined)headers['content-length']=String(len);
 const r=new Response(body,{status,headers});
 Object.defineProperty(r,'url',{value:url});
 return r;
};
test('CN: official empty main ruleset listing is real missing control, not release go',()=>{
 const r=evaluate(base());
 assert.equal(r.officialReadOnlySourceChainStructurallyValid,true,r.anomalyCodes.join(','));
 assert.equal(r.listedRulesetCount,0);
 assert.equal(r.activeBranchRulesetCount,0);
 assert.equal(r.exactProposalMatchingRulesetCount,0);
 check(r,'CN_NO_REPOSITORY_RULESETS_OBSERVED');
 check(r,'CN_GITHUB_EFFECTIVE_MAIN_RULES_EMPTY');
 check(r,'CN_GENUINE_CURRENT_HEAD_APPROVAL_QUORUM_ABSENT');
 check(r,'CN_MAIN_CODEOWNERS_NOT_OBSERVED');
 assert.equal(r.actualMainRulesetAuthorizedAndEnforced,false);
 assert.equal(r.configuredAdminAndAppBypassAbsenceIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CN: active installed proposal match with BY applied rules drift is flagged, not signed',()=>{
 const r=evaluate(fixtureWithRule(true));
 assert.equal(r.exactProposalMatchingRulesetCount,1);
 check(r,'CN_OFFICIAL_APPLIED_BRANCH_RULES_DISAGREE_WITH_RULESET_DETAILS');
 assert.equal(r.configuredAdminAndAppBypassAbsenceIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CN: GitHub hides bypass_actors from read-only users; missing member is UNKNOWN not []',()=>{
 const r=evaluate(fixtureWithRule(false));
 assert.equal(r.exactProposalMatchingRulesetCount,1);
 assert.equal(r.rulesetListAndAllBypassFieldsReadable,false);
 assert.equal(r.bypassFieldHiddenOnReadOnlySourceCount,1);
 assert.equal(r.detailRecords[0].configuredBypassActorCountVisible,null);
 check(r,'CN_GITHUB_RULESET_BYPASS_ACTORS_NOT_VISIBLE');
 assert.equal(r.actualMainRulesetAuthorizedAndEnforced,false);
});
test('CN: configured bypass actors seen in official response block independent no-bypass proof',()=>{
 const x=fixtureWithRule(true);
 x.observations.details['42'].bypass_actors=[
  {actor_type:'RepositoryRole',actor_id:5,bypass_mode:'always'}
 ];
 const r=evaluate(x);
 assert.equal(r.configuredBypassActorsObservedCount,1);
 check(r,'CN_CONFIGURED_BYPASS_ACTORS_OBSERVED');
 assert.equal(r.configuredAdminAndAppBypassAbsenceIndependentlyVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CN: visible empty bypass field is still not independent administrator bypass proof',()=>{
 const r=evaluate(fixtureWithRule(true));
 assert.equal(r.bypassFieldHiddenOnReadOnlySourceCount,0);
 assert.equal(r.configuredBypassActorsObservedCount,0);
 assert.equal(r.configuredAdminAndAppBypassAbsenceIndependentlyVerified,false);
 assert.equal(r.independentSecurityAndBusinessRolesAuthenticated,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CN: stale or weakened actual main ruleset cannot match intended strict proposed controls',()=>{
 for(const update of [
  r=>r.enforcement='disabled',
  r=>r.conditions.ref_name.include=['refs/heads/dev'],
  r=>r.rules.find(x=>x.type==='pull_request')
   .parameters.required_approving_review_count=1,
  r=>r.rules.find(x=>x.type==='pull_request')
   .parameters.require_last_push_approval=false,
  r=>r.rules.find(x=>x.type==='pull_request')
   .parameters.require_code_owner_review=false,
  r=>r.rules.find(x=>x.type==='required_status_checks')
   .parameters.strict_required_status_checks_policy=false,
  r=>r.rules.find(x=>x.type==='required_status_checks')
   .parameters.required_status_checks[0].context='rogue'
 ]){
  const x=fixtureWithRule(true);
  update(x.observations.details['42']);
  if(x.observations.details['42'].enforcement==='disabled')
   x.observations.listed[0].enforcement='disabled';
  const out=evaluate(x);
  assert.equal(out.exactProposalMatchingRulesetCount,0);
  assert.equal(out.productionReleaseAuthorized,false);
 }
});
test('CN: spoofed ruleset id, name, enforcement or denied GET details remain UNKNOWN',()=>{
 for(const modify of [
  x=>x.observations.detailStatus['42']='access_denied',
  x=>x.observations.details['42'].id=43,
  x=>x.observations.details['42'].name='different',
  x=>x.observations.details['42'].target='tag'
 ]){
  const x=fixtureWithRule(true);modify(x);
  const r=evaluate(x);
  check(r,'CN_RULESET_DETAIL_UNAVAILABLE_OR_MISMATCH');
  assert.equal(r.rulesetListAndAllBypassFieldsReadable,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CN: unavailable, access denied, hidden, or truncated ruleset listing never yields approved no-bypass',()=>{
 for(const status of ['unavailable','access_denied','not_found_or_hidden','incomplete_pagination']){
  const x=base();x.observations.listStatus=status;x.observations.listingComplete=false;
  const r=evaluate(x);
  check(r,'CN_OFFICIAL_RULESET_LIST_UNAVAILABLE_OR_INCOMPLETE');
  assert.equal(r.listedRulesetCount,null);
  assert.equal(r.configuredAdminAndAppBypassAbsenceIndependentlyVerified,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CN: no forged proposed ruleset can weaken eight CI jobs, bypass actors or two-review rule',()=>{
 for(const change of [
  r=>r.bypass_actors.push({actor_id:5,actor_type:'RepositoryRole',bypass_mode:'always'}),
  r=>r.rules[2].parameters.required_approving_review_count=1,
  r=>r.rules[3].parameters.required_status_checks[0].context='fake'
 ]){
  const x=base();change(x.proposal);
  const r=evaluate(x);
  check(r,'CN_UNREVIEWED_LOCAL_GITHUB_RULESET_PROPOSAL');
  assert.equal(r.officialReadOnlySourceChainStructurallyValid,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CN: fake BY GitHub read-only source or changed PR head is rejected',()=>{
 for(const change of [
  x=>x.byReport.kind='FORGED',
  x=>x.byReport.sourceBundleSha256='bad',
  x=>x.byReport.snapshotDerived.eventSourceHeadAndBaseMatch=false,
  x=>x.byReport.snapshotDerived.observedPrDraftAndUnmerged=false,
  x=>x.byReport.snapshotDerived.releaseDecision='GO'
 ]){
  const x=base();change(x);
  const r=evaluate(x);
  check(r,'CN_ACTUAL_GITHUB_PR_AND_BRANCH_SOURCE_CUSTODY_INVALID');
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CN: fake CL CODEOWNERS selected source, external signature or authorization rejected',()=>{
 for(const change of [
  x=>x.clReport.sourceExternallySigned=true,
  x=>x.clReport.decision.officialPublicObservationStructurallyValid=false,
  x=>x.clReport.decision.observedDevHeadSha='e'.repeat(40),
  x=>x.clReport.decision.releaseDecision='GO'
 ]){
  const x=base();change(x);
  const r=evaluate(x);
  check(r,'CN_CODEOWNERS_OBSERVER_CUSTODY_INVALID');
  assert.equal(r.officialReadOnlySourceChainStructurallyValid,false);
 }
});
test('CN: wrong repository, arbitrary ref, wrong checkout or branch job fails closed',()=>{
 for(const envChange of [
  {GITHUB_ACTIONS:'false'},
  {GITHUB_REPOSITORY:'attacker/fork'},
  {GITHUB_REF:'refs/heads/main'},
  {GITHUB_JOB:'baseline'},
  {GITHUB_SHA:'not-a-sha'},
  {GITHUB_SHA:'f'.repeat(40)}
 ]){
  const x=base();x.environment={...env,...envChange};
  check(evaluate(x),'CN_GITHUB_RUN_SOURCE_JOB_OR_PR_SHA_INVALID');
 }
});
test('CN: null-prototype genuine process.env is supported, absent context denied',()=>{
 const x=base();x.environment=Object.assign(Object.create(null),env);
 assert.equal(evaluate(x).officialReadOnlySourceChainStructurallyValid,true);
 x.environment=null;
 check(evaluate(x),'CN_GITHUB_RUN_SOURCE_JOB_OR_PR_SHA_INVALID');
});
test('CN: fixed GitHub REST list/detail paths reject attacker-controlled URL and illegal page',()=>{
 assert.equal(rulesetListPath(1),'/rulesets?per_page=100&page=1&includes_parents=true&targets=branch');
 assert.equal(rulesetDetailPath(42),'/rulesets/42?includes_parents=true');
 for(const page of [-1,0,3,'2',1.5])
  assert.throws(()=>rulesetListPath(page),/CN_UNAPPROVED_PAGE/);
 for(const id of ['../admin','0','01','not-integer','99999999999999999999'])
  assert.throws(()=>rulesetDetailPath(id),/CN_UNAPPROVED_RULESET_ID/);
});
test('CN: real official GETs fixed origin, no redirect, bounded response and zero extra privilege',async()=>{
 const path=rulesetListPath(1),url='https://api.github.com/repos/'+REPO+path;
 const r=await readOfficialRulesets(path,'test-token',async(u,opts)=>{
  assert.equal(u,url);
  assert.equal(opts.method,'GET');
  assert.equal(opts.redirect,'error');
  assert.equal(opts.cache,'no-store');
  return response(url,'[]');
 });
 assert.equal(r.status,'read');
 await assert.rejects(()=>readOfficialRulesets(
  '/rulesets?per_page=100&page=1&redirect_to=evil','test-token'),
  /CN_UNREVIEWED_GITHUB_ROUTE/);
 for(const item of [
  [response(url,'{}',{status:403}),'access_denied'],
  [response(url,'{}',{status:404}),'not_found_or_hidden'],
  [response(url,'{}',{status:429}),'unavailable'],
  [response('https://evil.example','[]'),'invalid'],
  [response(url,'[]',{mime:'text/html'}),'invalid'],
  [response(url,'[]',{len:200000}),'invalid'],
  [response(url,'['+' '.repeat(131200)+']'),'invalid']
 ]){
  const rr=await readOfficialRulesets(path,'token',async()=>item[0]);
  assert.equal(rr.status,item[1]);
 }
});
test('CN: actual zero-list API call cannot invent detail URLs or independent reviewer approvals',async()=>{
 const path=rulesetListPath(1),url='https://api.github.com/repos/'+REPO+path;
 let count=0;
 const list=await collectActualRulesets({token:'token',fetchImpl:async(u)=>{
  count++;
  assert.equal(u,url);
  return response(url,'[]');
 }});
 assert.equal(count,1);
 assert.equal(list.listStatus,'read');
 assert.equal(list.listingComplete,true);
 assert.deepEqual(list.listed,[]);
 assert.deepEqual(list.details,{});
 assert.equal(evaluate({...base(),observations:list}).productionReleaseAuthorized,false);
});
test('CN: bounded official list with one rule fetches only server-derived numeric ID',async()=>{
 const url='https://api.github.com/repos/'+REPO;
 const rule=example(42,false);
 const listURL=url+rulesetListPath(1);
 const detailURL=url+rulesetDetailPath(42);
 const requested=[];
 const observations=await collectActualRulesets({token:'token',fetchImpl:async u=>{
  requested.push(u);
  if(u===listURL)return response(u,JSON.stringify([
   {id:42,name:rule.name,target:'branch',enforcement:'active'}
  ]));
  if(u===detailURL)return response(u,JSON.stringify(rule));
  throw Error('unexpected request');
 }});
 assert.deepEqual(requested,[listURL,detailURL]);
 const result=evaluate({...base(),observations});
 assert.equal(result.bypassFieldHiddenOnReadOnlySourceCount,1);
 assert.equal(result.productionReleaseAuthorized,false);
});
test('CN: list injection, >12 rulesets and duplicate IDs never fetch arbitrary rule detail URLs',async()=>{
 const url='https://api.github.com/repos/'+REPO+rulesetListPath(1);
 for(const records of [
  [{id:'../attack',name:'bad'}],
  Array.from({length:13},(_,i)=>({id:i+1})),
  [{id:1},{id:1}],
  [{}]
 ]){
  let count=0;
  const result=await collectActualRulesets({token:'token',fetchImpl:async u=>{
   count++;
   assert.equal(u,url);
   return response(u,JSON.stringify(records));
  }});
  assert.equal(count,1);
  assert.notEqual(result.listStatus,'read');
  assert.equal(result.listingComplete,false);
 }
});
