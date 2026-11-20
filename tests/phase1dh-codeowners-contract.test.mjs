import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,AUTHOR,proposedCodeowners}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {REVIEWED_CODEOWNER_PATTERNS,validOwners,assessActualReadOnlyHandoff}
 from '../scripts/phase1dc-live-external-governance-readiness.mjs';
import {assessPinnedMainCodeowners,CODEOWNERS_PRECEDENCE}
 from '../scripts/phase1dg-effective-codeowners.mjs';

const SECURITY='security-appointed',BUSINESS='business-appointed';
const HEAD='a'.repeat(40),MAIN='b'.repeat(40);
const official=data=>({status:'read',data,httpStatus:200});
const absent={status:'absent_or_hidden',data:null,httpStatus:404};
const restricted={status:'access_denied',data:null,httpStatus:403};
const proposal=proposedCodeowners(SECURITY,BUSINESS).content;
function file(text,path='.github/CODEOWNERS'){
 const raw=Buffer.from(text,'utf8');
 const sha=createHash('sha1').update(Buffer.from('blob '+raw.length+'\0'))
  .update(raw).digest('hex');
 return {type:'file',path,sha,encoding:'base64',
  size:raw.length,content:raw.toString('base64')};
}
function reportFromPaths(paths){
 return assessActualReadOnlyHandoff({codeowners:{
  githubCodeowners:paths?.githubCodeowners??absent,
  rootCodeowners:paths?.rootCodeowners??absent,
  docsCodeowners:paths?.docsCodeowners??absent
 }});
}
function dgReceipt(data=file(proposal),path='.github/CODEOWNERS'){
 const roleJoin={phase:'1DF',schemaVersion:1,repository:REPO,
  candidateCrossSourceTechnicalApprovalJoinOnly:true,
  exactSourceAndMainStableAcrossOfficialReadsOnly:true,
  effectiveBaseMainGovernanceReadableOnly:true,
  currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'};
 const fresh=()=>Object.fromEntries(CODEOWNERS_PRECEDENCE.map(key=>[
  key,key===path?{status:'read',data}:{status:'absent_or_hidden',data:null}
 ]));
 return assessPinnedMainCodeowners({roleJoin,securityLogin:SECURITY,
  businessLogin:BUSINESS,observedFirst:fresh(),observedSecond:fresh()});
}
function hold(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
function invalid(text){
 const x=validOwners(file(text),'.github/CODEOWNERS');
 assert.equal(x.rootCovers,false,text);
}
test('DH: 1CM real multi-pattern proposed CODEOWNERS is compatible with 1DC',()=>{
 const r=validOwners(file(proposal),'.github/CODEOWNERS');
 assert.deepEqual(r,{valid:true,rootCovers:true});
 assert.equal(REVIEWED_CODEOWNER_PATTERNS.length,7);
 assert.equal(proposal.split('\n').filter(x=>x.startsWith('/')).length,6);
});
test('DH: 1CM -> 1DC -> 1DG same exact multi-line owner proposal never becomes release GO',()=>{
 const f=file(proposal);
 const dc=reportFromPaths({githubCodeowners:official(f)});
 assert.equal(dc.strictRootCoverageCodeownersFiles,1);
 assert.equal(dc.observedCodeownersFileCount,1);
 hold(dc);
 const dg=dgReceipt(f);
 assert.equal(dg.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,true,
  dg.anomalyCodes.join('|'));
 hold(dg);
 assert.equal(dg.independentlyAuthenticatedCorporateSecurityBusinessMandates,false);
 assert.equal(dg.effectiveMainRulesetOrAdminNonbypassApproved,false);
});
test('DH: accepts prior canonical one-line wildcard as backward-compatible technical subset',()=>{
 const r=validOwners(file('* @'+SECURITY+' @'+BUSINESS+'\n'),'.github/CODEOWNERS');
 assert.deepEqual(r,{valid:true,rootCovers:true});
});
test('DH: swapped legitimate nominee order does not weaken two-person ownership mapping',()=>{
 const text='* @'+SECURITY+' @'+BUSINESS+'\n/scripts/ @'+BUSINESS+' @'+SECURITY+'\n';
 assert.equal(validOwners(file(text),'.github/CODEOWNERS').rootCovers,true);
});
test('DH: identical real nominee pair every rule, case insensitive, does not imply authenticated mandate',()=>{
 const text='* @'+SECURITY+' @'+BUSINESS+'\n/scripts/ @'+SECURITY.toUpperCase()+' @'+BUSINESS+'\n';
 const result=reportFromPaths({githubCodeowners:official(file(text))});
 assert.equal(result.strictRootCoverageCodeownersFiles,1);
 hold(result);
 assert.equal(result.legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated,false);
});
test('DH: first existing higher-precedence valid file wins, not a union of three',()=>{
 const report=reportFromPaths({
  githubCodeowners:official(file(proposal)),
  rootCodeowners:official(file('* @other-one @other-two\n','CODEOWNERS'))
 });
 assert.equal(report.strictRootCoverageCodeownersFiles,1);
 hold(report);
});
test('DH: malformed .github CODEOWNERS cannot be rescued by valid root',()=>{
 const report=reportFromPaths({
  githubCodeowners:official(file('* @'+SECURITY+' @'+BUSINESS+
   '\n/scripts/ @'+SECURITY+' @unappointed\n')),
  rootCodeowners:official(file(proposal,'CODEOWNERS'))
 });
 assert.equal(report.strictRootCoverageCodeownersFiles,0);
 assert.ok(report.anomalyCodes.includes(
  'DC_CODEOWNERS_EXISTS_BUT_STRICT_MAIN_COVERAGE_NOT_PROVEN_githubCodeowners'));
 hold(report);
});
test('DH: .github missing permits legitimate root CODEOWNERS',()=>{
 const r=reportFromPaths({rootCodeowners:official(file(proposal,'CODEOWNERS'))});
 assert.equal(r.strictRootCoverageCodeownersFiles,1);hold(r);
});
test('DH: higher root file lacking wildcard prevents lower docs rescue',()=>{
 const r=reportFromPaths({
  rootCodeowners:official(file('/scripts/ @'+SECURITY+' @'+BUSINESS+'\n','CODEOWNERS')),
  docsCodeowners:official(file(proposal,'docs/CODEOWNERS'))
 });
 assert.equal(r.strictRootCoverageCodeownersFiles,0);hold(r);
});
test('DH: unknown higher-precedence access blocks lower valid CODEOWNERS',()=>{
 const r=reportFromPaths({
  githubCodeowners:restricted,rootCodeowners:official(file(proposal,'CODEOWNERS'))
 });
 assert.ok(r.anomalyCodes.includes('DC_CODEOWNERS_SOURCE_ACCESS_UNKNOWN'));
 assert.equal(r.technicallyObservedGithubPrerequisitesOnly,false);hold(r);
});
test('DH: unknown pattern and wildcard shadow are always denied',()=>{
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n/src/ @'+SECURITY+' @'+BUSINESS+'\n');
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n** @'+SECURITY+' @'+BUSINESS+'\n');
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n[ab]* @'+SECURITY+' @'+BUSINESS+'\n');
});
test('DH: duplicate rule or conflicting later owner is rejected',()=>{
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n* @'+SECURITY+' @'+BUSINESS+'\n');
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n/scripts/ @'+SECURITY+' @outsider\n');
});
test('DH: single owner, self owner and duplicate user fail closed',()=>{
 invalid('* @'+SECURITY+'\n');
 invalid('* @'+SECURITY+' @'+SECURITY+'\n');
 invalid('* @'+AUTHOR+' @'+BUSINESS+'\n');
});
test('DH: no global coverage never equals installed main CODEOWNERS',()=>{
 invalid('/scripts/ @'+SECURITY+' @'+BUSINESS+'\n');
 invalid('# ignored\n');
});
test('DH: unreviewed inline comment, tabs in owner and more than seven lines denied',()=>{
 invalid('* @'+SECURITY+' @'+BUSINESS+' # claimed\n');
 invalid('* @'+SECURITY+' @'+BUSINESS+'\n/tests/ @'+SECURITY+' @'+BUSINESS+'\n/tests/ @'+SECURITY+' @'+BUSINESS+'\n');
});
test('DH: invalid binary, bare CR, BOM and invalid UTF8 fail closed',()=>{
 for(const text of ['\uFEFF* @'+SECURITY+' @'+BUSINESS+'\n',
  '* @'+SECURITY+' @'+BUSINESS+'\r/scripts/ @'+SECURITY+' @'+BUSINESS+'\n',
  '* @'+SECURITY+' @'+BUSINESS+'\0\n'])invalid(text);
 const f=file(proposal),raw=Buffer.from([255,254,0]);
 f.content=raw.toString('base64');f.size=raw.length;
 const r=validOwners(f,'.github/CODEOWNERS');
 assert.equal(r.rootCovers,false);
});
test('DH: mismatched path, size, unsupported encoding and SHA metadata reject',()=>{
 const f=file(proposal);
 for(const mutate of [
  x=>{x.path='CODEOWNERS'},
  x=>{x.size=999},
  x=>{x.sha='z'.repeat(40)},
  x=>{x.encoding='hex'},
  x=>{x.content='not-base64!!'}
 ]){
  const x={...f};mutate(x);
  assert.equal(validOwners(x,'.github/CODEOWNERS').rootCovers,false);
 }
});
test('DH: 403 main protection and no rules/real corporate mandates remain HOLD, even valid layout',()=>{
 const r=reportFromPaths({githubCodeowners:official(file(proposal))});
 assert.equal(r.strictRootCoverageCodeownersFiles,1);
 assert.equal(r.technicallyObservedGithubPrerequisitesOnly,false);
 assert.equal(r.legalSecurityBusinessIdentityNominationsIndependentlyAuthenticated,false);
 hold(r);
});
test('DH: reviewed whitelist cannot be bypassed by huge or repeated rule set',()=>{
 const lines=['* @'+SECURITY+' @'+BUSINESS];
 for(const p of REVIEWED_CODEOWNER_PATTERNS.slice(1))
  lines.push(p+' @'+SECURITY+' @'+BUSINESS);
 lines.push('/tests/ @'+SECURITY+' @'+BUSINESS);
 invalid(lines.join('\n')+'\n');
});
test('DH: no CI/admin/GitHub write or external authority is added by narrow parser change',()=>{
 const src=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dc-live-external-governance-readiness.mjs'),'utf8');
 assert.equal(src.includes('REVIEWED_CODEOWNER_PATTERNS'),true);
 assert.equal(src.includes('if(!selectedEffective)'),true);
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(src),false);
 const r=validOwners(file(proposal),'.github/CODEOWNERS');
 assert.equal(r.rootCovers,true);
});
