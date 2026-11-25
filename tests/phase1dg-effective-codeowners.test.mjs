import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {REPO,CODEOWNERS_PRECEDENCE,assessPinnedMainCodeowners,
 readPinnedMainCodeowners} from '../scripts/phase1dg-effective-codeowners.mjs';
const MAIN='b'.repeat(40),HEAD='a'.repeat(40);
const security='security-validated',business='business-validated';
const ownerText='# reviewed proposal\n* @security-validated @business-validated\n'+
 '/.github/CODEOWNERS @security-validated @business-validated\n'+
 '/scripts/ @business-validated @security-validated\n';
const blob=(path,content=ownerText)=>{
 const bytes=Buffer.from(content);
 const sha=createHash('sha1').update(Buffer.from('blob '+bytes.length+'\0'))
  .update(bytes).digest('hex');
 return {type:'file',path,encoding:'base64',sha,size:bytes.length,
  content:bytes.toString('base64')};
};
const joined=()=>({phase:'1DF',schemaVersion:1,repository:REPO,
 candidateCrossSourceTechnicalApprovalJoinOnly:true,
 exactSourceAndMainStableAcrossOfficialReadsOnly:true,
 effectiveBaseMainGovernanceReadableOnly:true,
 currentDevelopmentHeadSha:HEAD,currentMainBaseSha:MAIN,
 productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
const absent=()=>Object.fromEntries(CODEOWNERS_PRECEDENCE.map(path=>[path,
 {status:'absent_or_hidden',data:null}]));
const withFile=(path='.github/CODEOWNERS',text=ownerText)=>{
 const obj=absent();obj[path]={status:'read',data:blob(path,text)};return obj;
};
const inputs=()=>({roleJoin:joined(),securityLogin:security,businessLogin:business,
 observedFirst:withFile(),observedSecond:withFile()});
function check(change){const x=inputs();change?.(x);return assessPinnedMainCodeowners(x)}
function hold(x){assert.equal(x.productionReleaseAuthorized,false);
 assert.equal(x.productionReleaseBlocked,true);
 assert.equal(x.releaseDecision,'HOLD');
 assert.equal(x.independentlyAuthenticatedCorporateSecurityBusinessMandates,false);
 assert.equal(x.effectiveMainRulesetOrAdminNonbypassApproved,false);
 assert.equal(x.providerCaMcaWormDrOidcAndStagingAccepted,false);
 assert.equal(x.canModifyMainRequestReviewsMergeOrDeploy,false);}
function deny(change,code){const x=check(change);hold(x);
 assert.equal(x.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,false);
 assert.ok(x.anomalyCodes.includes(code),x.anomalyCodes.join(','));return x;}
test('DG: fully consistent synthetic pinned highest-precedence file is only technical, never GO',()=>{
 const x=check();hold(x);assert.equal(x.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,true);
 assert.equal(x.effectiveCodeownersPath,'.github/CODEOWNERS');
 assert.deepEqual(x.anomalyCodes,[]);
});
test('DG: absence of any input cannot be promoted to GO',()=>{
 const x=assessPinnedMainCodeowners();hold(x);assert.equal(x.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,false);
});
test('DG: missing all three standard paths fails closed',()=>{
 const x=deny(i=>{i.observedFirst=absent();i.observedSecond=absent()},
  'DG_NO_BASE_MAIN_CODEOWNERS_INSTALLED');assert.equal(x.effectiveCodeownersPath,null);
});
test('DG: GitHub precedence selects .github file and never a lower root shadow',()=>{
 const x=check(i=>{for(const key of ['observedFirst','observedSecond']){
  i[key]['CODEOWNERS']={status:'read',data:blob('CODEOWNERS','* @other @someone\n')};
 }});hold(x);assert.equal(x.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,true);
});
test('DG: malformed high-priority file cannot fall back to valid lower-priority file',()=>{
 deny(i=>{for(const key of ['observedFirst','observedSecond']){
  i[key]['.github/CODEOWNERS'].data.content='@malformed';
  i[key]['CODEOWNERS']={status:'read',data:blob('CODEOWNERS')};
 }},'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: absent upper files allow exact pinned root CODEOWNERS only',()=>{
 const x=check(i=>{i.observedFirst=withFile('CODEOWNERS');i.observedSecond=withFile('CODEOWNERS')});
 hold(x);assert.equal(x.effectiveCodeownersPath,'CODEOWNERS');
 assert.equal(x.effectiveFilePrecedenceAndAllOwnerRulesCheckedOnly,true);
});
test('DG: deny unauthorized owner token, inline override and unknown wildcard',()=>{
 for(const row of ['* @security-validated @other',
  '*.ts @security-validated @business-validated',
  '* @security-validated @business-validated # unreviewed',
  '!*.md @security-validated @business-validated']){
  deny(i=>{i.observedFirst=withFile('.github/CODEOWNERS',ownerText+'\n'+row+'\n');
    i.observedSecond=withFile('.github/CODEOWNERS',ownerText+'\n'+row+'\n')},
   'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
 }
});
test('DG: no root wildcard denies narrower document patterns',()=>{
 deny(i=>{i.observedFirst=withFile('.github/CODEOWNERS',
  '/scripts/ @security-validated @business-validated\n');
  i.observedSecond=structuredClone(i.observedFirst)},
 'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: duplicate matching patterns and override attempts fail closed',()=>{
 deny(i=>{i.observedFirst=withFile('.github/CODEOWNERS',ownerText+'\n'+
  '/scripts/ @security-validated @business-validated\n');
  i.observedSecond=structuredClone(i.observedFirst)},
 'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: fake git SHA or reported file size never authenticates content',()=>{
 deny(i=>{i.observedSecond['.github/CODEOWNERS'].data.sha='a'.repeat(40)},
  'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
 deny(i=>{i.observedSecond['.github/CODEOWNERS'].data.size+=1},
  'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: owner file changed between pinned reads cannot be silently accepted',()=>{
 deny(i=>{i.observedSecond=withFile('.github/CODEOWNERS',
  '# second snapshot\n* @security-validated @business-validated\n')},
  'DG_PINNED_CODEOWNERS_MISMATCH_OR_REPLACEMENT');
});
test('DG: 403 UNKNOWN anywhere does not turn into absent or proof of an installed file',()=>{
 deny(i=>{i.observedSecond['docs/CODEOWNERS']={status:'access_denied',data:null}},
  'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: mismatched review/head joint snapshot refuses owner promotion',()=>{
 deny(i=>{i.roleJoin.candidateCrossSourceTechnicalApprovalJoinOnly=false},
  'DG_INDEPENDENT_ROLE_SPECIFIC_TECHNICAL_JOIN_NOT_OBSERVED');
 deny(i=>{i.roleJoin.currentMainBaseSha='not-a-sha'},
  'DG_INDEPENDENT_ROLE_SPECIFIC_TECHNICAL_JOIN_NOT_OBSERVED');
});
test('DG: nominee syntax, author and duplicate accounts denied',()=>{
 for(const change of [i=>i.securityLogin='j9619655391-max',
  i=>i.businessLogin=security,i=>i.securityLogin='bad/name'])
  deny(change,'DG_DISTINCT_AUTHORIZED_NONAUTHOR_NOMINEES_REQUIRED');
});
test('DG: invalid UTF8, BOM and control bytes fail closed',()=>{
 for(const raw of ['\uFEFF* @security-validated @business-validated\n',
  '* @security-validated @business-validated\u0000\n'])
  deny(i=>{i.observedFirst=withFile('.github/CODEOWNERS',raw);
   i.observedSecond=withFile('.github/CODEOWNERS',raw)},
   'DG_EFFECTIVE_MAIN_CODEOWNERS_UNREADABLE_OR_UNSAFE');
});
test('DG: operator receipt includes no token or GitHub usernames',()=>{
 const serialized=JSON.stringify(check());
 for(const needle of [security,business,'GITHUB_READ_TOKEN','Bearer '])
  assert.equal(serialized.includes(needle),false);
});
test('DG: pinned reader denies moving ref, guessed path and missing token',async()=>{
 await assert.rejects(()=>readPinnedMainCodeowners('README.md',MAIN,'x'),/DG_REJECT/);
 await assert.rejects(()=>readPinnedMainCodeowners('CODEOWNERS','main','x'),/DG_REJECT/);
 assert.deepEqual(await readPinnedMainCodeowners('CODEOWNERS',MAIN,''),
  {status:'unavailable',data:null});
});
test('DG: pinned reader only performs bounded GET with no redirect',async()=>{
 let called=0;
 const get=async(url,request)=>{called++;
  assert.equal(request.method,'GET');assert.equal(request.redirect,'error');
  assert.equal(url,'https://api.github.com/repos/'+REPO+'/contents/CODEOWNERS?ref='+MAIN);
  const contents=Buffer.from(JSON.stringify(blob('CODEOWNERS')));
  return {status:200,url,redirected:false,
   headers:{get:key=>key==='content-type'?'application/json':null},
   body:{getReader(){let done=false;return {async read(){
    if(done)return {done:true};done=true;return {done:false,value:contents};
   }}}}};
 };
 const result=await readPinnedMainCodeowners('CODEOWNERS',MAIN,'authorized-token',get);
 assert.equal(result.status,'read');assert.equal(called,1);
});
test('DG: official reader refuses redirect and 403 is never declared absence',async()=>{
 const fake=async(url)=>({status:200,url,redirected:true,headers:{get:()=> 'application/json'}});
 assert.equal((await readPinnedMainCodeowners('CODEOWNERS',MAIN,'token',fake)).status,'invalid');
 const denied=async()=>({status:403});
 assert.equal((await readPinnedMainCodeowners('CODEOWNERS',MAIN,'token',denied)).status,'access_denied');
});
test('DG: CLI requires out-of-CI explicit human execution; no write methods',()=>{
 const text=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1dg-effective-codeowners.mjs'),'utf8');
 assert.ok(text.includes("process.env.GITHUB_ACTIONS==='true'"));
 assert.ok(text.includes('--inspect-pinned-main-codeowners-readonly'));
 assert.equal(/method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/.test(text),false);
});
