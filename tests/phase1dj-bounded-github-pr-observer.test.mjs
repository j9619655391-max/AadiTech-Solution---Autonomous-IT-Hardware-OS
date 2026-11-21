import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
 BY_MAX_API_JSON_BYTES,BY_MAX_PR_DESCRIPTION_BYTES,
 readOfficialGithubEndpoint,assessObservedGithubGovernance
} from '../scripts/phase1by-github-governance-observer.mjs';

const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const PATH='/repos/'+REPO+'/pulls/1',TOKEN='synthetic-test-token';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),MERGE='c'.repeat(40);
function respond(body,{status=200,mime='application/json',
 len,redirected=false,urlOverride,chunkSize=body.length||1,failText=false}={}){
 const bytes=Buffer.isBuffer(body)?body:Buffer.from(body,'utf8');
 const readChunks={n:0};
 return {
  readChunks,
  fetchImpl:async(url,request)=>{
   assert.equal(request.method,'GET');assert.equal(request.redirect,'error');
   assert.equal(request.cache,'no-store');
   assert.ok(request.signal);
   assert.equal(request.headers.Authorization,'Bearer '+TOKEN);
   const response={
    status,url:urlOverride??url,redirected,
    headers:{get:key=>key==='content-type'?mime:
     key==='content-length'?len??null:null},
    body:{getReader(){
     let off=0;
     return {async read(){
      readChunks.n++;
      if(off>=bytes.length)return {done:true};
      const v=bytes.subarray(off,Math.min(bytes.length,off+chunkSize));
      off+=v.length;
      return {done:false,value:v};
     }};
    }}
   };
   if(failText)response.text=()=>{throw Error('MUST_NOT_READ_UNBOUNDED_TEXT');};
   return response;
  }
 };
}
const exec=(body,opts={})=>readOfficialGithubEndpoint(PATH,TOKEN,{
 fetchImpl:respond(body,opts).fetchImpl
});
const validJSON='{"proof":"untrusted-public-json"}';
const miniPR=body=>({
 number:1,state:'open',draft:true,merged:false,
 merge_commit_sha:MERGE,user:{login:'j9619655391-max'},
 head:{ref:'chore/phase0-foundation-20261106',sha:HEAD,repo:{full_name:REPO}},
 base:{ref:'main',sha:BASE,repo:{full_name:REPO}},
 ...(body===undefined?{}:{body})
});
function by(body){
 return assessObservedGithubGovernance({
  repository:REPO,githubRef:'refs/pull/1/merge',
  githubSha:MERGE,eventHeadSha:HEAD,eventBaseSha:BASE,
  githubHeadRef:'chore/phase0-foundation-20261106',
  githubBaseRef:'main',eventName:'pull_request',
  endpoints:{
   pr:{status:'read',data:miniPR(body)},
   reviews:{status:'read',data:[]},
   rules:{status:'read',data:[]},
   protection:{status:'access_denied',data:null}
  }
 });
}
function hold(x){
 assert.equal(x.productionReleaseAuthorized,false);
 assert.equal(x.productionReleaseBlocked,true);
 assert.equal(x.releaseDecision,'HOLD');
}
test('DJ streaming JSON read returns only bounded official object, never production GO',async()=>{
 const v=await exec(validJSON,{chunkSize:3,failText:true});
 assert.equal(v.status,'read');assert.equal(v.data.proof,'untrusted-public-json');
});
test('DJ fixed 192 KiB JSON byte cap and 8 KiB PR evidence-index byte cap',()=>{
 assert.equal(BY_MAX_API_JSON_BYTES,196608);
 assert.equal(BY_MAX_PR_DESCRIPTION_BYTES,8192);
 assert.ok(BY_MAX_PR_DESCRIPTION_BYTES<BY_MAX_API_JSON_BYTES);
});
test('DJ missing content-length remains safely streamed with bounded chunks',async()=>{
 const res=respond(validJSON,{len:null,chunkSize:2});
 const v=await readOfficialGithubEndpoint(PATH,TOKEN,{fetchImpl:res.fetchImpl});
 assert.equal(v.status,'read');
 assert.ok(res.readChunks.n>2);
});
test('DJ exact maximum byte JSON boundary is readable under streaming bound',async()=>{
 const prefix=JSON.stringify({x:''});
 const body=JSON.stringify({x:'a'.repeat(BY_MAX_API_JSON_BYTES-Buffer.byteLength(prefix))});
 assert.equal(Buffer.byteLength(body),BY_MAX_API_JSON_BYTES);
 const v=await exec(body,{chunkSize:32768});
 assert.equal(v.status,'read');
 assert.equal(v.data.x.length,BY_MAX_API_JSON_BYTES-prefix.length);
});
test('DJ one byte past API response cap is rejected without unbounded text read',async()=>{
 const prefix=JSON.stringify({x:''});
 const body=JSON.stringify({x:'b'.repeat(BY_MAX_API_JSON_BYTES-prefix.length+1)});
 const res=respond(body,{chunkSize:30000,failText:true});
 const v=await readOfficialGithubEndpoint(PATH,TOKEN,{fetchImpl:res.fetchImpl});
 assert.equal(v.status,'oversize');assert.equal(v.data,null);
 assert.ok(res.readChunks.n<=8);
});
test('DJ declared oversize before stream reader is consumed',async()=>{
 const v=await exec(validJSON,{len:String(BY_MAX_API_JSON_BYTES+1)});
 assert.equal(v.status,'oversize');
});
test('DJ invalid claimed content-length is untrusted and rejected closed',async()=>{
 for(const len of ['-1','NaN','1e9','1.1','0x10',' 90','999999999999999999999'])
  assert.equal((await exec(validJSON,{len})).status,'invalid',len);
});
test('DJ redirect flag even with otherwise valid source JSON is invalid',async()=>{
 assert.equal((await exec(validJSON,{redirected:true})).status,'invalid');
});
test('DJ endpoint URL mutation to different host is invalid even with strict fetch redirect',async()=>{
 assert.equal((await exec(validJSON,{urlOverride:'https://example.invalid/steal'})).status,'invalid');
});
test('DJ URL mutation to different path and query string is invalid',async()=>{
 for(const url of ['https://api.github.com/repos/other/x/pulls/1',
  'https://api.github.com'+PATH+'?page=2'])
  assert.equal((await exec(validJSON,{urlOverride:url})).status,'invalid');
});
test('DJ malformed or missing JSON MIME is rejected',async()=>{
 for(const mime of [null,'text/html','text/plain','application/octet-stream',
  'application/jsonp','application/xml'])
  assert.equal((await exec(validJSON,{mime})).status,'invalid',String(mime));
});
test('DJ GitHub compatible JSON MIME and charset accepted',async()=>{
 for(const mime of ['application/json; charset=utf-8','application/vnd.github+json']){
  const v=await exec(validJSON,{mime});
  assert.equal(v.status,'read',mime);
 }
});
test('DJ invalid JSON and invalid UTF-8 bytes fail closed with no raw payload echo',async()=>{
 assert.equal((await exec('{"secret":"never-report",')).status,'invalid');
 const invalid=Buffer.from([0x7b,0x22,0x61,0x22,0x3a,0x22,0xff,0x22,0x7d]);
 const v=await exec(invalid);
 assert.equal(v.status,'invalid');
 assert.equal(JSON.stringify(v).includes('secret'),false);
});
test('DJ top-level JSON primitive or null is untrusted',async()=>{
 for(const primitive of ['true','42','"string"','null'])
  assert.equal((await exec(primitive)).status,'invalid',primitive);
});
test('DJ top-level JSON array stays eligible for official review pagination',async()=>{
 const v=await exec('[{"id":1}]',{chunkSize:2});
 assert.equal(v.status,'read');assert.equal(v.data[0].id,1);
});
test('DJ missing body reader may not trigger fallback to response.text()',async()=>{
 const x=await readOfficialGithubEndpoint(PATH,TOKEN,{
  fetchImpl:async(url)=>({status:200,url,redirected:false,
   headers:{get:k=>k==='content-type'?'application/json':null},
   text:async()=>{throw Error('DO_NOT_CALL_TEXT');}})
 });
 assert.equal(x.status,'invalid');
});
test('DJ non-Uint8Array stream body and thrown reader are fail closed',async()=>{
 const bad=async url=>({status:200,url,redirected:false,
  headers:{get:k=>k==='content-type'?'application/json':null},
  body:{getReader:()=>({read:async()=>({done:false,value:'INVALID_BYTES'})})}});
 assert.equal((await readOfficialGithubEndpoint(PATH,TOKEN,{fetchImpl:bad})).status,'invalid');
 const throws=async url=>({status:200,url,redirected:false,
  headers:{get:k=>k==='content-type'?'application/json':null},
  body:{getReader:()=>({read:async()=>{throw Error('bearer token');}})}});
 const v=await readOfficialGithubEndpoint(PATH,TOKEN,{fetchImpl:throws});
 assert.equal(v.status,'unavailable');assert.equal(JSON.stringify(v).includes(TOKEN),false);
});
test('DJ missing token never issues network call',async()=>{
 let called=false;
 const v=await readOfficialGithubEndpoint(PATH,'',{
  fetchImpl:async()=>{called=true;throw Error('must never call');}
 });
 assert.equal(v.status,'missing_token');assert.equal(called,false);
});
test('DJ provider 403 remains access denied, never policy absent',async()=>{
 const v=await readOfficialGithubEndpoint(PATH,TOKEN,{
  fetchImpl:async()=>({status:403})
 });
 assert.equal(v.status,'access_denied');
});
test('DJ path allowlist rejects guessed or reflected APIs without any network request',async()=>{
 for(const path of ['/repos/attacker/repo/pulls/1',PATH+'?page=4',
  '/repos/'+REPO+'/issues/2']){
  await assert.rejects(
   readOfficialGithubEndpoint(path,TOKEN,{fetchImpl:async()=>{throw Error('network');}}),
   /BY untrusted API path/);
 }
});
test('DJ PR description at exact 8KiB byte boundary is accepted only as technical status',()=>{
 const v=by('a'.repeat(BY_MAX_PR_DESCRIPTION_BYTES));hold(v);
 assert.equal(v.prDescriptionWithinBudget,true);
 assert.equal(v.observedPrDescriptionUtf8Bytes,BY_MAX_PR_DESCRIPTION_BYTES);
});
test('DJ PR description 8KiB+1 byte fails explicit bounded-index CI gate',()=>{
 const v=by('a'.repeat(BY_MAX_PR_DESCRIPTION_BYTES+1));hold(v);
 assert.equal(v.prDescriptionWithinBudget,false);
 assert.ok(v.anomalyCodes.includes('BY_PR_DESCRIPTION_OUTSIDE_BOUNDED_EVIDENCE_INDEX'));
});
test('DJ multibyte UTF-8 budget cannot be bypassed with short JS character count',()=>{
 const body='€'.repeat(2731);
 assert.ok(body.length<BY_MAX_PR_DESCRIPTION_BYTES);
 const v=by(body);hold(v);
 assert.equal(v.prDescriptionWithinBudget,false);
 assert.equal(v.observedPrDescriptionUtf8Bytes,8193);
});
test('DJ missing PR body value is invalid, null empty description still allowed',()=>{
 const missing=by(undefined);hold(missing);
 assert.equal(missing.prDescriptionWithinBudget,false);
 const empty=by(null);hold(empty);
 assert.equal(empty.prDescriptionWithinBudget,true);
 assert.equal(empty.observedPrDescriptionUtf8Bytes,0);
});
test('DJ fail-closed PR API oversize cannot be laundered into valid budget',()=>{
 const x=by('short');hold(x);
 assert.equal(x.prDescriptionWithinBudget,true);
 const f={endpoints:{pr:{status:'oversize',data:null},
   reviews:{status:'read',data:[]},rules:{status:'read',data:[]},
   protection:{status:'access_denied',data:null}}};
 const v=assessObservedGithubGovernance(f);hold(v);
 assert.equal(v.prDescriptionWithinBudget,false);
 assert.ok(v.anomalyCodes.includes('BY_GITHUB_PR_NOT_READ'));
});
test('DJ PR description budget is independent of genuine human/admin/CA provider authority',()=>{
 const v=by('## Draft\nProduction HARD HOLD');hold(v);
 assert.equal(v.prDescriptionWithinBudget,true);
 assert.equal(v.effectiveProtectedBranchPolicyIndependentlyAuthenticated,false);
 assert.equal(v.independentReviewerSecurityAndBusinessRolesVerified,false);
});
test('DJ source uses bounded byte-stream and no text(), admin HTTP writes or budget override',()=>{
 const src=readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
  '../scripts/phase1by-github-governance-observer.mjs'),'utf8');
 assert.ok(src.includes("response.body.getReader()"));
 assert.equal(src.includes('await response.text()'),false);
 assert.equal(/method:\s*['"](?:POST|PATCH|PUT|DELETE)['"]/.test(src),false);
 assert.ok(src.includes("if(result.prDescriptionWithinBudget===false||"));
});
