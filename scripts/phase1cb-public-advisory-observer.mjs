import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock} from './phase1bt-production-scope.mjs';

// Phase 1CB: PUBLIC read-only advisory observation, never a vendor-accepted
// patch, independent publisher signature, production waiver or release GO.
export const SOURCES=Object.freeze({
 github:'https://api.github.com/advisories/GHSA-fc5q-39xc-vjpf',
 osv:'https://api.osv.dev/v1/vulns/GHSA-fc5q-39xc-vjpf'
});
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const ID='GHSA-fc5q-39xc-vjpf', CVE='CVE-2026-112366';
const LOCKED='picomatch@4.0.7';
const sha256=s=>createHash('sha256').update(s).digest('hex');
const shape=x=>x&&typeof x==='object'&&!Array.isArray(x);
const exactDate=x=>typeof x==='string'&&Number.isFinite(Date.parse(x))&&
 Date.parse(x)>=Date.parse('2026-10-19T00:00:00Z')&&
 Date.parse(x)<=Date.now()+5*60*1000;
function readAffectedFromGithub(github){
 if(!shape(github)||github.ghsa_id!==ID||github.cve_id!==CVE||
   github.severity?.toLowerCase()!=='high'||
   !exactDate(github.updated_at)||!Array.isArray(github.vulnerabilities))
  return {valid:false,patchClaim:false};
 const rows=github.vulnerabilities.filter(row=>shape(row)&&
  row.package?.ecosystem==='npm'&&row.package?.name==='picomatch');
 if(rows.length!==1)return {valid:false,patchClaim:false};
 const row=rows[0];
 const range=typeof row.vulnerable_version_range==='string'?
  row.vulnerable_version_range.replace(/\s/g,''):'';
 const patch=row.first_patched_version;
 const patchClaim=patch!==null&&patch!==undefined;
 return {valid:range==='<=4.0.7'&&patch===null,patchClaim};
}
function readAffectedFromOsv(osv){
 if(!shape(osv)||osv.id!==ID||!Array.isArray(osv.aliases)||
   !osv.aliases.includes(CVE)||!exactDate(osv.modified)||
   osv.database_specific?.severity!=='HIGH'||
   !Array.isArray(osv.affected))
  return {valid:false,patchClaim:false};
 const rows=osv.affected.filter(row=>row?.package?.ecosystem==='npm'&&
   row.package?.name==='picomatch');
 if(rows.length!==1||!Array.isArray(rows[0].ranges))return {valid:false,patchClaim:false};
 const ranges=rows[0].ranges.filter(x=>x?.type==='SEMVER'&&Array.isArray(x.events));
 if(ranges.length!==1)return {valid:false,patchClaim:false};
 const events=ranges[0].events;
 const patchClaim=events.some(x=>x&&Object.hasOwn(x,'fixed'));
 return {valid:events.length===2&&events[0]?.introduced==='0'&&
  events[1]?.last_affected==='4.0.7'&&!patchClaim,patchClaim};
}
export function assessUpstreamAdvisory({github,osv,lock,environment={}}={}){
 const anomalies=new Set();
 const locked=lock?.packages?.picomatch;
 const version=Array.isArray(locked)?locked[0]:null;
 if(version!==LOCKED||!Array.isArray(locked)||
   !/^sha512-[A-Za-z0-9+/]{86}==$/.test(locked[3]??''))
  anomalies.add('CB_LOCKED_PICOMATCH_VERSION_OR_INTEGRITY_DRIFT');
 if(environment.CI==='true'||environment.GITHUB_ACTIONS==='true'){
  if(environment.GITHUB_REPOSITORY!==REPO||
    !/^[a-f0-9]{40}$/.test(environment.GITHUB_SHA??'')||
    !/^refs\/heads\/chore\/phase0-foundation-20261106$|^refs\/pull\/1\/merge$/.test(
      environment.GITHUB_REF??''))
   anomalies.add('CB_UNREVIEWED_CI_SOURCE_CONTEXT');
 }
 const g=readAffectedFromGithub(github),o=readAffectedFromOsv(osv);
 // Phase 1CJ: a publicly withdrawn security advisory is NOT a released
 // upstream patch and MUST be independently adjudicated against other feeds.
 // Distinguish absent lifecycle metadata (active) from malformed or missing
 // source records (unknown). Never infer that withdrawal fixes the lock.
 const ghWithdrawn=github?.withdrawn_at;
 const osWithdrawn=osv?.withdrawn;
 const githubLifecycleState=github==null?'unavailable':
  !g.valid?'invalid':ghWithdrawn==null?'active':
  exactDate(ghWithdrawn)?'withdrawn':'invalid';
 const osvLifecycleState=osv==null?'unavailable':
  !o.valid?'invalid':osWithdrawn==null?'active':
  exactDate(osWithdrawn)?'withdrawn':'invalid';
 if(githubLifecycleState==='withdrawn')
  anomalies.add('CB_GITHUB_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION');
 if(osvLifecycleState==='withdrawn')
  anomalies.add('CB_OSV_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION');
 if(github!=null&&ghWithdrawn!=null&&githubLifecycleState==='invalid')
  anomalies.add('CB_GITHUB_WITHDRAWAL_DATE_INVALID');
 if(osv!=null&&osWithdrawn!=null&&osvLifecycleState==='invalid')
  anomalies.add('CB_OSV_WITHDRAWAL_DATE_INVALID');
 if(githubLifecycleState!=='unavailable'&&osvLifecycleState!=='unavailable'&&
    githubLifecycleState!=='invalid'&&osvLifecycleState!=='invalid'&&
    githubLifecycleState!==osvLifecycleState)
  anomalies.add('CB_PUBLIC_ADVISORY_LIFECYCLE_DISAGREEMENT');
 if(!g.valid)anomalies.add(github==null?
  'CB_GITHUB_ADVISORY_UNAVAILABLE':'CB_GITHUB_ADVISORY_ID_RANGE_OR_PATCH_DRIFT');
 if(!o.valid)anomalies.add(osv==null?
  'CB_OSV_ADVISORY_UNAVAILABLE':'CB_OSV_ADVISORY_ID_RANGE_OR_PATCH_DRIFT');
 if(g.patchClaim||o.patchClaim)
  anomalies.add('CB_PATCH_CANDIDATE_REQUIRES_INDEPENDENT_REVIEW');
 return Object.freeze({
  phase:'1CB',schemaVersion:1,
  kind:'UNSIGNED_PUBLIC_ADVISORY_OBSERVATION_HOLD',
  githubEndpoint:SOURCES.github,osvEndpoint:SOURCES.osv,
  checkedRepository:environment.GITHUB_REPOSITORY??null,
  checkedRunnerCommit:/^[a-f0-9]{40}$/.test(environment.GITHUB_SHA??'')?
   environment.GITHUB_SHA:null,
  lockedPicomatchVersion:version,
  githubLifecycleState,osvLifecycleState,
  githubWithdrawnAt:githubLifecycleState==='withdrawn'?ghWithdrawn:null,
  osvWithdrawnAt:osvLifecycleState==='withdrawn'?osWithdrawn:null,
  withdrawnAdvisoryNotEquivalentToFixedVersion:true,
  twoPublicFeedsDescribeCurrentUnpatchedRange:anomalies.size===0,
  publishedPatchCandidateObserved:g.patchClaim||o.patchClaim,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  githubSourceContentSha256:github==null?null:sha256(JSON.stringify(github)),
  osvSourceContentSha256:osv==null?null:sha256(JSON.stringify(osv)),
  unauthenticatedApplicantVendorPacketAccepted:false,
  publicFeedIsIndependentPublisherSignature:false,
  independentlyAuthenticatedUpstreamPatchVerified:false,
  lockfileRemediationOrAuditWaiver:false,
  independentSignedCiAttestationVerified:false,
  externalWormOrDrReceiptVerified:false,
  independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
// Strict, fixed-host GET: no redirects, credentials, URL construction,
// arbitrary user-selected destinations, unbounded responses or raw response logs.
export async function fetchBoundedPublicJson(url,fetchImpl=fetch){
 if(!Object.values(SOURCES).includes(url))
  throw Error('CB_UNREVIEWED_PUBLIC_ADVISORY_ENDPOINT');
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),6500);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',signal:controller.signal,cache:'no-store',
   headers:{Accept:'application/json','User-Agent':'AadiTech-HOLD-Observer/1CB'}
  });
  if(response.status!==200||response.redirected||response.url!==url||
     !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
       response.headers.get('content-type')??''))
   throw Error('CB_PUBLIC_ADVISORY_RESPONSE_NOT_TRUSTED');
  const length=response.headers.get('content-length');
  if(length!==null&&(!/^\d+$/.test(length)||Number(length)>131072))
   throw Error('CB_PUBLIC_ADVISORY_OVERSIZED');
  const reader=response.body?.getReader();
  if(!reader)throw Error('CB_PUBLIC_ADVISORY_NO_STREAM');
  const chunks=[];let size=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))throw Error('CB_PUBLIC_ADVISORY_BAD_STREAM');
   size+=value.byteLength;
   if(size>131072)throw Error('CB_PUBLIC_ADVISORY_OVERSIZED');
   chunks.push(Buffer.from(value));
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
 }finally{clearTimeout(timer);}
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CB only supports --ci-hold');
 const stat=lstatSync('bun.lock');
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size>1024*1024)
  throw Error('CB requires reviewed bounded regular Bun lock');
 const lock=readBunLock(readFileSync('bun.lock','utf8'));
 const [a,b]=await Promise.allSettled([
  fetchBoundedPublicJson(SOURCES.github),
  fetchBoundedPublicJson(SOURCES.osv)
 ]);
 const assessment=assessUpstreamAdvisory({
  github:a.status==='fulfilled'?a.value:null,
  osv:b.status==='fulfilled'?b.value:null,
  lock,environment:process.env
 });
 const report={assessment,fetchOutcome:{
  github:a.status==='fulfilled'?'SUCCESS':'UNAVAILABLE_OR_REJECTED',
  osv:b.status==='fulfilled'?'SUCCESS':'UNAVAILABLE_OR_REJECTED'
 }};
 writeFileSync('phase1cb-public-advisory-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 // Observation-only: public API rate limits are UNKNOWN, never evidence of a
 // patch or permission to release. The separate zero-High baseline remains RED.
 if(assessment.productionReleaseAuthorized||
    !assessment.productionReleaseBlocked||
    assessment.releaseDecision!=='HOLD')process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('CB public advisory observation failed closed:',
    e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 });
