import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock} from './phase1bt-production-scope.mjs';

// 1CH: observe only exact fixed public publisher endpoints and corroborate
// advisory/registry/upstream release claims. Registry and GitHub public JSON
// are NOT signed vendor acceptance and do NOT waive the strict Bun audit.
export const SOURCES=Object.freeze({
 npm:'https://registry.npmjs.org/picomatch/latest',
 release:'https://api.github.com/repos/micromatch/picomatch/releases/latest'
});
export const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
export const ADVISORY='GHSA-fc5q-39xc-vjpf';
export const CVE='CVE-2026-112366';
const CURRENT='4.0.7';
const SHA512=/^sha512-[A-Za-z0-9+/]{86}==$/;
const SHA=/^[0-9a-f]{40}$/;
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const sha256=s=>createHash('sha256').update(s).digest('hex');
const simpleSemver=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
function newerThanCurrent(version){
 if(typeof version!=='string'||!simpleSemver.test(version))return false;
 const [major,minor,patch]=version.split('.').map(Number);
 return Number.isSafeInteger(major)&&Number.isSafeInteger(minor)&&
  Number.isSafeInteger(patch)&&major===4&&
  (minor>0||(minor===0&&patch>7));
}
function normalDate(value){
 if(typeof value!=='string')return false;
 const timestamp=Date.parse(value);
 return Number.isFinite(timestamp)&&timestamp>=Date.parse('2026-08-01T00:00:00Z')&&
  timestamp<=Date.now()+300000;
}
function validateNpm(latest){
 if(!obj(latest)||latest.name!=='picomatch'||
    typeof latest.version!=='string'||!simpleSemver.test(latest.version)||
    !obj(latest.dist)||!SHA512.test(latest.dist.integrity??'')||
    latest.dist.tarball!=='https://registry.npmjs.org/picomatch/-/picomatch-'+latest.version+'.tgz')
  return {valid:false,version:null,integrity:null};
 return {valid:true,version:latest.version,integrity:latest.dist.integrity};
}
function validateRelease(release){
 if(release===null)return {available:false,valid:false,version:null};
 if(!obj(release)||typeof release.tag_name!=='string'||
    !/^v?4\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(release.tag_name)||
    release.draft!==false||release.prerelease!==false||
    !normalDate(release.published_at))
  return {available:true,valid:false,version:null};
 const v=release.tag_name.replace(/^v/,'');
 const allowed=['https://github.com/micromatch/picomatch/releases/tag/'+v,
  'https://github.com/micromatch/picomatch/releases/tag/v'+v];
 return {available:true,valid:allowed.includes(release.html_url),version:v};
}
export function assessPublisherRemediation({
 cbReport=null,npmLatest=null,upstreamRelease=null,lock=null,
 environment={}
}={}){
 const anomalies=new Set();
 const known=lock?.packages?.picomatch;
 const locked=Array.isArray(known)&&typeof known[0]==='string'?known[0]:null;
 const lockIntegrity=Array.isArray(known)?known[3]:null;
 if(locked!=='picomatch@4.0.7'||!SHA512.test(lockIntegrity??''))
  anomalies.add('CH_FROZEN_LOCKED_PICOMATCH_INTEGRITY_OR_VERSION_DRIFT');
 if(!obj(environment))environment={};
 if(environment.CI==='true'||environment.GITHUB_ACTIONS==='true'){
  if(environment.CI!=='true'||environment.GITHUB_ACTIONS!=='true'||
    environment.GITHUB_REPOSITORY!==REPO||
    !SHA.test(environment.GITHUB_SHA??'')||
    !/^refs\/heads\/chore\/phase0-foundation-20261106$|^refs\/pull\/1\/merge$/.test(environment.GITHUB_REF??''))
   anomalies.add('CH_UNVERIFIED_GITHUB_CI_WORKLOAD_CONTEXT');
 }
 const cb=cbReport?.assessment;
 const upstream=validateNpm(npmLatest);
 const released=validateRelease(upstreamRelease);
 const twoFeedUnpatched=cb?.phase==='1CB'&&
  cb?.kind==='UNSIGNED_PUBLIC_ADVISORY_OBSERVATION_HOLD'&&
  cb?.lockedPicomatchVersion==='picomatch@4.0.7'&&
  cb?.twoPublicFeedsDescribeCurrentUnpatchedRange===true&&
  cb?.publishedPatchCandidateObserved===false&&
  cb?.productionReleaseAuthorized===false&&cb?.releaseDecision==='HOLD'&&
  cbReport?.fetchOutcome?.github==='SUCCESS'&&
  cbReport?.fetchOutcome?.osv==='SUCCESS'&&
  /^[a-f0-9]{64}$/.test(cb.githubSourceContentSha256??'')&&
  /^[a-f0-9]{64}$/.test(cb.osvSourceContentSha256??'');
 if(!twoFeedUnpatched)
  anomalies.add('CH_GITHUB_OSV_ADVISORIES_MISSING_DISAGREE_OR_CHANGED');
 if(npmLatest===null)anomalies.add('CH_NPM_PUBLISHER_METADATA_UNAVAILABLE');
 else if(!upstream.valid)anomalies.add('CH_NPM_PUBLISHER_METADATA_INVALID_OR_UNTRUSTED');
 if(upstream.valid&&upstream.version===CURRENT&&upstream.integrity!==lockIntegrity)
  anomalies.add('CH_LATEST_NPM_TARBALL_INTEGRITY_DISAGREES_WITH_BUN_LOCK');
 if(upstream.valid&&upstream.version!==CURRENT)
  anomalies.add('CH_NEW_OR_DIFFERENT_UPSTREAM_VERSION_REQUIRES_FULL_SECURITY_REVIEW');
 if(upstreamRelease!==null&&!released.valid)
  anomalies.add('CH_GITHUB_OFFICIAL_RELEASE_METADATA_INVALID');
 if(released.valid&&upstream.valid&&released.version!==upstream.version)
  anomalies.add('CH_RELEASE_TAG_AND_NPM_LATEST_DISAGREE');
 if(released.valid&&newerThanCurrent(released.version))
  anomalies.add('CH_NEW_GITHUB_RELEASE_REQUIRES_MANUAL_SECURITY_ACCEPTANCE');
 // No registry or public advisory, even if internally consistent, is proof
 // of real upstream patch implementation, maintainer signing, an updated
 // tested frozen graph, or independent Security approval.
 return Object.freeze({
  phase:'1CH',schemaVersion:1,
  kind:'PUBLIC_NPM_UPSTREAM_GHSA_OSV_UNPATCHED_OBSERVER_HOLD',
  lockedPicomatchVersion:locked,
  latestNpmVersion:upstream.version,
  npmMetadataShapeValid:upstream.valid,
  lockedArtifactIntegrityAgreesWithRegistry:upstream.valid&&
    upstream.version===CURRENT&&upstream.integrity===lockIntegrity,
  officialGithubReleaseMetadataObserved:released.available,
  officialGithubReleaseMetadataConsistent:released.valid,
  publiclyObservedUpstreamReleaseVersion:released.version,
  exactPublicAdvisoriesReportUnpatchedRange:twoFeedUnpatched,
  newerSupportedVersionRequiresIndependentReview:
    newerThanCurrent(upstream.version)||newerThanCurrent(released.version),
  publicObservationSha256:upstream.valid?
    sha256(JSON.stringify({name:'picomatch',version:upstream.version,
      integrity:upstream.integrity})):null,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  approvedUpstreamPatchAndSignedProvenanceVerified:false,
  independentlyAuthenticatedVendorPublisherVerified:false,
  verifiedSafeReplacementAndFrozenGraphRebuilt:false,
  actualPatchedPicomatchReleaseVerified:false,
  globalZeroCriticalHighAuditPassed:false,
  genuineIndependentSecurityApprovalsVerified:false,
  independentExternalProviderOrWormEvidenceVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export async function readFixedPublicPublisher(url,fetchImpl=fetch){
 if(!Object.values(SOURCES).includes(url))
  throw Error('CH_UNAPPROVED_OR_REDIRECTED_REGISTRY_OR_VENDOR_ENDPOINT');
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),6500);
 try{
  const response=await fetchImpl(url,{
   method:'GET',redirect:'error',cache:'no-store',
   signal:controller.signal,
   headers:{Accept:'application/json','User-Agent':'AadiTech-HOLD-Observer/1CH'}
  });
  if(response.status!==200||response.redirected===true||response.url!==url||
    !/^application\/(?:json|[a-z0-9.+-]*\+json)\b/i.test(
      response.headers?.get?.('content-type')??''))
   throw Error('CH_PUBLISHER_RESPONSE_UNAVAILABLE_OR_UNVERIFIED');
  const length=response.headers?.get?.('content-length');
  if(length!==null&&length!==undefined&&
    (!/^\d+$/.test(length)||Number(length)>98304))
   throw Error('CH_PUBLISHER_RESPONSE_TOO_LARGE');
  const reader=response.body?.getReader();
  if(!reader)throw Error('CH_PUBLISHER_STREAM_NOT_AVAILABLE');
  const chunks=[];let lengthRead=0;
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))
    throw Error('CH_PUBLISHER_INVALID_STREAM_CHUNK');
   lengthRead+=value.byteLength;
   if(lengthRead>98304)throw Error('CH_PUBLISHER_STREAM_TOO_LARGE');
   chunks.push(Buffer.from(value));
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
 }finally{clearTimeout(timeout);}
}
function safeLocalJson(path){
 const stat=lstatSync(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>1024*1024)
  throw Error('CH unsafe/symlink/oversize held source');
 return JSON.parse(readFileSync(path,'utf8'));
}
async function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('CH only supports zero-secret read-only --ci-hold');
 const cbReport=safeLocalJson('phase1cb-public-advisory-hold.json');
 const lock=readBunLock(readFileSync('bun.lock','utf8'));
 const [npm,release]=await Promise.allSettled([
  readFixedPublicPublisher(SOURCES.npm),
  readFixedPublicPublisher(SOURCES.release)
 ]);
 const assessment=assessPublisherRemediation({
  cbReport,lock,environment:process.env,
  npmLatest:npm.status==='fulfilled'?npm.value:null,
  upstreamRelease:release.status==='fulfilled'?release.value:null
 });
 const report={assessment,fetchOutcome:{
  npm:npm.status==='fulfilled'?'SUCCESS':'UNAVAILABLE_OR_REJECTED',
  release:release.status==='fulfilled'?'SUCCESS':'UNAVAILABLE_OR_REJECTED'
 }};
 writeFileSync('phase1ch-publisher-remediation-hold.json',
  JSON.stringify(report,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(report,null,2));
 if(assessment.productionReleaseAuthorized!==false||
    assessment.productionReleaseBlocked!==true||
    assessment.releaseDecision!=='HOLD')
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{
  console.error('CH public vendor patch readiness HARD HOLD failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 });
