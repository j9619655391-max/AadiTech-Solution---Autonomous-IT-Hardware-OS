import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {SOURCES,assessPublisherRemediation,readFixedPublicPublisher}
 from '../scripts/phase1ch-upstream-patch-publication-preflight.mjs';

const lock=readBunLock(readFileSync('bun.lock','utf8'));
const integrity=lock.packages.picomatch[3];
const releaseDate='2026-08-24T00:00:00Z';
const validRegistry=(v='4.0.7',i=integrity)=>({
 name:'picomatch',version:v,
 dist:{integrity:i,tarball:'https://registry.npmjs.org/picomatch/-/picomatch-'+v+'.tgz'}
});
const release=(v='4.0.7')=>({
 tag_name:'v'+v,draft:false,prerelease:false,
 published_at:releaseDate,
 html_url:'https://github.com/micromatch/picomatch/releases/tag/v'+v
});
const cbReport={
 assessment:{phase:'1CB',kind:'UNSIGNED_PUBLIC_ADVISORY_OBSERVATION_HOLD',
  lockedPicomatchVersion:'picomatch@4.0.7',
  twoPublicFeedsDescribeCurrentUnpatchedRange:true,
  publishedPatchCandidateObserved:false,
  githubSourceContentSha256:'a'.repeat(64),
  osvSourceContentSha256:'b'.repeat(64),
  productionReleaseAuthorized:false,releaseDecision:'HOLD'},
 fetchOutcome:{github:'SUCCESS',osv:'SUCCESS'}
};
const evaluate=more=>assessPublisherRemediation({
 cbReport,lock,npmLatest:validRegistry(),upstreamRelease:release(),...more
});
const response=(url,body,{status=200,headers={'content-type':'application/json'}}={})=>{
 const res=new Response(body,{status,headers});
 Object.defineProperty(res,'url',{value:url});
 return res;
};
test('CH: current 4.0.7 exact npm integrity, two public advisories and upstream release do NOT patch',()=>{
 const r=evaluate();
 assert.equal(r.lockedPicomatchVersion,'picomatch@4.0.7');
 assert.equal(r.latestNpmVersion,'4.0.7');
 assert.equal(r.exactPublicAdvisoriesReportUnpatchedRange,true,r.anomalyCodes.join(','));
 assert.equal(r.npmMetadataShapeValid,true);
 assert.equal(r.lockedArtifactIntegrityAgreesWithRegistry,true);
 assert.equal(r.officialGithubReleaseMetadataConsistent,true);
 assert.deepEqual(r.anomalyCodes,[]);
 for(const key of ['approvedUpstreamPatchAndSignedProvenanceVerified',
  'independentlyAuthenticatedVendorPublisherVerified',
  'verifiedSafeReplacementAndFrozenGraphRebuilt',
  'actualPatchedPicomatchReleaseVerified',
  'globalZeroCriticalHighAuditPassed',
  'genuineIndependentSecurityApprovalsVerified',
  'independentExternalProviderOrWormEvidenceVerified',
  'productionReleaseAuthorized'])assert.equal(r[key],false,key);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CH: no registry, no release and missing third party material cannot be mistaken for patch',()=>{
 const r=evaluate({npmLatest:null,upstreamRelease:null});
 assert.ok(r.anomalyCodes.includes('CH_NPM_PUBLISHER_METADATA_UNAVAILABLE'));
 assert.equal(r.officialGithubReleaseMetadataObserved,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CH: upstream has no GitHub Release endpoint but npm unpatched still HOLD',()=>{
 const r=evaluate({upstreamRelease:null});
 assert.equal(r.officialGithubReleaseMetadataObserved,false);
 assert.equal(r.exactPublicAdvisoriesReportUnpatchedRange,true);
 assert.equal(r.actualPatchedPicomatchReleaseVerified,false);
});
test('CH: false npm package name, malicious dist URL and missing sha512 rejected',()=>{
 for(const latest of [
  {...validRegistry(),name:'@attacker/picomatch'},
  {...validRegistry(),dist:{integrity,tarball:'https://evil.invalid/picomatch.tgz'}},
  {...validRegistry(),dist:{integrity:'sha256-unsafe',
   tarball:'https://registry.npmjs.org/picomatch/-/picomatch-4.0.7.tgz'}},
  {...validRegistry(),dist:{}}
 ]){
  const r=evaluate({npmLatest:latest});
  assert.ok(r.anomalyCodes.includes('CH_NPM_PUBLISHER_METADATA_INVALID_OR_UNTRUSTED'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CH: registry same-version tarball integrity mismatch cannot be silently accepted',()=>{
 const r=evaluate({npmLatest:validRegistry('4.0.7','sha512-'+'A'.repeat(86)+'==')});
 assert.ok(r.anomalyCodes.includes('CH_LATEST_NPM_TARBALL_INTEGRITY_DISAGREES_WITH_BUN_LOCK'));
 assert.equal(r.lockedArtifactIntegrityAgreesWithRegistry,false);
});
test('CH: hypothetical 4.0.8 or later is candidate not a verified patch or override',()=>{
 for(const version of ['4.0.8','4.1.0','4.2.3']){
  const r=evaluate({npmLatest:validRegistry(version),upstreamRelease:release(version)});
  assert.equal(r.latestNpmVersion,version);
  assert.equal(r.newerSupportedVersionRequiresIndependentReview,true);
  assert.ok(r.anomalyCodes.includes('CH_NEW_OR_DIFFERENT_UPSTREAM_VERSION_REQUIRES_FULL_SECURITY_REVIEW'));
  assert.ok(r.anomalyCodes.includes('CH_NEW_GITHUB_RELEASE_REQUIRES_MANUAL_SECURITY_ACCEPTANCE'));
  assert.equal(r.actualPatchedPicomatchReleaseVerified,false);
  assert.equal(r.globalZeroCriticalHighAuditPassed,false);
 }
});
test('CH: prerelease and attacker fork tags never qualify for supported remediation',()=>{
 for(const version of ['4.0.8-alpha.1','4.0.7-aikido.1','999.0.0','4.0.08']){
  const r=evaluate({npmLatest:validRegistry(version)});
  if(version==='999.0.0')assert.ok(r.anomalyCodes.includes('CH_NEW_OR_DIFFERENT_UPSTREAM_VERSION_REQUIRES_FULL_SECURITY_REVIEW'));
  else assert.ok(r.anomalyCodes.includes('CH_NPM_PUBLISHER_METADATA_INVALID_OR_UNTRUSTED'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CH: repository release mismatch with npm tag fails independently',()=>{
 const r=evaluate({upstreamRelease:release('4.0.6')});
 assert.ok(r.anomalyCodes.includes('CH_RELEASE_TAG_AND_NPM_LATEST_DISAGREE'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CH: fake release hosts, draft, prerelease or invalid source date fail',()=>{
 for(const invalid of [
  {...release(),html_url:'https://github.com/attacker/picomatch/releases/tag/v4.0.7'},
  {...release(),draft:true},
  {...release(),prerelease:true},
  {...release(),published_at:'not-time'},
  {...release(),tag_name:'v4.0.8-fake'}
 ]){
  const r=evaluate({upstreamRelease:invalid});
  assert.ok(r.anomalyCodes.includes('CH_GITHUB_OFFICIAL_RELEASE_METADATA_INVALID'));
  assert.equal(r.officialGithubReleaseMetadataConsistent,false);
 }
});
test('CH: GHSA/OSV unavailable, advisory disagreement or false patch claim never promote',()=>{
 for(const variant of [
  {cbReport:null},
  {cbReport:{...cbReport,fetchOutcome:{github:'UNAVAILABLE_OR_REJECTED',osv:'SUCCESS'}}},
  {cbReport:{...cbReport,assessment:{...cbReport.assessment,publishedPatchCandidateObserved:true}}},
  {cbReport:{...cbReport,assessment:{...cbReport.assessment,twoPublicFeedsDescribeCurrentUnpatchedRange:false}}},
  {cbReport:{...cbReport,assessment:{...cbReport.assessment,productionReleaseAuthorized:true}}}
 ]){
  const r=evaluate(variant);
  assert.ok(r.anomalyCodes.includes('CH_GITHUB_OSV_ADVISORIES_MISSING_DISAGREE_OR_CHANGED'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CH: changed frozen lock version, corruption or forged integrity fails local provenance',()=>{
 for(const modify of [
  x=>x.packages.picomatch[0]='picomatch@4.0.8',
  x=>x.packages.picomatch[3]='forged-sha512',
  x=>delete x.packages.picomatch
 ]){
  const l=structuredClone(lock);modify(l);
  const r=evaluate({lock:l});
  assert.ok(r.anomalyCodes.includes('CH_FROZEN_LOCKED_PICOMATCH_INTEGRITY_OR_VERSION_DRIFT'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CH: altered GitHub CI repository, ref, source sha and missing GitHub Actions flag denied',()=>{
 const base={CI:'true',GITHUB_ACTIONS:'true',
  GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
  GITHUB_SHA:'a'.repeat(40),GITHUB_REF:'refs/pull/1/merge'};
 assert.equal(evaluate({environment:base}).anomalyCodes.length,0);
 for(const variant of [
  {...base,GITHUB_REPOSITORY:'attacker/other'},
  {...base,GITHUB_REF:'refs/heads/main'},
  {...base,GITHUB_SHA:'bad'},
  {...base,GITHUB_ACTIONS:'false'}
 ]){
  const r=evaluate({environment:variant});
  assert.ok(r.anomalyCodes.includes('CH_UNVERIFIED_GITHUB_CI_WORKLOAD_CONTEXT'));
 }
});
test('CH: fixed read-only npm and GitHub hosts with bounded JSON streams',async()=>{
 for(const url of Object.values(SOURCES)){
  const body=JSON.stringify({name:'picomatch',version:'4.0.7'});
  const doc=await readFixedPublicPublisher(url,async(u,opts)=>{
   assert.equal(u,url);assert.equal(opts.method,'GET');
   assert.equal(opts.redirect,'error');
   assert.equal(opts.cache,'no-store');
   assert.equal(opts.headers.Authorization,undefined);
   return response(url,body);
  });
  assert.equal(doc.name,'picomatch');
 }
});
test('CH: reject arbitrary hosts, redirects, status drift, bad MIME, oversized streams',async()=>{
 await assert.rejects(()=>readFixedPublicPublisher('https://evil.invalid/picomatch'),/CH_UNAPPROVED/);
 const url=SOURCES.npm;
 for(const result of [
  response(url,'{}',{status:404}),
  response('https://evil.invalid/picomatch','{}'),
  response(url,'{}',{headers:{'content-type':'text/html'}}),
  response(url,'{}',{headers:{'content-type':'application/json','content-length':'200000'}}),
  response(url,'X'.repeat(100000))
 ]){
  await assert.rejects(()=>readFixedPublicPublisher(url,async()=>result));
 }
});
test('CH: public feed is only investigation signal, never independently signed provider evidence',()=>{
 const version='4.0.8';
 const r=evaluate({npmLatest:validRegistry(version),upstreamRelease:release(version),
  cbReport:{...cbReport,assessment:{...cbReport.assessment,
   twoPublicFeedsDescribeCurrentUnpatchedRange:false,publishedPatchCandidateObserved:true}}});
 assert.equal(r.newerSupportedVersionRequiresIndependentReview,true);
 assert.equal(r.actualPatchedPicomatchReleaseVerified,false);
 assert.equal(r.approvedUpstreamPatchAndSignedProvenanceVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
