import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {SOURCES,assessUpstreamAdvisory,fetchBoundedPublicJson}
 from '../scripts/phase1cb-public-advisory-observer.mjs';

const lock=readBunLock(readFileSync('bun.lock','utf8'));
const now='2026-11-17T16:00:03Z';
const github={
 ghsa_id:'GHSA-fc5q-39xc-vjpf',cve_id:'CVE-2026-112366',
 severity:'high',updated_at:now,
 vulnerabilities:[{package:{ecosystem:'npm',name:'picomatch'},
  vulnerable_version_range:'<= 4.0.7',first_patched_version:null}]
};
const osv={
 id:'GHSA-fc5q-39xc-vjpf',aliases:['CVE-2026-112366'],modified:now,
 database_specific:{severity:'HIGH'},
 affected:[{package:{ecosystem:'npm',name:'picomatch'},
  ranges:[{type:'SEMVER',events:[{introduced:'0'},{last_affected:'4.0.7'}]}]}]
};
const evaluate=changes=>assessUpstreamAdvisory({github,osv,lock,...changes});
const responseAt=(url,body,init)=>{
 const response=new Response(body,init);
 Object.defineProperty(response,'url',{value:url});
 return response;
};
test('1CB: checked-in picomatch 4.0.7 and two matching public advisory shapes remain HOLD',()=>{
 const r=evaluate();
 assert.equal(r.twoPublicFeedsDescribeCurrentUnpatchedRange,true,r.anomalyCodes.join(','));
 assert.equal(r.publishedPatchCandidateObserved,false);
 assert.equal(r.lockedPicomatchVersion,'picomatch@4.0.7');
 assert.equal(r.unauthenticatedApplicantVendorPacketAccepted,false);
 assert.equal(r.publicFeedIsIndependentPublisherSignature,false);
 assert.equal(r.lockfileRemediationOrAuditWaiver,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('1CB: missing provider evidence is UNKNOWN and never proves a patch',()=>{
 for(const change of [{github:null},{osv:null},{github:null,osv:null}]){
  const r=evaluate(change);
  assert.equal(r.twoPublicFeedsDescribeCurrentUnpatchedRange,false);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.ok(r.anomalyCodes.some(x=>x.endsWith('UNAVAILABLE')));
 }
});
test('1CB: wrong GHSA, CVE, severity and forged vendor schema are rejected',()=>{
 for(const change of [
  {ghsa_id:'GHSA-attacker'}, {cve_id:'CVE-fake'}, {severity:'low'},
  {updated_at:'2020-01-01'}, {vulnerabilities:[]},
  {vulnerabilities:[{package:{ecosystem:'npm',name:'other'},
   vulnerable_version_range:'<= 4.0.7',first_patched_version:null}]}
 ]){
  const r=evaluate({github:{...github,...change}});
  assert.ok(r.anomalyCodes.includes('CB_GITHUB_ADVISORY_ID_RANGE_OR_PATCH_DRIFT'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('1CB: forged OSV identity, range, future fix or fake aliases never greenlight',()=>{
 for(const change of [
  {id:'GHSA-fake'}, {aliases:['CVE-fake']},
  {database_specific:{severity:'LOW'}},{affected:[]},
  {affected:[{package:{ecosystem:'npm',name:'picomatch'},ranges:[
   {type:'SEMVER',events:[{introduced:'0'},{fixed:'4.0.8'}]}]}]}
 ]){
  const r=evaluate({osv:{...osv,...change}});
  assert.ok(r.anomalyCodes.includes('CB_OSV_ADVISORY_ID_RANGE_OR_PATCH_DRIFT'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('1CB: alleged new upstream fix becomes review-needed, not accepted',()=>{
 const next={...github,vulnerabilities:[{...github.vulnerabilities[0],
  first_patched_version:{identifier:'4.0.8'}}]};
 const r=evaluate({github:next});
 assert.equal(r.publishedPatchCandidateObserved,true);
 assert.ok(r.anomalyCodes.includes('CB_PATCH_CANDIDATE_REQUIRES_INDEPENDENT_REVIEW'));
 assert.equal(r.independentlyAuthenticatedUpstreamPatchVerified,false);
 assert.equal(r.lockfileRemediationOrAuditWaiver,false);
});
test('1CB: tampered Bun version/hash and repo/ref source drift are denied',()=>{
 const l=structuredClone(lock);l.packages.picomatch[0]='picomatch@4.0.8';
 assert.ok(evaluate({lock:l}).anomalyCodes.includes('CB_LOCKED_PICOMATCH_VERSION_OR_INTEGRITY_DRIFT'));
 const c=structuredClone(lock);c.packages.picomatch[3]='sha512-fake';
 assert.ok(evaluate({lock:c}).anomalyCodes.includes('CB_LOCKED_PICOMATCH_VERSION_OR_INTEGRITY_DRIFT'));
 const env={CI:'true',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'attacker/fork',
  GITHUB_SHA:'a'.repeat(40),GITHUB_REF:'refs/heads/main'};
 assert.ok(evaluate({environment:env}).anomalyCodes.includes('CB_UNREVIEWED_CI_SOURCE_CONTEXT'));
 assert.equal(evaluate({environment:{...env,
  GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
  GITHUB_REF:'refs/pull/1/merge'}}).twoPublicFeedsDescribeCurrentUnpatchedRange,true);
});
test('1CB: endpoint allowlist, bounded authentic URL and content-type enforced',async()=>{
 await assert.rejects(()=>fetchBoundedPublicJson('https://attacker.invalid/secret'),
  /UNREVIEWED_PUBLIC_ADVISORY_ENDPOINT/);
 const ok=await fetchBoundedPublicJson(SOURCES.osv,async url=>
  responseAt(url,JSON.stringify(osv),{headers:{'Content-Type':'application/json'}}));
 assert.equal(ok.id,osv.id);
 await assert.rejects(()=>fetchBoundedPublicJson(SOURCES.github,async url=>
  responseAt(url,'{}',{status:403,headers:{'Content-Type':'application/json'}})),/NOT_TRUSTED/);
 await assert.rejects(()=>fetchBoundedPublicJson(SOURCES.github,async url=>
  responseAt(url,'{}',{headers:{'Content-Type':'text/html'}})),/NOT_TRUSTED/);
});
test('1CB: reject oversized streamed remote response and invalid JSON',async()=>{
 await assert.rejects(()=>fetchBoundedPublicJson(SOURCES.osv,async url=>responseAt(url,
  ' '.repeat(131073),{headers:{'Content-Type':'application/json'}})),/OVERSIZED/);
 await assert.rejects(()=>fetchBoundedPublicJson(SOURCES.osv,async url=>responseAt(url,
  '{not json}',{headers:{'Content-Type':'application/json'}})),SyntaxError);
});
test('1CB: unverified public sources never imply CI/WORM or live production permissions',()=>{
 const r=evaluate();
 assert.equal(r.independentSignedCiAttestationVerified,false);
 assert.equal(r.externalWormOrDrReceiptVerified,false);
 assert.equal(r.independentSecurityApprovalVerified,false);
 assert.equal(r.productionReleaseBlocked,true);
});

test('1CJ: withdrawn GitHub GHSA while OSV remains active forces explicit source-disagreement HOLD',()=>{
 const gh={...github,updated_at:'2026-11-18T10:30:00.000Z',
  withdrawn_at:'2026-11-18T10:00:00.000Z'};
 const r=evaluate({github:gh});
 assert.equal(r.githubLifecycleState,'withdrawn');
 assert.equal(r.osvLifecycleState,'active');
 assert.equal(r.githubWithdrawnAt,gh.withdrawn_at);
 assert.equal(r.osvWithdrawnAt,null);
 assert.equal(r.twoPublicFeedsDescribeCurrentUnpatchedRange,false);
 assert.ok(r.anomalyCodes.includes('CB_GITHUB_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION'));
 assert.ok(r.anomalyCodes.includes('CB_PUBLIC_ADVISORY_LIFECYCLE_DISAGREEMENT'));
 assert.equal(r.withdrawnAdvisoryNotEquivalentToFixedVersion,true);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('1CJ: matching withdrawn GitHub and OSV feeds cannot be interpreted as patched vendor release',()=>{
 const withdrawn='2026-11-18T10:00:00.000Z';
 const r=evaluate({github:{...github,withdrawn_at:withdrawn},
  osv:{...osv,withdrawn}});
 assert.equal(r.githubLifecycleState,'withdrawn');
 assert.equal(r.osvLifecycleState,'withdrawn');
 assert.equal(r.twoPublicFeedsDescribeCurrentUnpatchedRange,false);
 assert.ok(!r.anomalyCodes.includes('CB_PUBLIC_ADVISORY_LIFECYCLE_DISAGREEMENT'));
 assert.ok(r.anomalyCodes.includes('CB_OSV_WITHDRAWN_NEEDS_INDEPENDENT_SECURITY_ADJUDICATION'));
 assert.equal(r.independentlyAuthenticatedUpstreamPatchVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('1CJ: malformed withdrawal timestamps and unavailable feeds never turn unknown into safe',()=>{
 for(const change of [
  {github:{...github,withdrawn_at:'NOT_A_TIME'}},
  {osv:{...osv,withdrawn:'2028-01-01T00:00:00Z'}},
  {github:null,osv:{...osv,withdrawn:'2026-11-18T10:00:00Z'}}
 ]){
  const r=evaluate(change);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.twoPublicFeedsDescribeCurrentUnpatchedRange,false);
  assert.ok(r.anomalyCodes.some(x=>x.includes('WITHDRAWAL_DATE_INVALID')||
    x.endsWith('ADVISORY_UNAVAILABLE')));
 }
});
