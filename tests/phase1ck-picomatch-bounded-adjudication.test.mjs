import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {triageDependencyAudit} from '../scripts/triage-dependencies.mjs';
import {CASE_IDS,WORKER_TIMEOUT_MS,runBoundedPicomatchSample,
 assessBoundedTechnicalAdjudication}
 from '../scripts/phase1ck-picomatch-bounded-adjudication.mjs';

const pkg=JSON.parse(readFileSync('package.json','utf8'));
const lock=readBunLock(readFileSync('bun.lock','utf8'));
const rawAudit={picomatch:[{severity:'high',
 url:'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
 title:'Withdrawn GHSA / independent adjudication still required',
 vulnerable_versions:'<= 4.0.7'}]};
const env={GITHUB_ACTIONS:'true',GITHUB_JOB:'baseline',
 GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
 GITHUB_REF:'refs/pull/1/merge',GITHUB_SHA:'a'.repeat(40)};
const samples=()=>CASE_IDS.map((caseId,i)=>({
 caseId,state:'COMPLETED',installedVersion:'4.0.7',
 matched:i===0,executionMs:i/10+0.2
}));
const assess=extra=>assessBoundedTechnicalAdjudication({
 pkg,lock,rawAudit,normalizedAudit:triageDependencyAudit(rawAudit),
 samples:samples(),environment:env,...extra
});
const broken=(r,code)=>assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join(','));
test('CK: exact frozen audit plus three tiny worker receipts is STILL a strict HOLD',()=>{
 const r=assess();
 assert.equal(r.localAuditAndSampleInputsStructurallyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.fullLockAdvisoryCount??r.fullLockAuditAdvisoryCount,1);
 assert.equal(r.fullLockCurrentHigh,1);
 assert.equal(r.fullLockCriticalHighOrUnknownObserved,true);
 assert.equal(r.frozenPicomatchVersion,'picomatch@4.0.7');
 assert.equal(r.actualInstalledMatcherWorkerSamplingCompleted,true);
 assert.equal(r.sampleTimeoutMs,WORKER_TIMEOUT_MS);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CK: technical short-input sampling cannot prove no exploit, actual fix or external approval',()=>{
 const r=assess();
 for(const flag of ['reproducibleFullComplexityGrowthIndependentlyEstablished',
  'completeAttackerControlledPatternReachabilityExcluded',
  'advisoryWithdrawnThereforeSafe',
  'withdrawnGhsaIndependentlyAdjudicatedBySecurity',
  'realVendorPatchAndIndependentPublisherProvenanceVerified',
  'fullDependencySecurityGateWaived',
  'independentThirdPartyEvidenceOrReviewerSignoffVerified',
  'productionReleaseAuthorized'])assert.equal(r[flag],false,flag);
});
test('CK: real installed node_modules picomatch worker bounded control sample',async()=>{
 const outcome=await runBoundedPicomatchSample('control_literal');
 assert.equal(outcome.caseId,'control_literal');
 assert.ok(['COMPLETED','TIMEOUT'].includes(outcome.state),JSON.stringify(outcome));
 if(outcome.state==='COMPLETED'){
  assert.equal(outcome.installedVersion,'4.0.7');
  assert.equal(typeof outcome.matched,'boolean');
  assert.ok(outcome.executionMs>=0);
 }
 assert.equal(assess({samples:[outcome,...samples().slice(1)]})
  .productionReleaseAuthorized,false);
});
test('CK: fixed advisory-inspired sample IDs cannot be replaced by input patterns',async()=>{
 await assert.rejects(()=>runBoundedPicomatchSample('+(*)'),/CK_UNAPPROVED_SAMPLE_ID/);
 await assert.rejects(()=>runBoundedPicomatchSample('../file'),/CK_UNAPPROVED_SAMPLE_ID/);
 await assert.rejects(()=>runBoundedPicomatchSample({id:'control_literal'}),/CK_UNAPPROVED_SAMPLE_ID/);
});
test('CK: repeatable sample ordering, missing quorum or duplicate sample receipt is rejected',()=>{
 broken(assess({samples:samples().slice(1)}),'CK_SAMPLE_QUORUM_NOT_COMPLETED');
 const mixed=samples();mixed[1]=mixed[0];
 const r=assess({samples:mixed});
 broken(r,'CK_FIXED_SAMPLE_OR_WORKER_FAILED_repeated_extglob_star');
 broken(r,'CK_DUPLICATED_OR_MISSING_SAMPLE_ID');
});
test('CK: deliberate worker deadline is observed but never declares package safe',()=>{
 const result=samples();
 result[2]={caseId:CASE_IDS[2],state:'TIMEOUT',
  installedVersion:null,matched:null,executionMs:null};
 const r=assess({samples:result});
 assert.equal(r.localAuditAndSampleInputsStructurallyConsistent,true);
 assert.equal(r.boundedWorkerTimeoutObserved,true);
 assert.equal(r.actualInstalledMatcherWorkerSamplingCompleted,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CK: worker timeout spoof with matching value, fake finished result or loose shape rejected',()=>{
 for(const replacement of [
  {caseId:CASE_IDS[0],state:'TIMEOUT',installedVersion:'4.0.7',matched:true,executionMs:2000},
  {caseId:CASE_IDS[0],state:'COMPLETED',installedVersion:'4.0.8',matched:true,executionMs:1},
  {caseId:CASE_IDS[0],state:'COMPLETED',installedVersion:'4.0.7',matched:1,executionMs:1},
  {caseId:CASE_IDS[0],state:'ERROR',reason:'attacker',installedVersion:null,matched:null,executionMs:null}
 ]){
  const rows=samples();rows[0]=replacement;
  assert.equal(assess({samples:rows}).localAuditAndSampleInputsStructurallyConsistent,false);
 }
});
test('CK: unbounded timing and fabricated NaN/negative worker duration fail closed',()=>{
 for(const n of [-1,Infinity,NaN,WORKER_TIMEOUT_MS+500]){
  const rows=samples();rows[1].executionMs=n;
  broken(assess({samples:rows}),
   'CK_INSTALLED_VERSION_OR_BOUNDED_WORKER_RECEIPT_repeated_extglob_star');
 }
});
test('CK: unreadable/incorrect advisory JSON and normalization substitution denied',()=>{
 const bad=assess({rawAudit:[]});
 broken(bad,'CK_INVALID_OR_MISSING_WHOLE_LOCK_AUDIT');
 const wrong=triageDependencyAudit(rawAudit);
 wrong.bySeverity.high=0;
 broken(assess({normalizedAudit:wrong}),'CK_RAW_VS_NORMALIZED_AUDIT_DISAGREEMENT');
});
test('CK: when public advisory vanishes from audit, does NOT authorize production or mark withdrawal safe',()=>{
 const raw={};
 const r=assess({rawAudit:raw,normalizedAudit:triageDependencyAudit(raw)});
 assert.equal(r.localAuditAndSampleInputsStructurallyConsistent,true);
 assert.equal(r.fullLockCurrentHigh,0);
 assert.equal(r.fullLockCriticalHighOrUnknownObserved,false);
 assert.equal(r.advisoryWithdrawnThereforeSafe,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CK: unknown audit severity remains unsafe; a parseable advisory is still accountable',()=>{
 const raw={picomatch:[{severity:'weird',
  url:'https://github.com/advisories/GHSA-fc5q-39xc-vjpf'}]};
 const r=assess({rawAudit:raw,normalizedAudit:triageDependencyAudit(raw)});
 assert.equal(r.localAuditAndSampleInputsStructurallyConsistent,true);
 assert.equal(r.fullLockCurrentUnknown,1);
 assert.equal(r.fullLockCriticalHighOrUnknownObserved,true);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CK: frozen vendor version, tarball SHA-512 or root manifest substitution detected',()=>{
 for(const mutation of [
  x=>x.packages.picomatch[0]='picomatch@4.0.8',
  x=>x.packages.picomatch[3]='forged',
  x=>delete x.packages.picomatch
 ]){
  const l=structuredClone(lock);mutation(l);
  broken(assess({lock:l}),'CK_REAL_FROZEN_LOCK_VERSION_OR_INTEGRITY_INVALID');
 }
 const p=structuredClone(pkg);
 p.dependencies.express='9999.0.0';
 broken(assess({pkg:p}),'CK_FROZEN_ROOT_WORKSPACE_MISMATCH');
});
test('CK: fake app or lock metadata cannot turn a signed independent security approval on',()=>{
 const p={...pkg,productionReleaseAuthorized:true,globalZeroCriticalHighAuditPassed:true};
 const l=structuredClone(lock);
 l.packages.picomatch[2].independentSecurityApproval='APPROVED';
 const r=assess({pkg:p,lock:l});
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.fullDependencySecurityGateWaived,false);
 assert.equal(r.withdrawnGhsaIndependentlyAdjudicatedBySecurity,false);
});
test('CK: all job/repository/ref/commit mismatch variants fail the real Actions identity check',()=>{
 for(const fields of [
  {GITHUB_REPOSITORY:'somebody/fork'},
  {GITHUB_REF:'refs/heads/main'},
  {GITHUB_SHA:'bad'},
  {GITHUB_JOB:'review-vendor-intake-hold'},
  {GITHUB_ACTIONS:'false'}
 ]){
  broken(assess({environment:{...env,...fields}}),
   'CK_GITHUB_RUN_JOB_AND_SHA_CONTEXT_INVALID');
 }
});
test('CK: Node process.env special prototype is acceptable but wrong identities not',()=>{
 const o=Object.assign(Object.create(null),env);
 assert.equal(assess({environment:o}).localAuditAndSampleInputsStructurallyConsistent,true);
 const bad=Object.assign(Object.create(null),env,{GITHUB_SHA:'faked'});
 broken(assess({environment:bad}),'CK_GITHUB_RUN_JOB_AND_SHA_CONTEXT_INVALID');
});
