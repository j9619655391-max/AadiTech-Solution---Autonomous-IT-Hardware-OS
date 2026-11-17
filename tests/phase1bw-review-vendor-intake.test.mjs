import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {assessReviewerGovernance,assessVendorPatchIntake,
 makeGovernanceReceipt,GOVERNED_INPUTS}
 from '../scripts/phase1bw-review-vendor-intake.mjs';

const get=path=>readFileSync(path,'utf8');
const policy=JSON.parse(get('docs/security/phase1bw-review-policy.json'));
const workflow=get('.github/workflows/ci.yml');
const template=get('.github/pull_request_template.md');
const lock=readBunLock(get('bun.lock'));
const evaluate=(p=policy,w=workflow,t=template,pr={})=>
 assessReviewerGovernance(p,w,t,pr);
const clone=x=>structuredClone(x);

test('BW real policy is internally consistent but externally all approvals remain unverified and HARD HOLD',()=>{
 const r=evaluate();
 assert.equal(r.localPolicyConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.requestedIndependentReviewerCount,2);
 assert.equal(r.independentGithubBranchProtectionVerified,false);
 assert.equal(r.verifiedSubmittedIndependentApprovals,0);
 assert.equal(r.independentReviewerSignaturesAuthenticated,false);
 assert.equal(r.externalSecurityApprovalVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BW policy tampering, reviewer quorum reduction and mandatory check removal fail closed',()=>{
 for(const key of [
  'preventDirectPush','preventForcePush','preventDeletion','requirePullRequest',
  'dismissStaleReviews','requireApprovalOfMostRecentPush',
  'requireCodeOwnerReview','requireConversationResolution',
  'forbidBypassForAdmins','requireExactHeadRevalidation',
  'requireIndependentSignedCIProvenance','requireAuthenticatedSecurityAcceptance'
 ]){
  const p=clone(policy);p.requiredControls[key]=false;
  assert.ok(evaluate(p).anomalyCodes.includes('BW_REQUIRED_CONTROL_WEAKENED_'+key));
 }
 const less=clone(policy);less.requiredControls.minimumIndependentApprovals=1;
 assert.ok(evaluate(less).anomalyCodes.includes('BW_INDEPENDENT_REVIEW_QUORUM_WEAKENED'));
 const check=clone(policy);check.requiredControls.requireSuccessfulChecks.pop();
 assert.ok(evaluate(check).anomalyCodes.includes('BW_REQUIRED_JOB_QUORUM_WEAKENED'));
});
test('BW applicant-added fake reviewer signatures, branch-protection approval and release GO cannot authenticate themselves',()=>{
 for(const [key,value] of [
  ['mainProtectionIndependentlyVerified',true],
  ['independentReviewersAuthenticated',true],
  ['distinctReviewerApprovalsVerified',2],
  ['independentSignedProvenanceVerified',true],
  ['securityReleaseApprovalVerified',true],
  ['productionReleaseAuthorized',true],
  ['releaseDecision','GO']
 ]){
  const p=clone(policy);p.observedState[key]=value;
  const r=evaluate(p);
  assert.equal(r.localPolicyConsistent,false,key);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.ok(r.anomalyCodes.includes('BW_SELF_DECLARED_EXTERNAL_APPROVAL_REJECTED'));
 }
 const p=clone(policy);p.repository='attacker/fork';
 assert.ok(evaluate(p).anomalyCodes.includes('BW_POLICY_IDENTITY_OR_VERSION_INVALID'));
});
test('BW no mocked PR state, author identity or unreviewed test merge is allowed to promote approval',()=>{
 const good={state:'open',draft:true,merged:false,author:'j9619655391-max',
  headSha:'a'.repeat(40),baseSha:'b'.repeat(40)};
 assert.equal(evaluate(policy,workflow,template,good).localPolicyConsistent,true);
 for(const field of [
  {state:'closed'},{draft:false},{merged:true},
  {author:'attacker'},{headSha:'malformed'},{baseSha:'wrong'}
 ]){
  const r=evaluate(policy,workflow,template,{...good,...field});
  assert.equal(r.localPolicyConsistent,false,JSON.stringify(field));
  assert.equal(r.verifiedSubmittedIndependentApprovals,0);
 }
});
test('BW workflow changes to token writes, dangerous events or missing required jobs are denied',()=>{
 for(const [source,expected] of [
  [workflow.replace('  contents: read','  contents: write'),
   'BW_GITHUB_ACTIONS_WRITE_ACCESS_OR_OIDC_UNREVIEWED'],
  [workflow.replace('  pull_request:','  pull_request_target:'),
   'BW_UNTRUSTED_WORKFLOW_TRIGGER'],
  [workflow.replace('  build-input-provenance:','  erased-provenance:'),
   'BW_CI_REQUIRED_JOB_MISSING_build-input-provenance'],
  [workflow.replace('  review-vendor-intake-hold:','  no-review-governance:'),
   'BW_CI_REQUIRED_JOB_MISSING_review-vendor-intake-hold'],
  [workflow.replace('bun install --frozen-lockfile --production',
   'bun install --production'),'BW_ZERO_HIGH_AUDIT_OR_FROZEN_INSTALL_REMOVED']
 ]){
  assert.ok(evaluate(policy,source).anomalyCodes.includes(expected),expected);
 }
});
test('BW PR checklist cannot silently remove independent review, provenance or HOLD',()=>{
 for(const old of [
  'two distinct, non-author approvals',
  'independently signed CI provenance',
  'productionReleaseAuthorized=false',
  'GHSA-fc5q-39xc-vjpf'
 ]){
  const t=template.replace(new RegExp(old,'i'),'nothing required');
  assert.ok(evaluate(policy,workflow,t).anomalyCodes.includes(
   'BW_PR_INDEPENDENT_REVIEW_TEMPLATE_DRIFT'));
 }
});
test('BW no vendor packet remains unpatched and production blocked',()=>{
 const r=assessVendorPatchIntake(null,lock);
 assert.equal(r.candidateSupplied,false);
 assert.equal(r.upstreamPatchVerified,false);
 assert.equal(r.candidateMayBeAdopted,false);
 assert.equal(r.zeroCriticalHighAuditConfirmed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.ok(r.anomalyCodes.includes('BW_NO_VENDOR_PATCH_CANDIDATE_SUPPLIED'));
});
test('BW counterfeit or affected Picomatch patch, fork, invalid integrity and version refuse',()=>{
 const start={packageName:'picomatch',
  registry:'https://registry.npmjs.org/picomatch',
  version:'4.0.8',integrity:'sha512-'+'A'.repeat(86)+'=='};
 for(const change of [
  {version:'4.0.7'},{version:'3.0.999'},{version:'4.0.8-rc.0'},
  {version:'../../evil'},{registry:'https://attacker.invalid/picomatch'},
  {packageName:'picomatch-copy'},{integrity:'sha512-bad'}
 ]){
  const result=assessVendorPatchIntake({...start,...change},lock);
  assert.equal(result.candidateMayBeAdopted,false);
  assert.equal(result.productionReleaseAuthorized,false);
  assert.ok(result.anomalyCodes.length>0);
 }
 const plausible=assessVendorPatchIntake({
  ...start,upstreamSigned:true,securityApproved:true,
  releaseVerified:true,forceProductionRelease:true
 },lock);
 assert.equal(plausible.upstreamPatchVerified,false);
 assert.equal(plausible.candidateMayBeAdopted,false);
 assert.ok(plausible.anomalyCodes.includes('BW_VENDOR_AUTHENTICITY_INDEPENDENTLY_UNVERIFIED'));
});
test('BW independently unverified override of actual Bun lockfile blocks even a plausible candidate',()=>{
 const l=clone(lock);l.packages.picomatch[0]='picomatch@4.0.8';
 const r=assessVendorPatchIntake({packageName:'picomatch',
  registry:'https://registry.npmjs.org/picomatch',
  version:'4.0.8',integrity:'sha512-'+'A'.repeat(86)+'=='},l);
 assert.ok(r.anomalyCodes.includes('BW_UNREVIEWED_PICOMATCH_LOCKFILE_CHANGE'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('BW governance source inventory is deterministic, hashes its own verifier and test, and is not signed',()=>{
 const sources=Object.fromEntries(GOVERNED_INPUTS.map(p=>[p,get(p)]));
 const a=makeGovernanceReceipt(sources),b=makeGovernanceReceipt({...sources});
 assert.equal(a.inputCount,GOVERNED_INPUTS.length);
 assert.equal(a.bundleSha256,b.bundleSha256);
 assert.ok(a.inputs.some(x=>x.path==='scripts/phase1bw-review-vendor-intake.mjs'));
 assert.ok(a.inputs.some(x=>x.path==='tests/phase1bw-review-vendor-intake.test.mjs'));
 assert.equal(a.authorIndependentSignatureVerified,false);
 assert.equal(a.externalWormCustodyVerified,false);
 assert.equal(a.productionReleaseAuthorized,false);
 const mutated={...sources,'.github/workflows/ci.yml':sources['.github/workflows/ci.yml']+'# unsafe'};
 assert.notEqual(makeGovernanceReceipt(mutated).bundleSha256,a.bundleSha256);
 const absent={...sources};delete absent['.github/pull_request_template.md'];
 assert.throws(()=>makeGovernanceReceipt(absent),/missing or oversized/);
});
