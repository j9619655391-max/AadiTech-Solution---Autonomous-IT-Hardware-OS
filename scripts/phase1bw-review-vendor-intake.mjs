import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock} from './phase1bt-production-scope.mjs';

// Phase 1BW deny-only review/patch intake. This program CAN NOT retrieve real
// branch protection, verify human identity or certify an npm vendor release.
// Never promote supplied applicant-controlled data into external approval.
export const GOVERNED_INPUTS=Object.freeze([
 '.github/pull_request_template.md',
 '.github/workflows/ci.yml',
 'docs/security/phase1bw-review-policy.json',
 'scripts/phase1bw-review-vendor-intake.mjs',
 'tests/phase1bw-review-vendor-intake.test.mjs'
]);
const REPO='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS';
const DEV='chore/phase0-foundation-20261106';
const CONTROLS=Object.freeze([
 'preventDirectPush','preventForcePush','preventDeletion','requirePullRequest',
 'dismissStaleReviews','requireApprovalOfMostRecentPush',
 'requireCodeOwnerReview','requireConversationResolution',
 'forbidBypassForAdmins','requireExactHeadRevalidation',
 'requireSeparateSecurityReviewer','requireSeparateBusinessOwnerReviewer',
 'prohibitSelfApproval','requireIndependentSignedCIProvenance',
 'requireExternalImmutableAttestationRetention',
 'requireAuthenticatedSecurityAcceptance'
]);
const REQUIRED_JOBS=Object.freeze([
 'baseline','mysql-integration','production-runtime-scope',
 'build-input-provenance','review-vendor-intake-hold',
 'independent-evidence-hold','live-github-governance-hold'
]);
const sha256=s=>createHash('sha256').update(s).digest('hex');
const LOCAL_DOMAIN='aaditech/phase1bw/untrusted-local-governance-inputs/v1\n';
function contains(s,regex){return regex.test(s);}
export function assessReviewerGovernance(policy,workflow,template,pr={}){
 const reasons=new Set();
 if(!policy||policy.schemaVersion!==1||policy.phase!=='1BW'||
    policy.policyKind!=='REQUIRED_BUT_UNVERIFIED_INDEPENDENT_GOVERNANCE'||
    policy.repository!==REPO||policy.protectedBranch!=='main'||
    policy.engineeringBranch!==DEV)
  reasons.add('BW_POLICY_IDENTITY_OR_VERSION_INVALID');
 const required=policy?.requiredControls,observed=policy?.observedState;
 if(!required||typeof required!=='object'){
  reasons.add('BW_REQUIRED_CONTROLS_MISSING');
 }else{
  for(const key of CONTROLS)if(required[key]!==true)
   reasons.add('BW_REQUIRED_CONTROL_WEAKENED_'+key);
  if(!Number.isInteger(required.minimumIndependentApprovals)||
     required.minimumIndependentApprovals<2)
   reasons.add('BW_INDEPENDENT_REVIEW_QUORUM_WEAKENED');
  if(!Array.isArray(required.requireSuccessfulChecks)||
     new Set(required.requireSuccessfulChecks).size!==REQUIRED_JOBS.length||
     REQUIRED_JOBS.some(x=>!required.requireSuccessfulChecks.includes(x)))
   reasons.add('BW_REQUIRED_JOB_QUORUM_WEAKENED');
 }
 if(!observed||typeof observed!=='object'||
    observed.releaseDecision!=='HOLD'||
    observed.productionReleaseAuthorized!==false||
    policy.releaseGate!=='HARD_HOLD'||
    Object.entries(observed).some(([key,value])=>
      key!=='releaseDecision'&&key!=='distinctReviewerApprovalsVerified'&&value!==false)||
    observed?.distinctReviewerApprovalsVerified!==0)
  reasons.add('BW_SELF_DECLARED_EXTERNAL_APPROVAL_REJECTED');
 if(typeof workflow!=='string'||typeof template!=='string')
  throw Error('BW missing workflow or PR template');
 if(!contains(workflow,/^permissions:\s*\n\s*contents:\s*read\s*$/m)||
    contains(workflow,/^\s*(?:id-token|contents|actions|packages|security-events):\s*write\s*$/m))
  reasons.add('BW_GITHUB_ACTIONS_WRITE_ACCESS_OR_OIDC_UNREVIEWED');
 if(!contains(workflow,/^on:\s*\n\s*push:\s*\n\s*pull_request:\s*$/m)||
    contains(workflow,/pull_request_target:|workflow_dispatch:|repository_dispatch:|workflow_run:/))
  reasons.add('BW_UNTRUSTED_WORKFLOW_TRIGGER');
 for(const job of REQUIRED_JOBS){
  if(!workflow.includes('\n  '+job+':\n'))
   reasons.add('BW_CI_REQUIRED_JOB_MISSING_'+job);
 }
 if(!contains(workflow,/Verify patched dependency versions and zero critical\/high advisory matches/)||
    !contains(workflow,/node scripts\/verify-patched-dependencies\.mjs/)||
    !contains(workflow,/bun install --frozen-lockfile --production/))
  reasons.add('BW_ZERO_HIGH_AUDIT_OR_FROZEN_INSTALL_REMOVED');
 if(!contains(template,/two distinct, non-author approvals/i)||
    !contains(template,/independently signed CI provenance/i)||
    !contains(template,/productionReleaseAuthorized=false/)||
    !contains(template,/GHSA-fc5q-39xc-vjpf/i))
  reasons.add('BW_PR_INDEPENDENT_REVIEW_TEMPLATE_DRIFT');
 // PR metadata is contextual only. Never infer real GitHub protection from it.
 if(pr.state!==undefined&&pr.state!=='open')
  reasons.add('BW_PR_NOT_OPEN');
 if(pr.draft!==undefined&&pr.draft!==true)
  reasons.add('BW_PR_NOT_DRAFT');
 if(pr.merged===true)
  reasons.add('BW_PR_ALREADY_MERGED');
 if(pr.baseSha!==undefined&&!/^[0-9a-f]{40}$/.test(pr.baseSha))
  reasons.add('BW_PR_BASE_SHA_MALFORMED');
 if(pr.headSha!==undefined&&!/^[0-9a-f]{40}$/.test(pr.headSha))
  reasons.add('BW_PR_HEAD_SHA_MALFORMED');
 if(pr.author!==undefined&&pr.author!=='j9619655391-max')
  reasons.add('BW_UNEXPECTED_PR_AUTHOR');
 return Object.freeze({
  phase:'1BW',schemaVersion:1,localPolicyConsistent:reasons.size===0,
  anomalyCodes:Object.freeze([...reasons].sort()),
  requestedIndependentReviewerCount:2,
  independentGithubBranchProtectionVerified:false,
  independentReviewerSignaturesAuthenticated:false,
  verifiedSubmittedIndependentApprovals:0,
  ciArtifactIdentityExternallyVerified:false,
  externalImmutableAttestationAccepted:false,
  codeownerEnrollmentIndependentlyVerified:false,
  externalSecurityApprovalVerified:false,
  prodAuthorityEstablished:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
const VERSION=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export function assessVendorPatchIntake(candidate,lock){
 const anomalies=[];
 const locked=lock?.packages?.picomatch?.[0]??null;
 if(locked!=='picomatch@4.0.7')
  anomalies.push('BW_UNREVIEWED_PICOMATCH_LOCKFILE_CHANGE');
 if(candidate==null)anomalies.push('BW_NO_VENDOR_PATCH_CANDIDATE_SUPPLIED');
 else{
  if(!candidate||typeof candidate!=='object'||Array.isArray(candidate))
   anomalies.push('BW_INVALID_VENDOR_PACKET');
  else{
   if(candidate.packageName!=='picomatch'||
      candidate.registry!=='https://registry.npmjs.org/picomatch')
    anomalies.push('BW_UNTRUSTED_UPSTREAM_SOURCE');
   if(typeof candidate.version!=='string'||!VERSION.test(candidate.version))
    anomalies.push('BW_MALFORMED_VERSION');
   else{
    const [major,minor,patch]=candidate.version.split('.').map(Number);
    if(major<4||(major===4&&minor===0&&patch<=7))
     anomalies.push('BW_AFFECTED_VERSION_NOT_ACCEPTABLE');
   }
   if(typeof candidate.integrity!=='string'||
      !/^sha512-[A-Za-z0-9+/]{86}==$/.test(candidate.integrity))
    anomalies.push('BW_NO_REVIEWED_PACKAGE_INTEGRITY');
  }
  // An applicant-controlled JSON packet cannot authenticate vendor release,
  // the published advisory's patched ranges or a real security reviewer.
  anomalies.push('BW_VENDOR_AUTHENTICITY_INDEPENDENTLY_UNVERIFIED');
 }
 return Object.freeze({
  phase:'1BW',schemaVersion:1,
  lockedPicomatchVersion:locked,
  candidateSupplied:candidate!=null,
  anomalyCodes:Object.freeze(anomalies.sort()),
  upstreamPatchVerified:false,
  officialRegistryReleaseIndependentlyAuthenticated:false,
  adverseExtglobRegressionProven:false,
  independentSecurityApprovalVerified:false,
  zeroCriticalHighAuditConfirmed:false,
  lockfileRegenAndCiIndependentlyVerified:false,
  candidateMayBeAdopted:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
export function makeGovernanceReceipt(files){
 const rows=[];
 for(const path of GOVERNED_INPUTS){
  const value=files?.[path];
  if(typeof value!=='string'||!value.length||
     Buffer.byteLength(value)>1024*1024)
   throw Error('BW missing or oversized governance source input: '+path);
  rows.push({path,bytes:Buffer.byteLength(value),sha256:sha256(value)});
 }
 return Object.freeze({
  schemaVersion:1,phase:'1BW',kind:'UNSIGNED_LOCAL_REVIEW_REQUIREMENTS_DIGEST',
  inputCount:rows.length,
  bundleSha256:sha256(LOCAL_DOMAIN+rows.map(r=>
   r.path+'\0'+r.bytes+'\0'+r.sha256+'\n').join('')),
  inputs:rows,
  authorIndependentSignatureVerified:false,
  independentProtectedBranchVerified:false,
  externalWormCustodyVerified:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 });
}
function main(){
 if(process.argv.slice(2).join(' ')!=='--ci-hold')
  throw Error('Phase 1BW supports only --ci-hold; no approval or release command');
 const files={};
 for(const path of GOVERNED_INPUTS){
  const stat=lstatSync(path);
  if(stat.isSymbolicLink()||!stat.isFile()||stat.size>1024*1024)
   throw Error('BW source must be bounded regular non-symlink: '+path);
  files[path]=readFileSync(path,'utf8');
 }
 const policy=JSON.parse(files['docs/security/phase1bw-review-policy.json']);
 const governance=assessReviewerGovernance(
  policy,files['.github/workflows/ci.yml'],
  files['.github/pull_request_template.md']);
 const lock=readBunLock(readFileSync('bun.lock','utf8'));
 // CI deliberately supplies no applicant-controlled real release evidence.
 const vendor=assessVendorPatchIntake(null,lock);
 const localReceipt=makeGovernanceReceipt(files);
 const output={governance,vendor,localReceipt};
 writeFileSync('phase1bw-held-review-vendor-report.json',
  JSON.stringify(output,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(output,null,2));
 if(!governance.localPolicyConsistent||vendor.candidateMayBeAdopted||
    output.governance.productionReleaseAuthorized)
  process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('BW independently governed vendor intake HARD HOLD failed:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
