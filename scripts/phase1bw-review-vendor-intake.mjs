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
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json',
 'scripts/phase1bw-review-vendor-intake.mjs',
 'tests/phase1bw-review-vendor-intake.test.mjs',
 'scripts/phase1cb-public-advisory-observer.mjs',
 'scripts/phase1ch-upstream-patch-publication-preflight.mjs',
 'scripts/phase1cj-advisory-withdrawal-quarantine.mjs',
 'scripts/phase1ck-picomatch-bounded-adjudication.mjs',
 'scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs',
 'scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs',
 'scripts/phase1cn-ruleset-bypass-reconciliation.mjs',
 'scripts/phase1co-live-exact-head-reviewer-quorum.mjs',
 'scripts/phase1cp-github-actions-check-app-source.mjs',
 'scripts/phase1cq-postrun-github-check-receipt.mjs',
 'scripts/phase1cr-actions-jobs-reconciliation.mjs',
 'scripts/phase1ct-dual-event-postrun-governance.mjs',
 'scripts/phase1cu-independent-governance-handoff.mjs',
 'scripts/phase1cv-policy-freeze-detached-candidate.mjs',
 'scripts/phase1cw-crossrun-revocation-recovery-candidate.mjs',
 'scripts/phase1cx-pinned-external-source-highwatermark.mjs',
 'scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs',
 'scripts/phase1cz-corporate-mandate-incident-quarantine.mjs',
 'scripts/phase1da-appendonly-incident-replay-ledger.mjs',
 'scripts/phase1db-external-mandate-cas-sealed-recovery.mjs',
 'scripts/phase1dc-live-external-governance-readiness.mjs',
 'scripts/phase1dd-authorized-human-handoff.mjs',
 'scripts/phase1de-admin-activation-readiness.mjs',
 'scripts/phase1df-role-bound-readonly-reconciliation.mjs',
 'scripts/phase1dg-effective-codeowners.mjs',
 'scripts/phase1di-terminal-main-review-recheck.mjs',
 'scripts/phase1dk-submitted-review-history-integrity.mjs',
 'scripts/phase1dl-ephemeral-reviewer-handoff-continuity.mjs',
 'scripts/phase1dm-corporate-appointment-challenge-handoff.mjs',
 'scripts/phase1dn-corporate-role-session-reconciliation.mjs',
 'scripts/phase1do-offline-registrar-witness-enrollment.mjs',
 'scripts/phase1dp-offline-registrar-witness-equivocation.mjs',
 'scripts/phase1dr-offline-keyid-bound-witness-v2.mjs',
 'scripts/phase1ds-offline-witness-key-rollover.mjs',
 'scripts/phase1dt-offline-rollover-checkpoint-continuity.mjs',
 'scripts/phase1du-offline-multi-epoch-rollover-chain.mjs',
 'scripts/phase1dv-offline-observer-publication-candidate.mjs',
 'scripts/phase1dw-offline-observer-enrollment-revocation.mjs',
 'scripts/phase1dx-offline-evidence-incident-recovery.mjs',
 'scripts/phase1dy-offline-source-admission-unfreeze-preconditions.mjs',
 'scripts/phase1dz-offline-cross-epoch-anchor-custody.mjs',
 'scripts/phase1ea-offline-gossip-admission-boundary.mjs',
 'scripts/phase1eb-offline-cross-run-gossip-incident-custody.mjs',
 'scripts/phase1ec-offline-authority-handoff-custody.mjs',
 'scripts/phase1ed-disconnected-authority-verification-ports.mjs',
 'scripts/phase1ee-disconnected-version-failure-taxonomy.mjs',
 'scripts/phase1ef-disconnected-quarantine-escalation.mjs',
 'scripts/phase1eg-unsent-manual-authority-handoff.mjs',
 'scripts/phase1eh-disconnected-response-intake-quarantine.mjs',
 'database/migrations/0044_en_workflow_review_scopes.sql',
 'scripts/migrate-en-reviewer-scopes.ts',
 'tests/en-reviewer-scope-migration.test.ts',
 'database/migrations/0045_eo_stock_journal_review_scopes.sql',
 'scripts/migrate-eo-reviewer-scopes.ts',
 'tests/eo-reviewer-scope-migration.test.ts',
 'database/migrations/0046_ep_proof_key_trust_review_scopes.sql',
 'database/migrations/0047_eq_provider_review_scopes.sql',
 'scripts/migrate-eq-provider-scopes.ts',
 'tests/eq-provider-reviewer-scope-migration.test.ts',
 'server/security/providerReviewScope.ts',
 'server/providerBridge/reviewRouter.ts',
 'server/providerSandbox/reviewRouter.ts',
 'server/providerSelection/reviewRouter.ts',
 'server/providerOnboarding/reviewRouter.ts',
 'scripts/migrate-ep-reviewer-scopes.ts',
 'server/security/sensitiveReviewScope.ts',
 'server/proofFoundation/reviewRouter.ts',
 'server/keyLifecycle/reviewRouter.ts',
 'server/externalTrust/reviewRouter.ts',
 'tests/signed-proof-mysql.integration.ts',
 'tests/key-lifecycle-mysql.integration.ts',
 'tests/provider-bridge-mysql.integration.ts',
 'tests/provider-sandbox-mysql.integration.ts',
 'tests/provider-selection-mysql.integration.ts',
 'tests/external-trust-mysql.integration.ts',
 'tests/ep-reviewer-scope-migration.test.ts',
 'server/stockFoundation/reviewRouter.ts',
 'server/journalFoundation/reviewRouter.ts',
 'tests/stock-foundation-mysql.integration.ts',
 'tests/journal-foundation-mysql.integration.ts',
 'server/intake/reviewRouter.ts',
 'server/dispatch/reviewRouter.ts',
 'server/evidenceChain/reviewRouter.ts',
 'tests/dispatch-mysql.integration.ts',
 'tests/evidence-chain-mysql.integration.ts',
 'server/intake/ownerRouter.ts',
 'tests/intake-mysql.integration.ts',
 'server/inventory/router.ts',
 'tests/inventory-mysql.integration.ts',
 'server/crm/repository.ts',
 'server/crm/router.ts',
 'server/quotes/router.ts',
 'server/procurement/ownerRouter.ts',
 'tests/staging-preflight.test.ts',
 'tests/el-reviewer-scope-migration.test.ts',
 'tests/crm-mysql.integration.ts',
 'tests/fa-role-cycle-concurrency-mysql.integration.ts',
 'tests/fb-runtime-db-privileges.test.ts',
 'tests/fc-runtime-db-privileges-mysql.integration.ts',
 'tests/fd-crm-owner-race-mysql.integration.ts',
 'tests/fk-quote-owner-race-mysql.integration.ts',
 'server/troubleshooting/guides.ts',
 'server/troubleshooting/router.ts',
 'src/App.tsx',
 'src/components/Header.tsx',
 'src/components/WindowsTroubleshootingWorkspace.tsx',
 'tests/fm-troubleshooting.test.ts',
 'database/migrations/0049_fn_service_tickets_internal.sql',
 'scripts/migrate-service-tickets.ts',
 'server/serviceDesk/validation.ts',
 'server/serviceDesk/router.ts',
 'src/components/LiveServiceDeskWorkspace.tsx',
 'tests/fn-service-tickets.test.ts',
 'tests/fn-service-tickets-mysql.integration.ts',
 'database/authority/phase1fo_active_owner_guard.sql',
 'database/authority/phase1gi_session_quote_bind_candidate.sql',
 'database/authority/phase1gj_quote_intent_candidate.sql',
 'database/authority/phase1gk_customer_create_intent_candidate.sql',
 'database/authority/phase1gl_product_create_intent_candidate.sql',
 'database/authority/phase1gl_lead_create_intent_candidate.sql',
 'tests/fo-definer-owner-guard.test.ts',
 'tests/fo-owner-guard-mysql.integration.ts',
 'database/migrations/0051_gf_crm_quote_write_once.sql',
 'scripts/migrate-gf-provenance.ts',
 'tests/gf-provenance-mysql.integration.ts',
 'tests/procurement-mysql.integration.ts',
 'database/migrations/0043_el_reviewer_scope_candidates.sql',
 'scripts/migrate-el-reviewer-scopes.ts',
 'server/security/reviewerScopeRouter.ts',
 'server/quotes/reviewRouter.ts',
 'tests/er-legacy-reviewer-active-identity.test.mjs',
 'tests/es-reviewer-nominator-transaction.test.mjs',
 'tests/et-reviewer-lifecycle.test.mjs',
 'scripts/migrate-ew-role-cycle.ts',
 'tests/ex-trigger-body-integrity.test.ts',
 'server/security/adminRouter.ts',
 'server/procurement/reviewRouter.ts',
 'scripts/lib/stagingPreflight.ts',
 'scripts/staging-preflight.ts',
 'scripts/phase1fb-runtime-db-privileges.ts',
 'package.json',
 'server.ts',
 'scripts/phase1ei-independent-admission-prerequisites.mjs',
 'scripts/phase1by-github-governance-observer.mjs',
 'scripts/phase1cs-push-head-governance.mjs',
 'scripts/phase1ck-picomatch-worker.cjs',
 'scripts/phase1ci-picomatch-exposure-preflight.mjs',
 'tests/phase1cb-public-advisory-observer.test.mjs',
 'tests/phase1ch-upstream-patch-publication-preflight.test.mjs',
 'tests/phase1cj-advisory-withdrawal-quarantine.test.mjs',
 'tests/phase1ck-picomatch-bounded-adjudication.test.mjs',
 'tests/phase1cl-live-codeowners-reviewer-onboarding.test.mjs',
 'tests/phase1cm-admin-ruleset-reviewer-handoff.test.mjs',
 'tests/phase1cn-ruleset-bypass-reconciliation.test.mjs',
 'tests/phase1co-live-exact-head-reviewer-quorum.test.mjs',
 'tests/phase1cp-github-actions-check-app-source.test.mjs',
 'tests/phase1cq-postrun-github-check-receipt.test.mjs',
 'tests/phase1cr-actions-jobs-reconciliation.test.mjs',
 'tests/phase1ct-dual-event-postrun-governance.test.mjs',
 'tests/phase1cu-independent-governance-handoff.test.mjs',
 'tests/phase1cv-policy-freeze-detached-candidate.test.mjs',
 'tests/phase1cw-crossrun-revocation-recovery-candidate.test.mjs',
 'tests/phase1cx-pinned-external-source-highwatermark.test.mjs',
 'tests/phase1cy-operator-pin-lifecycle-quarantine.test.mjs',
 'tests/phase1cz-corporate-mandate-incident-quarantine.test.mjs',
 'tests/phase1da-appendonly-incident-replay-ledger.test.mjs',
 'tests/phase1db-external-mandate-cas-sealed-recovery.test.mjs',
 'tests/phase1dc-live-external-governance-readiness.test.mjs',
 'tests/phase1dd-authorized-human-handoff.test.mjs',
 'tests/phase1de-admin-activation-readiness.test.mjs',
 'tests/phase1df-role-bound-readonly-reconciliation.test.mjs',
 'tests/phase1dg-effective-codeowners.test.mjs',
 'tests/phase1dh-codeowners-contract.test.mjs',
 'tests/phase1di-terminal-main-review-recheck.test.mjs',
 'tests/phase1dk-submitted-review-history-integrity.test.mjs',
 'tests/phase1dl-ephemeral-reviewer-handoff-continuity.test.mjs',
 'tests/phase1dm-corporate-appointment-challenge-handoff.test.mjs',
 'tests/phase1dn-corporate-role-session-reconciliation.test.mjs',
 'tests/phase1do-offline-registrar-witness-enrollment.test.mjs',
 'tests/phase1dp-offline-registrar-witness-equivocation.test.mjs',
 'tests/phase1dr-offline-keyid-bound-witness-v2.test.mjs',
 'tests/phase1ds-offline-witness-key-rollover.test.mjs',
 'tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs',
 'tests/phase1by-github-governance-observer.test.mjs',
 'tests/phase1dj-bounded-github-pr-observer.test.mjs',
 'tests/helpers/phase1cz-candidate-fixture.mjs',
 'tests/helpers/phase1da-candidate-fixture.mjs',
 'tests/helpers/phase1db-candidate-fixture.mjs',
 'tests/phase1cs-push-head-governance.test.mjs',
 'tests/phase1ci-picomatch-exposure-preflight.test.mjs',
 'scripts/phase1cc-ci-evidence-envelope.mjs',
 'scripts/phase1cd-external-custody-preflight.mjs',
 'scripts/phase1ce-cross-witness-retrieval-preflight.mjs',
 'scripts/phase1cf-checkpoint-publication-review-preflight.mjs',
 'scripts/phase1cg-external-source-reconciliation-preflight.mjs',
 'tests/phase1cc-ci-evidence-envelope.test.mjs',
 'tests/phase1cd-external-custody-preflight.test.mjs',
 'tests/phase1ce-cross-witness-retrieval-preflight.test.mjs',
 'tests/phase1cf-checkpoint-publication-review-preflight.test.mjs',
 'tests/phase1cg-external-source-reconciliation-preflight.test.mjs'
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
 'independent-evidence-hold','live-github-governance-hold',
 'source-merge-lineage-hold'
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
