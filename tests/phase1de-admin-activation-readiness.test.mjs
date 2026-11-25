import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {REPO,AUTHOR,RULESET_PROPOSAL}
 from '../scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs';
import {assessAdminActivationPreflight,ACTION_STAGES}
 from '../scripts/phase1de-admin-activation-readiness.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40);
function governance(){
 return {phase:'1DC',schemaVersion:1,repository:REPO,
  kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
  currentDevelopmentHeadSha:HEAD,currentMainBaseSha:BASE,
  officialMainRefAndDraftPrStable:true,
  observedDistinctCurrentHeadNonauthorApprovals:0,
  officialSubmittedReviewPaginationComplete:true,
  strictRootCoverageCodeownersFiles:0,
  observedStrictBypassFreeMainRulesetCount:0,
  directMainBranchProtectionStatus:'access_denied',
  directMainBranchProtectionExplicitly403:true,
  anomalyCodes:['DC_MAIN_CODEOWNERS_NOT_VERIFIABLY_INSTALLED'],
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 };
}
const proposal=()=>JSON.parse(readFileSync(RULESET_PROPOSAL,'utf8'));
const names={
 securityLogin:'candidate-security-officer',
 businessLogin:'candidate-business-officer'
};
const permission=(name,value='write')=>({
 status:'read',data:{user:{login:name},permission:value}
});
function inspect(change,withNames=true,withPermissions=true){
 const input={github:governance(),proposal:proposal(),
  securityLogin:withNames?names.securityLogin:null,
  businessLogin:withNames?names.businessLogin:null,
  securityPermission:withPermissions?permission(names.securityLogin):null,
  businessPermission:withPermissions?permission(names.businessLogin):null};
 change?.(input);
 return assessAdminActivationPreflight(input);
}
function expectHold(r){
 assert.equal(r.phase,'1DE');
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.reviewOfCorporateRoleAppointmentsAuthenticated,false);
 assert.equal(r.approvedActualAdminWriteOrPolicyInstallation,false);
 assert.equal(r.trustedExternalOfficerProviderAndCaMandatesAuthenticated,false);
 assert.equal(r.finalIndependentProductionAcceptance,false);
 assert.equal(r.canInstallOrChangeMainGovernance,false);
 assert.equal(r.canRequestOrSubmitReviewOrMerge,false);
 assert.equal(r.canActivateExternalProvidersOrDeploy,false);
}
function denied(fn,code){
 const r=inspect(fn);
 assert.ok(r.anomalyCodes.includes(code),
  code+' missing: '+r.anomalyCodes.join(','));
 expectHold(r);
 return r;
}
test('DE: live-style 0 reviews/rules/CODEOWNERS with protection 403 remains HUMAN HOLD',()=>{
 const r=inspect(null,false,false);
 expectHold(r);
 assert.equal(r.officialGithubSourcePrAndMainStable,true);
 assert.equal(r.proposedMainRulesetStructurallyValidOnly,true);
 assert.equal(r.candidateReviewerSyntaxAndIndependenceValid,false);
 assert.equal(r.technicalReviewerWritePermissionsObservedOnly,false);
 assert.equal(r.officialMainCodeownersVisible,false);
 assert.equal(r.officialMainRulesAndProtectionVisible,false);
 assert.equal(r.observedTwoNonauthorExactHeadGithubReviewsOnly,false);
 assert.equal(r.requiredHumanActions.length,6);
 assert.equal(r.numberOfMandatoryHostedCheckContexts,8);
 assert.equal(r.independentExternalGateCount,9);
});
test('DE: even synthetic technically write-capable distinct nominated users are not legal appointments',()=>{
 const r=inspect();
 expectHold(r);
 assert.equal(r.candidateAdminPreparationInputsMathematicallyConsistentOnly,true,
  r.anomalyCodes.join(','));
 assert.equal(r.technicalReviewerWritePermissionsObservedOnly,true);
 assert.equal(r.candidateReviewerSyntaxAndIndependenceValid,true);
 assert.match(r.proposedMainRulesetPayloadSha256,/^[a-f0-9]{64}$/);
 assert.match(r.proposedCodeownersContentSha256,/^[a-f0-9]{64}$/);
 assert.equal(r.proposedCodeownersNotInstalled,true);
 assert.equal(r.reviewOfCorporateRoleAppointmentsAuthenticated,false);
 assert.ok(r.anomalyCodes.includes('DE_NO_TWO_REAL_EXACT_HEAD_APPROVALS_OBSERVED'));
});
test('DE: all mocked GitHub technical gates passing still cannot prove corporate mandate or production GO',()=>{
 const r=inspect(input=>{
  input.github.observedDistinctCurrentHeadNonauthorApprovals=2;
  input.github.strictRootCoverageCodeownersFiles=1;
  input.github.observedStrictBypassFreeMainRulesetCount=1;
  input.github.directMainBranchProtectionStatus='read';
  input.github.directMainBranchProtectionExplicitly403=false;
 });
 expectHold(r);
 assert.equal(r.officialMainCodeownersVisible,true);
 assert.equal(r.officialMainRulesAndProtectionVisible,true);
 assert.equal(r.observedTwoNonauthorExactHeadGithubReviewsOnly,true);
 assert.equal(r.anomalyCodes.length,0);
 assert.equal(r.finalIndependentProductionAcceptance,false);
});
test('DE: report never includes candidate login or GitHub permission token',()=>{
 const report=JSON.stringify(inspect());
 assert.equal(report.includes(names.securityLogin),false);
 assert.equal(report.includes(names.businessLogin),false);
 assert.equal(report.includes('GITHUB_READ_TOKEN'),false);
 assert.equal(report.includes('BEGIN PUBLIC KEY'),false);
});
test('DE: existing reviewed Phase 1CM ruleset proposal is structurally valid but UNINSTALLED',()=>{
 const r=inspect();
 assert.equal(r.proposedMainRulesetStructurallyValidOnly,true);
 assert.equal(r.proposedCodeownersNotInstalled,true);
 assert.equal(r.approvedActualAdminWriteOrPolicyInstallation,false);
 expectHold(r);
});
test('DE: missing proposal and 2 weak pull-review rules rejected',()=>{
 denied(input=>{input.proposal=null},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
 denied(input=>{input.proposal.rules[2].parameters.required_approving_review_count=1},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
 denied(input=>{input.proposal.rules[2].parameters.require_last_push_approval=false},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
});
test('DE: bypass actors, missing check contexts and non-main target rejected',()=>{
 denied(input=>{input.proposal.bypass_actors=[{actor_id:1}]},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
 denied(input=>{input.proposal.rules[3].parameters.required_status_checks.pop()},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
 denied(input=>{input.proposal.conditions.ref_name.include=['refs/heads/development']},
  'DE_UNAPPLIED_MAIN_RULESET_PROPOSAL_INVALID');
});
test('DE: without real nominated reviewers there is no CODEOWNERS draft, permission state stays unknown',()=>{
 const r=inspect(null,false,false);
 expectHold(r);
 assert.equal(r.proposedCodeownersContentSha256,null);
 assert.equal(r.candidateReviewerSyntaxAndIndependenceValid,false);
 assert.ok(r.anomalyCodes.includes(
  'DE_AUTHORIZED_HUMAN_REVIEWER_NOMINATIONS_NOT_SUPPLIED'));
});
test('DE: one or both GitHub users must not be author or identical',()=>{
 for(const fn of [
  x=>{x.securityLogin=AUTHOR},
  x=>{x.businessLogin=AUTHOR},
  x=>{x.businessLogin=x.securityLogin},
  x=>{x.businessLogin='INVALID/SLASH'},
  x=>{x.securityLogin=' '}
 ])denied(fn,'DE_AUTHORIZED_HUMAN_REVIEWER_NOMINATIONS_NOT_SUPPLIED');
});
test('DE: unauthenticated claimed security reviewer or business reviewer not technically verified',()=>{
 for(const fn of [
  x=>{x.securityPermission={status:'access_denied',data:null}},
  x=>{x.businessPermission={status:'access_denied',data:null}},
  x=>{x.securityPermission={status:'not_found_or_hidden',data:null}},
  x=>{x.businessPermission=null}
 ])denied(fn,'DE_NOMINEE_WRITE_PERMISSIONS_NOT_OBSERVED');
});
test('DE: read or triage permission does not qualify as actual repo write access',()=>{
 for(const role of ['securityPermission','businessPermission'])
  for(const value of ['read','triage','none'])
   denied(input=>{input[role].data.permission=value},
    'DE_NOMINEE_WRITE_PERMISSIONS_NOT_OBSERVED');
});
test('DE: forged user account in official permission payload cannot be counted',()=>{
 denied(input=>{input.securityPermission.data.user.login='other-candidate'},
  'DE_NOMINEE_WRITE_PERMISSIONS_NOT_OBSERVED');
 denied(input=>{input.businessPermission.data.user.login=AUTHOR},
  'DE_NOMINEE_WRITE_PERMISSIONS_NOT_OBSERVED');
});
test('DE: official PR/head SHA unreadable, wrong repository and GO report fail closed',()=>{
 for(const fn of [
  x=>{x.github.currentDevelopmentHeadSha='wrong'},
  x=>{x.github.currentMainBaseSha='f'.repeat(39)},
  x=>{x.github.repository='another/repo'},
  x=>{x.github.officialMainRefAndDraftPrStable=false},
  x=>{x.github.productionReleaseAuthorized=true},
  x=>{x.github.releaseDecision='GO'}
 ])denied(fn,'DE_LIVE_GITHUB_PR_MAIN_STABILITY_UNVERIFIED');
});
test('DE: no GitHub governance snapshot is never interpreted as a verified admin green signal',()=>{
 const r=assessAdminActivationPreflight();
 expectHold(r);
 assert.equal(r.officialGithubSourcePrAndMainStable,false);
 assert.equal(r.proposedMainRulesetStructurallyValidOnly,false);
 assert.equal(r.candidateAdminPreparationInputsMathematicallyConsistentOnly,false);
});
test('DE: base-main CODEOWNERS cannot be accepted from a proposed development draft',()=>{
 const r=inspect();
 expectHold(r);
 assert.equal(r.proposedCodeownersNotInstalled,true);
 assert.equal(r.officialMainCodeownersVisible,false);
 assert.ok(r.anomalyCodes.includes(
  'DE_BASE_MAIN_CODEOWNERS_NOT_VERIFIABLY_EFFECTIVE'));
});
test('DE: direct protection access denied never means protection is definitely disabled',()=>{
 const r=inspect();
 expectHold(r);
 assert.equal(r.officialMainRulesAndProtectionVisible,false);
 assert.equal(r.requiredHumanActions[3].status,
  'ADMIN_RULESET_REVIEW_OR_ACCESS_REQUIRED');
});
test('DE: merely two GitHub technical approvals do not prove independent named Security and Business roles',()=>{
 const r=inspect(x=>{
  x.github.observedDistinctCurrentHeadNonauthorApprovals=2;
 });
 expectHold(r);
 assert.equal(r.observedTwoNonauthorExactHeadGithubReviewsOnly,true);
 assert.equal(r.reviewOfCorporateRoleAppointmentsAuthenticated,false);
});
test('DE: source integrity not stable when reported PR stable boolean is false',()=>{
 denied(x=>{x.github.officialMainRefAndDraftPrStable=false},
  'DE_LIVE_GITHUB_PR_MAIN_STABILITY_UNVERIFIED');
});
test('DE: six ordered action stages and statuses remain review-only, not executable API commands',()=>{
 const r=inspect();
 assert.deepEqual(r.requiredHumanActions.map(x=>x.stage),ACTION_STAGES);
 assert.equal(r.requiredHumanActions.every(x=>x.office?.length>8),true);
 assert.equal(r.requiredHumanActions.every(x=>!('endpoint' in x||'writeToken' in x)),true);
 expectHold(r);
});
test('DE: issuer/CA/WORM/DR/oidc/Legal staging remain independent even with technical GitHub readiness',()=>{
 const r=inspect(x=>{
  x.github.observedDistinctCurrentHeadNonauthorApprovals=2;
  x.github.strictRootCoverageCodeownersFiles=1;
  x.github.observedStrictBypassFreeMainRulesetCount=1;
  x.github.directMainBranchProtectionStatus='read';
  x.github.directMainBranchProtectionExplicitly403=false;
 });
 expectHold(r);
 assert.equal(r.independentExternalGateCount,9);
 assert.equal(r.trustedExternalOfficerProviderAndCaMandatesAuthenticated,false);
});
