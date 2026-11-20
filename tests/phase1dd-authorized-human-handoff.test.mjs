import test from 'node:test';
import assert from 'node:assert/strict';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {EXTERNAL_GATES}
 from '../scripts/phase1dc-live-external-governance-readiness.mjs';
import {ACTIONS,assessIndependentOperatorHandoff}
 from '../scripts/phase1dd-authorized-human-handoff.mjs';
const HEAD='a'.repeat(40),BASE='b'.repeat(40),
 NOW='2026-11-20T09:00:00.000Z';
function governance(){
 return {
  phase:'1DC',kind:'ACTUAL_GITHUB_READONLY_GOVERNANCE_ESCALATION_HARD_HOLD',
  repository:REPO,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD',
  officialMainRefAndDraftPrStable:true,
  currentDevelopmentHeadSha:HEAD,currentMainBaseSha:BASE,
  observedSubmittedReviewCount:0,
  observedDistinctCurrentHeadNonauthorApprovals:0,
  strictRootCoverageCodeownersFiles:0,
  observedStrictBypassFreeMainRulesetCount:0,
  observedActiveBranchRulesetCount:0,
  technicallyObservedGithubPrerequisitesOnly:false,
  directMainBranchProtectionStatus:'access_denied',
  directMainBranchProtectionExplicitly403:true,
  anomalyCodes:[
   'DC_MAIN_CODEOWNERS_NOT_VERIFIABLY_INSTALLED',
   'DC_NO_VISIBLE_ACTIVE_BYPASS_FREE_MAIN_RULESET',
   'DC_DIRECT_BRANCH_PROTECTION_UNVERIFIED_OR_WEAK'
  ]
 };
}
function metadata(){
 return {
  schemaVersion:1,repository:REPO,sourceHeadSha:HEAD,
  mainBaseSha:BASE,createdAt:'2026-11-20T08:58:00.000Z',
  records:ACTIONS.map(([gate,custodianRole,evidenceClass],i)=>({
   gate,custodianRole,evidenceClass,
   recordDigestSha256:String(i+1).repeat(64),
   collectedAt:'2026-11-20T08:57:00.000Z',
   expiresAt:'2026-12-20T09:00:00.000Z',
   reviewState:'UNVERIFIED'
  }))
 };
}
function inspect(edit,includeMetadata=false){
 const g=governance(),m=includeMetadata?metadata():null;
 edit?.(g,m);
 return assessIndependentOperatorHandoff({
  governance:g,metadata:m,now:NOW
 });
}
function rejected(change,code,includeMetadata=true){
 const r=inspect(change,includeMetadata);
 assert.ok(r.anomalyCodes.includes(code),
  'expected '+code+' got '+r.anomalyCodes.join('|'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
}
test('DD: actual-style 0 review, 0 owners and 0 rules + 403 remain concrete action blockers',()=>{
 const r=inspect();
 assert.equal(r.precedingLiveGithubSnapshotStructurallyAccepted,true);
 assert.equal(r.githubTechnicallyObservedOnly,false);
 assert.equal(r.outstandingActions.length,9);
 assert.equal(r.candidateMetadataReferenceCount,0);
 assert.equal(r.outstandingActions[1].technicalSignal,'NOT_VERIFIABLY_INSTALLED');
 assert.equal(r.outstandingActions[2].technicalSignal,
  'ADMIN_ACCESS_REQUIRED_UNKNOWN_PROTECTION');
 assert.equal(r.outstandingActions[3].technicalSignal,'APPROVALS_MISSING_OR_STALE');
 assert.equal(r.authorityIntakeComplete,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('DD: even perfect applicant-provided nine metadata references are UNVERIFIED and never GO',()=>{
 const r=inspect(()=>{},true);
 assert.equal(r.submittedHumanEvidenceMetadataLocallyWellFormedOnly,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.candidateMetadataReferenceCount,9);
 assert.equal(r.independentCorporateOrProviderEvidenceVerified,false);
 assert.equal(r.acceptedLatestHeadIndependentReviewerMandates,false);
 assert.equal(r.externallyDurableWormCasOrCaTrustVerified,false);
 assert.equal(r.authorityIntakeComplete,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('DD: external action register covers exact nine source gates with role-specific tasks',()=>{
 assert.equal(ACTIONS.length,EXTERNAL_GATES.length);
 assert.deepEqual(ACTIONS.map(x=>x[0]),EXTERNAL_GATES);
 const r=inspect();
 assert.equal(new Set(r.outstandingActions.map(x=>x.gate)).size,9);
 for(const x of r.outstandingActions){
  assert.equal(x.independentlyAuthenticated,false);
  assert.equal(typeof x.requiredNextAction,'string');
  assert.ok(x.requiredNextAction.length>32);
  assert.ok(x.custodianRole.length>8);
 }
});
test('DD: GitHub technical signal alone never claims corporate appointments or release',()=>{
 const r=inspect(g=>{
  g.observedDistinctCurrentHeadNonauthorApprovals=2;
  g.strictRootCoverageCodeownersFiles=1;
  g.observedStrictBypassFreeMainRulesetCount=1;
  g.observedActiveBranchRulesetCount=1;
  g.technicallyObservedGithubPrerequisitesOnly=true;
  g.directMainBranchProtectionStatus='read';
  g.directMainBranchProtectionExplicitly403=false;
  g.anomalyCodes=[];
 });
 assert.equal(r.githubTechnicallyObservedOnly,true);
 assert.equal(r.outstandingActions[1].technicalSignal,
  'TECHNICALLY_OBSERVED_NOT_LEGALLY_APPROVED');
 assert.equal(r.outstandingActions[3].technicalSignal,
  'TECHNICALLY_OBSERVED_NO_CORPORATE_MANDATE');
 assert.equal(r.independentCorporateOrProviderEvidenceVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('DD: lack of upstream read-only GitHub report is detected, never default success',()=>{
 for(const g of [null,undefined,{},'APPROVED',[],{releaseDecision:'HOLD'}]){
  const r=assessIndependentOperatorHandoff({governance:g,now:NOW});
  assert.ok(r.anomalyCodes.includes('DD_PRECEDING_GITHUB_READONLY_HOLD_REPORT_INVALID'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('DD: forged preceding phase, kind, repo, GO, production or blocking flags rejected',()=>{
 for(const [field,value] of [
  ['phase','1DE'],['kind','PRODUCTION_READY'],['repository','attacker/repo'],
  ['releaseDecision','GO'],['productionReleaseAuthorized',true],
  ['productionReleaseBlocked',false]
 ])rejected(g=>{g[field]=value;},
  'DD_PRECEDING_GITHUB_READONLY_HOLD_REPORT_INVALID',false);
});
test('DD: unreadable, malformed or unstable previous PR/main SHA never endorsed',()=>{
 for(const [field,value] of [
  ['officialMainRefAndDraftPrStable',false],
  ['currentDevelopmentHeadSha','0'.repeat(39)],
  ['currentMainBaseSha','invalid'],
  ['currentDevelopmentHeadSha',null],
  ['currentMainBaseSha','']
 ])rejected(g=>{g[field]=value;},
  'DD_OFFICIAL_HEAD_BASE_NOT_STABLY_VERIFIED',false);
});
test('DD: negative, non-integer, null or too-large GitHub counters are untrusted',()=>{
 for(const field of [
  'observedSubmittedReviewCount',
  'observedDistinctCurrentHeadNonauthorApprovals',
  'strictRootCoverageCodeownersFiles',
  'observedStrictBypassFreeMainRulesetCount',
  'observedActiveBranchRulesetCount'
 ])for(const value of [-1,null,0.5,100001,'two'])
  rejected(g=>{g[field]=value;},
   'DD_GITHUB_READONLY_COUNTS_MISSING_OR_UNTRUSTED',false);
});
test('DD: a 403 branch-protection gate remains unknown and cannot be promoted to absent',()=>{
 const r=inspect();
 assert.equal(r.outstandingActions[2].technicalSignal,
  'ADMIN_ACCESS_REQUIRED_UNKNOWN_PROTECTION');
 assert.equal(r.productionReleaseAuthorized,false);
});
test('DD: contradictory GitHub 403 flag and read status detected',()=>{
 rejected(g=>{g.directMainBranchProtectionStatus='read';},
  'DD_PROTECTION_403_NOT_PRESERVED_AS_UNKNOWN',false);
 rejected(g=>{g.directMainBranchProtectionStatus='FORCE_GO';},
  'DD_MAIN_BRANCH_PROTECTION_STATUS_UNVERIFIED',false);
});
test('DD: missing, malformed or synthesized upstream DC anomaly codes rejected',()=>{
 for(const anomalies of [
  null,['SUPERUSER_APPROVED'],['DC_BAD',18],['A'.repeat(150)]
 ])rejected(g=>{g.anomalyCodes=anomalies;},
  'DD_UPSTREAM_GITHUB_ANOMALY_LIST_INVALID',false);
});
test('DD: ready flag cannot accompany an unstable official snapshot',()=>{
 rejected(g=>{
  g.technicallyObservedGithubPrerequisitesOnly=true;
  g.officialMainRefAndDraftPrStable=false;
 },'DD_TECHNICAL_READY_WITH_UNSTABLE_OFFICIAL_SOURCE',false);
});
test('DD: technical ready with contradictory upstream anomalies is not clean',()=>{
 rejected(g=>{
  g.technicallyObservedGithubPrerequisitesOnly=true;
 },'DD_TECHNICAL_READY_BUT_UPSTREAM_GITHUB_ANOMALIES',false);
});
test('DD: current verifier clock must be canonical ISO UTC, not invalid or future spoof',()=>{
 for(const now of ['invalid','2026-11-20T09:00:00Z','2040-01-01',null]){
  const r=assessIndependentOperatorHandoff({governance:governance(),now});
  assert.ok(r.anomalyCodes.includes('DD_INVALID_OPERATOR_CLOCK'));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('DD: schema requires only narrow metadata keys, no secret, URL or arbitrary flags',()=>{
 rejected((g,m)=>{m.secret='malicious-value'},
  'DD_UNREVIEWED_INTAKE_METADATA_SCHEMA');
 rejected((g,m)=>{m.schemaVersion=2},
  'DD_INTAKE_REPOSITORY_OR_CURRENT_HEAD_MISMATCH');
 rejected((g,m)=>{delete m.repository},
  'DD_UNREVIEWED_INTAKE_METADATA_SCHEMA');
});
test('DD: metadata must remain exact real head/base and repository-bound',()=>{
 for(const [field,value] of [
  ['repository','other/repo'],['sourceHeadSha','f'.repeat(40)],
  ['mainBaseSha','0'.repeat(40)],['sourceHeadSha','bad']
 ])rejected((g,m)=>{m[field]=value;},
  'DD_INTAKE_REPOSITORY_OR_CURRENT_HEAD_MISMATCH');
});
test('DD: stale, badly formatted, future and clock-skewed metadata does not qualify',()=>{
 for(const when of [
  '2026-11-20T08:00:00.000Z',
  '2026-11-20T09:30:00.000Z',
  'not-a-date','2026-11-20T08:58:00Z'
 ])rejected((g,m)=>{m.createdAt=when;},
  'DD_INTAKE_METADATA_FRESHNESS_UNVERIFIED');
});
test('DD: missing, truncated or additional metadata gate rejected',()=>{
 rejected((g,m)=>m.records.pop(),
  'DD_EXACT_EXTERNAL_GATE_METADATA_SET_REQUIRED');
 rejected((g,m)=>m.records.push({...m.records[0]}),
  'DD_EXACT_EXTERNAL_GATE_METADATA_SET_REQUIRED');
 rejected((g,m)=>{m.records=[]},
  'DD_EXACT_EXTERNAL_GATE_METADATA_SET_REQUIRED');
});
test('DD: duplicate gate, unknown gate or missing required gate rejected',()=>{
 rejected((g,m)=>{m.records[1].gate=m.records[0].gate},
  'DD_DUPLICATE_OR_UNKNOWN_EXTERNAL_GATE');
 rejected((g,m)=>{m.records[1].gate='PRODUCTION_BYPASS'},
  'DD_DUPLICATE_OR_UNKNOWN_EXTERNAL_GATE');
});
test('DD: custodian role or evidence category substitution cannot authenticate applicant',()=>{
 rejected((g,m)=>{m.records[1].custodianRole=m.records[0].custodianRole},
  'DD_EXTERNAL_CUSTODIAN_OR_REVIEW_ASSERTION_INVALID');
 rejected((g,m)=>{m.records[0].evidenceClass='CA_APPROVED'},
  'DD_EXTERNAL_CUSTODIAN_OR_REVIEW_ASSERTION_INVALID');
});
test('DD: invented VERIFIED/APPROVED record status is blocked',()=>{
 for(const reviewState of ['VERIFIED','APPROVED','GO',true]){
  rejected((g,m)=>{m.records[3].reviewState=reviewState},
   'DD_EXTERNAL_CUSTODIAN_OR_REVIEW_ASSERTION_INVALID');
 }
});
test('DD: no record accepts extra PII, secrets, usernames or provider credentials',()=>{
 for(const prop of ['token','privateKey','actualReviewerName','credentialUri']){
  rejected((g,m)=>{m.records[0][prop]='secret'},
   'DD_UNREVIEWED_EXTERNAL_RECORD_FIELDS');
 }
});
test('DD: stale, repeated, non-hex, missing and all-zero evidence digests blocked',()=>{
 for(const edit of [
  m=>{m.records[0].recordDigestSha256='1'.repeat(63)},
  m=>{m.records[0].recordDigestSha256='g'.repeat(64)},
  m=>{m.records[0].recordDigestSha256='0'.repeat(64)},
  m=>{m.records[1].recordDigestSha256=m.records[0].recordDigestSha256}
 ])rejected((g,m)=>edit(m),'DD_EVIDENCE_DIGEST_MISSING_REPEATED_OR_FORGED');
});
test('DD: collection and expiry times must be canonical and within bounds',()=>{
 for(const edit of [
  m=>{m.records[3].collectedAt='2026-11-20T01:00:00.000Z'},
  m=>{m.records[3].collectedAt='future'},
  m=>{m.records[3].expiresAt='2026-11-20T08:00:00.000Z'},
  m=>{m.records[3].expiresAt='2029-11-20T09:00:00.000Z'},
  m=>{m.records[3].expiresAt='2026-11-20T09:00:00Z'}
 ])rejected((g,m)=>edit(m),'DD_EVIDENCE_TIMESTAMPS_UNREVIEWED');
});
test('DD: metadata remains untrusted even with distinct possible-looking digests',()=>{
 const r=inspect(()=>{},true);
 assert.equal(r.submittedHumanEvidenceMetadataLocallyWellFormedOnly,true);
 assert.equal(r.authorityIntakeComplete,false);
 assert.equal(r.independentCorporateOrProviderEvidenceVerified,false);
 for(const row of r.outstandingActions){
  assert.equal(row.metadataReferencePresent,true);
  assert.equal(row.independentlyAuthenticated,false);
 }
});
test('DD: handoff exposes neither applicant fingerprint, source secret nor username',()=>{
 const m=metadata(),x=assessIndependentOperatorHandoff({
  governance:governance(),metadata:m,now:NOW
 }),raw=JSON.stringify(x);
 assert.equal(raw.includes(m.records[0].recordDigestSha256),false);
 assert.equal(raw.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(raw.includes('GITHUB_READ_TOKEN'),false);
 assert.equal(raw.includes('j9619655391-max'),true); // Repo name, not a credential
 assert.match(x.handoffIntegrityDigestSha256,/^[a-f0-9]{64}$/);
 assert.equal(x.releaseDecision,'HOLD');
});
