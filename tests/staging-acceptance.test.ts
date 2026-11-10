import test from 'node:test';
import assert from 'node:assert/strict';
import {assessStagingAcceptance,type StagingAcceptancePackage} from '../scripts/lib/stagingAcceptance';
import type {RecoveryReviewPackage} from '../scripts/lib/recoveryReadiness';

const now=new Date('2026-11-10T12:00:00Z');
const recovery:RecoveryReviewPackage={
 changeTicket:'CHG-STAGING-REVIEW',evidenceLocation:'private-vault-recovery-evidence',
 operatorId:'operator-001',independentWitnessId:'independent-restore-003',
 witnessApprovalReference:'WITNESS-REVIEW-003',
 isolatedNetworkVerified:true,outboundDispatchDisabled:true,stagingTlsVerified:true,
 objectives:{maxRtoMinutes:60,maxRpoMinutes:5},
 evidence:{
  targetDatabase:'aaditech_staging_rehearsal',sourceSnapshotSha256:'a'.repeat(64),
  restoredSnapshotSha256:'a'.repeat(64),backupCompletedAt:'2026-11-10T09:00:00Z',
  restoreStartedAt:'2026-11-10T09:10:00Z',restoreCompletedAt:'2026-11-10T09:40:00Z',
  sourceAsOf:'2026-11-10T09:00:00Z',recoveryPointAsOf:'2026-11-10T08:58:00Z',
  tableCountsMatch:true,sampledRecordHashesMatch:true,mfaKeyRecoveryVerified:true,
  independentReviewer:'independent-restore-003',reviewerSignoffAt:'2026-11-10T09:55:00Z'
 }
};
const example:StagingAcceptancePackage={
 changeTicket:'CHG-STAGING-REVIEW',stagingOrigin:'https://staging.aaditechs.in',
 operatorId:'operator-001',independentSecurityReviewerId:'security-reviewer-002',
 independentInfrastructureReviewerId:'infra-reviewer-004',
 securityApprovalReference:'SEC-APPROVAL-REFERENCE',
 infrastructureApprovalReference:'INFRA-APPROVAL-REFERENCE',
 reviewerSignedAt:'2026-11-10T11:30:00Z',
 networkIsolationEvidenceRef:'private-network-isolation-reference',
 proxyHeaderRewriteEvidenceRef:'private-proxy-headers-reference',
 mysqlCaEvidenceRef:'private-db-ca-trust-reference',
 realHttpsBrowserMfaEvidenceRef:'private-browser-mfa-reference',
 outboundDispatchHeldEvidenceRef:'private-outbox-hold-reference',
 probe:{
  targetOrigin:'https://staging.aaditechs.in',changeTicket:'CHG-STAGING-REVIEW',
  observedAt:'2026-11-10T11:00:00Z',observedChecksPassed:true,failures:[],
  proxyIpOverwriteIndependentlyVerified:true,
  directListenerIsolationIndependentlyVerified:true,
  databaseTlsIndependentlyVerified:true,
  productionReleaseAuthorized:false
 },
 actualRestoreReview:recovery
};
test('even an entirely complete synthetic acceptance file cannot approve production',()=>{
 const result=assessStagingAcceptance(example,now);
 assert.equal(result.submittedEvidenceComplete,true);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.actualRestoreIndependentlyVerified,false);
 assert.equal(result.independentIdentityAndSignaturesVerified,false);
 assert.equal(result.restoreRtoMinutes,30);
});
test('stale probe, missing network attestations, inconsistent tickets or reviewer collusion block completeness',()=>{
 const invalid=assessStagingAcceptance({...example,
  independentSecurityReviewerId:example.operatorId,
  probe:{...example.probe,observedAt:'2026-11-09T10:00:00Z',
   proxyIpOverwriteIndependentlyVerified:false},
  actualRestoreReview:{...recovery,changeTicket:'CHG-OTHER-RECOVERY'}
 },now);
 assert.equal(invalid.submittedEvidenceComplete,false);
 assert.ok(invalid.issues.length>=4);
 assert.equal(invalid.productionReleaseAuthorized,false);
});
test('probe read-only evidence is intentionally insufficient for external infrastructure attestations',()=>{
 const result=assessStagingAcceptance({...example,probe:{...example.probe,
  proxyIpOverwriteIndependentlyVerified:false,
  directListenerIsolationIndependentlyVerified:false,
  databaseTlsIndependentlyVerified:false
 }},now);
 assert.equal(result.submittedEvidenceComplete,false);
 assert.equal(result.providerInfrastructureVerified,false);
});
test('missing, invalid or future-dated inputs fail closed without reaching production',()=>{
 assert.equal(assessStagingAcceptance({...example,stagingOrigin:'https://aaditechs.in'},now).submittedEvidenceComplete,false);
 assert.equal(assessStagingAcceptance({...example,probe:{...example.probe,observedAt:'2027-11-10T12:00:00Z'}},now).submittedEvidenceComplete,false);
 assert.equal(assessStagingAcceptance({...example,securityApprovalReference:''},now).submittedEvidenceComplete,false);
});
