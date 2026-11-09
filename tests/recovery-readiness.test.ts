import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRecoveryReviewPackage,type RecoveryReviewPackage} from '../scripts/lib/recoveryReadiness';

const example:RecoveryReviewPackage={
 changeTicket:'CHG-STAGING-2026-123',
 evidenceLocation:'private-change-record-2026-123',
 operatorId:'staging-operator-01',
 independentWitnessId:'security-reviewer-02',
 witnessApprovalReference:'SEC-APPROVAL-REFERENCE',
 isolatedNetworkVerified:true,
 outboundDispatchDisabled:true,
 stagingTlsVerified:true,
 objectives:{maxRtoMinutes:60,maxRpoMinutes:5},
 evidence:{
  targetDatabase:'aaditech_staging_rehearsal',
  sourceSnapshotSha256:'a'.repeat(64),restoredSnapshotSha256:'a'.repeat(64),
  backupCompletedAt:'2026-11-09T09:00:00Z',
  restoreStartedAt:'2026-11-09T09:10:00Z',
  restoreCompletedAt:'2026-11-09T09:40:00Z',
  sourceAsOf:'2026-11-09T09:00:00Z',
  recoveryPointAsOf:'2026-11-09T08:58:00Z',
  tableCountsMatch:true,sampledRecordHashesMatch:true,
  mfaKeyRecoveryVerified:true,
  independentReviewer:'security-reviewer-02',
  reviewerSignoffAt:'2026-11-09T10:00:00Z'
 }
};
test('synthetic complete recovery package still cannot independently certify real restore',()=>{
 const report=assessRecoveryReviewPackage(example);
 assert.equal(report.reportedEvidenceComplete,true);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.externallyWitnessedRestoreVerified,false);
 assert.equal(report.measuredRtoMinutes,30);
});
test('recovery package denies missing independent witness, TLS, dispatch isolation or impossible evidence',()=>{
 const report=assessRecoveryReviewPackage({...example,
  independentWitnessId:example.operatorId,
  outboundDispatchDisabled:false,
  stagingTlsVerified:false,
  evidence:{...example.evidence,tableCountsMatch:false}});
 assert.equal(report.reportedEvidenceComplete,false);
 assert.ok(report.issues.length>=4);
 assert.equal(report.productionReleaseAuthorized,false);
});
