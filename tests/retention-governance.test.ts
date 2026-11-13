import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRetentionPolicyEvidence,type RetentionPolicyEvidence} from '../scripts/lib/retentionGovernance';
const sample:RetentionPolicyEvidence={
 changeTicket:'CHG-2026-01023',dataController:'Owner decision reference',
 privacyReviewer:'Independent privacy reviewer',
 securityReviewer:'Independent security reviewer',
 approvedAt:'2026-11-10T01:00:00Z',
 retentionScheduleReference:'Private retention policy reference',
 incidentHoldProcedure:'Incident hold and legal freeze procedure',
 backupRestorationReference:'Independent backup rehearsal record',
 applicableJurisdiction:'Indian data protection applicability review'
};
test('even complete self-reported policy fields never authorize production deletions',()=>{
 const result=assessRetentionPolicyEvidence(sample);
 assert.equal(result.evidenceComplete,true);
 assert.equal(result.approvalIndependentlyVerified,false);
 assert.equal(result.authorizesDataDeletion,false);
 assert.equal(result.productionRetentionEnabled,false);
});
test('missing or non-independent governance attestations fail review',()=>{
 const result=assessRetentionPolicyEvidence({...sample,
  privacyReviewer:sample.dataController,securityReviewer:'',approvedAt:'not approved'});
 assert.equal(result.evidenceComplete,false);
 assert.ok(result.issues.length>=3);
});
