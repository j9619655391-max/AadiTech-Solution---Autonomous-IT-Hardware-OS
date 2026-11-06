import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateRestoreEvidence,type RestoreEvidence} from '../scripts/lib/restoreEvidence';
const sample:RestoreEvidence={
 targetDatabase:'aaditech_staging_rehearsal',
 sourceSnapshotSha256:'a'.repeat(64),restoredSnapshotSha256:'a'.repeat(64),
 backupCompletedAt:'2026-11-06T09:00:00Z',
 restoreStartedAt:'2026-11-06T09:10:00Z',
 restoreCompletedAt:'2026-11-06T09:40:00Z',
 sourceAsOf:'2026-11-06T09:00:00Z',
 recoveryPointAsOf:'2026-11-06T08:58:00Z',
 tableCountsMatch:true,sampledRecordHashesMatch:true,
 mfaKeyRecoveryVerified:true,independentReviewer:'staging-security-reviewer',
 reviewerSignoffAt:'2026-11-06T10:00:00Z'
};
test('restore assessment measures RTO/RPO but does not claim a restore happened',()=>{
 const r=evaluateRestoreEvidence(sample,{maxRtoMinutes:60,maxRpoMinutes:5});
 assert.equal(r.accepted,true);
 assert.equal(r.rtoMinutes,30);
 assert.equal(r.rpoMinutes,2);
});
test('rehearsal evidence fails closed for unverified checks, invalid target or thresholds',()=>{
 assert.equal(evaluateRestoreEvidence({...sample,tableCountsMatch:false},{maxRtoMinutes:60,maxRpoMinutes:5}).accepted,false);
 assert.equal(evaluateRestoreEvidence({...sample,targetDatabase:'aaditech_production'},{maxRtoMinutes:60,maxRpoMinutes:5}).accepted,false);
 assert.equal(evaluateRestoreEvidence({...sample,restoreCompletedAt:'2026-11-06T12:40:00Z'},{maxRtoMinutes:60,maxRpoMinutes:5}).accepted,false);
 assert.equal(evaluateRestoreEvidence({...sample,recoveryPointAsOf:'2026-11-06T08:00:00Z'},{maxRtoMinutes:60,maxRpoMinutes:5}).accepted,false);
 assert.equal(evaluateRestoreEvidence({...sample,reviewerSignoffAt:'2026-11-06T09:00:00Z'},{maxRtoMinutes:60,maxRpoMinutes:5}).accepted,false);
 assert.throws(()=>evaluateRestoreEvidence(sample,{maxRtoMinutes:0,maxRpoMinutes:5}));
});
