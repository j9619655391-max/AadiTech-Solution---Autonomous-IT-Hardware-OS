import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {AZ_PURPOSE,phase1AzAssessReadiness} from '../scripts/lib/phase1AzExternalReadiness.mjs';
import {recordPhase1AzReadiness,inspectPhase1AzReadiness,azReadinessWriteTarget}
 from '../server/externalReadiness/durable';

if(process.env.NODE_ENV!=='test'||process.env.DB_NAME!=='aaditech_ci'||
   process.env.CRM_TEST_DB!=='1')throw Error('1AZ MySQL tests only on disposable CI');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const now=new Date('2026-11-16T17:00:00.000Z'),env=process.env;
const h=n=>n.toString(16).padStart(64,'0');
const newLog=()=>('az-log-'+randomUUID());
function packet(logRef){
 return {schemaVersion:1,purpose:AZ_PURPOSE,revision:1,previousPacketSha256:null,
  witnesses:[
   {witnessRef:'witness-first-001',organizationRef:'witness-organization-001',
    administrativeAuthorityRef:'witness-administrator-001',publicKeySpkiSha256:h(1),
    contractSha256:h(2),publisherPolicySha256:h(3),scope:'CHECKPOINT_WITNESS_ONLY',
    state:'CANDIDATE_UNVERIFIED'},
   {witnessRef:'witness-second-002',organizationRef:'witness-organization-002',
    administrativeAuthorityRef:'witness-administrator-002',publicKeySpkiSha256:h(4),
    contractSha256:h(5),publisherPolicySha256:h(6),scope:'CHECKPOINT_WITNESS_ONLY',
    state:'CANDIDATE_UNVERIFIED'}],
  archive:{logRef,checkpointReceiptSha256:h(11),archiveObjectSha256:h(12),
   storageAccountSha256:h(13),objectVersionIdSha256:h(14),retentionPolicySha256:h(15),
   encryptionKeyIdentifierSha256:h(16),claimedLockMode:'COMPLIANCE',
   legalHoldEvidenceSha256:h(17),createdAt:'2026-11-01T00:00:00.000Z',
   retentionUntil:'2027-05-01T00:00:00.000Z',minimumRetentionDays:90,
   externalStorageState:'NOT_VERIFIED'},
  recovery:{incidentRef:'rehearsal-incident-001',
   sourceCheckpointReceiptSha256:h(11),restoredCheckpointReceiptSha256:h(11),
   sourceManifestSha256:h(20),restoredManifestSha256:h(20),
   archiveObjectSha256:h(12),revocationSnapshotSha256:h(21),
   startedAt:'2026-11-15T12:00:00.000Z',
   completedAt:'2026-11-15T12:05:00.000Z',measuredRpoMs:150,
   rtoObjectiveMs:600000,rpoObjectiveMs:500,
   encryptedRestoreState:'NOT_EXTERNALLY_VERIFIED',outboundHeld:true},
  approvers:[
   {role:'SECURITY',reviewerRef:'security-reviewer-001',
    authorityRef:'security-authority-001',reviewRecordSha256:h(31)},
   {role:'OPERATIONS',reviewerRef:'operations-reviewer-002',
    authorityRef:'operations-authority-002',reviewRecordSha256:h(32)},
   {role:'OWNER',reviewerRef:'owner-reviewer-003',
    authorityRef:'owner-authority-003',reviewRecordSha256:h(33)}],
  releaseDecision:'HOLD'};
}
const record=(logRef,packet)=>recordPhase1AzReadiness(pool,{logRef,packet,env,now});
const inspect=logRef=>inspectPhase1AzReadiness(pool,logRef,env);
test('deny any production target or unapproved staging evidence write',()=>{
 assert.throws(()=>azReadinessWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_prod'} as NodeJS.ProcessEnv));
 assert.throws(()=>azReadinessWriteTarget({NODE_ENV:'production',CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci'} as NodeJS.ProcessEnv));
 assert.throws(()=>azReadinessWriteTarget({DB_NAME:'aaditech_staging_trial',DB_SSL:'false',
  AZ_READINESS_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'} as NodeJS.ProcessEnv));
});
test('revision 1, revision 2, exact retries and readback preserve internal HOLD',async()=>{
 const logRef=newLog(),first=packet(logRef);
 assert.equal((await record(logRef,first)).outcome,'RECORDED_UNTRUSTED');
 const sha=phase1AzAssessReadiness(first,{now}).packetSha256;
 const second={...first,revision:2,previousPacketSha256:sha};
 assert.equal((await record(logRef,second)).outcome,'RECORDED_UNTRUSTED');
 assert.equal((await record(logRef,second)).outcome,'REPLAY');
 const audit=await inspect(logRef);
 assert.equal(audit.latestRevision,2);
 assert.equal(audit.recordedAttempts,2);
 assert.equal(audit.localDigestHistoryConsistent,true);
 assert.equal(audit.governanceState,'HELD_UNVERIFIED');
 assert.equal(audit.immutableExternalArchiveVerified,false);
 assert.equal(audit.productionReleaseAuthorized,false);
});
test('simultaneous conflicting revised digests trigger atomic quarantine and no last-wins',async()=>{
 const logRef=newLog(),first=packet(logRef);
 await record(logRef,first);
 const digest=phase1AzAssessReadiness(first,{now}).packetSha256;
 const left={...first,revision:2,previousPacketSha256:digest,
  witnesses:[{...first.witnesses[0],publisherPolicySha256:h(88)},first.witnesses[1]]};
 const right={...first,revision:2,previousPacketSha256:digest,
  witnesses:[{...first.witnesses[0],publisherPolicySha256:h(89)},first.witnesses[1]]};
 const outcomes=(await Promise.all([record(logRef,left),record(logRef,right)])).map(r=>r.outcome).sort();
 assert.deepEqual(outcomes,['CONFLICT_QUARANTINED','RECORDED_UNTRUSTED']);
 const audit=await inspect(logRef);
 assert.equal(audit.governanceState,'QUARANTINED');
 assert.equal(audit.latestRevision,2);
 assert.equal(audit.recordedAttempts,3);
 const subsequent={...left,revision:3,previousPacketSha256:phase1AzAssessReadiness(left,{now}).packetSha256};
 assert.equal((await record(logRef,subsequent)).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(logRef)).latestRevision,2);
});
test('stale previously accepted packet is recorded as rollback incident and idempotent thereafter',async()=>{
 const logRef=newLog(),first=packet(logRef);
 await record(logRef,first);
 const second={...first,revision:2,previousPacketSha256:phase1AzAssessReadiness(first,{now}).packetSha256};
 await record(logRef,second);
 assert.equal((await record(logRef,first)).outcome,'ROLLBACK_QUARANTINED');
 const report=await inspect(logRef);
 assert.equal(report.governanceState,'QUARANTINED');
 assert.equal(report.recordedAttempts,3);
 assert.equal((await record(logRef,first)).outcome,'DUPLICATE_REJECTED');
 assert.equal((await inspect(logRef)).recordedAttempts,3);
});
test('missing predecessor, revision gaps and inconsistent recovery claim quarantine',async()=>{
 const a=newLog(),p=packet(a);
 await record(a,p);
 const wrong={...p,revision:2,previousPacketSha256:h(999)};
 assert.equal((await record(a,wrong)).outcome,'PREDECESSOR_MISMATCH_QUARANTINED');
 const b=newLog(),gap={...packet(b),revision:5,previousPacketSha256:h(33)};
 assert.equal((await record(b,gap)).outcome,'GAP_QUARANTINED');
 assert.equal((await inspect(b)).latestRevision,0);
 const c=newLog(),claim=packet(c);
 claim.recovery.restoredManifestSha256=h(900);
 const rejected=await record(c,claim);
 assert.equal(rejected.outcome,'INVALID_CLAIM_QUARANTINED');
 assert.equal((await inspect(c)).governanceState,'QUARANTINED');
});
test('raw credentials and mismatched log references fail before write',async()=>{
 const logRef=newLog(),p=packet(logRef);
 await assert.rejects(record(logRef,{...p,accessToken:'NEVER_STORE'}));
 await assert.rejects(record('other-log-001',p),/identity/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS total FROM inv_az_readiness_streams WHERE log_ref=?',[logRef]);
 assert.equal(Number(rows[0].total),0);
});
test('isolated disposable tamper drill detects head corruption on readback',async()=>{
 const logRef=newLog(),p=packet(logRef);
 await record(logRef,p);
 const expected=phase1AzAssessReadiness(p,{now}).packetSha256;
 try{
  await pool.execute(
   'UPDATE inv_az_readiness_streams SET last_packet_sha256=? WHERE log_ref=?',
   [h(999),logRef]);
  const audit=await inspect(logRef);
  assert.equal(audit.localDigestHistoryConsistent,false);
  assert.ok(audit.anomalyCodes.includes('HEAD_MISMATCH'));
 }finally{
  await pool.execute(
   'UPDATE inv_az_readiness_streams SET last_packet_sha256=? WHERE log_ref=?',
   [expected,logRef]);
 }
 assert.equal((await inspect(logRef)).localDigestHistoryConsistent,true);
});
