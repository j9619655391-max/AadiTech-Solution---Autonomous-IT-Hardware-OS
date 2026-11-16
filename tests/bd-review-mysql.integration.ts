import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {bdFixture,h} from './support/phase1bdFixture.mjs';
import {bcFixture} from './support/phase1bcFixture.mjs';
import {assessPhase1BdEvidenceReview,phase1BdStorageBytes}
 from '../scripts/lib/phase1BdEvidenceReview.mjs';
import {recordPhase1AzReadiness} from '../server/externalReadiness/durable';
import {recordPhase1BbEvidence} from '../server/evidenceIntake/durable';
import {recordPhase1BcWitnessCustody} from '../server/witnessCustody/durable';
import {bdWriteTarget,recordPhase1BdEvidenceReview,inspectPhase1BdEvidenceReview}
 from '../server/evidenceReview/durable';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BD MySQL tests require disposable CI');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,log=()=>('bd-log-'+randomUUID());
const review=(f:any,revision:number,previousReviewSha256:string|null)=>
 recordPhase1BdEvidenceReview(pool,{...f,revision,previousReviewSha256,env});
const inspect=(logRef:string)=>inspectPhase1BdEvidenceReview(pool,logRef,env);
async function prepare(f:any,{skipBC=false}={}){
 const logRef=f.azPacket.archive.logRef;
 assert.equal((await recordPhase1AzReadiness(pool,{
  logRef,packet:f.azPacket,now:f.now,env})).outcome,'RECORDED_UNTRUSTED');
 assert.equal((await recordPhase1BbEvidence(pool,{
  azPacket:f.azPacket,records:f.bbRecords,sequence:1,
  previousBatchSha256:null,now:f.now,env})).outcome,'ACCEPTED_UNVERIFIED');
 if(!skipBC){
  const bc=bcFixture(logRef,{azPacket:f.azPacket,actors:f.actors,
   records:f.bbRecords,now:f.now});
  const proof=bc.make(2,3);
  assert.equal((await recordPhase1BcWitnessCustody(pool,{
   azPacket:f.azPacket,observations:proof.observations,now:f.now,env
  })).outcome,'GENESIS_UNVERIFIED');
 }
}
function amended(f:any,digest:string){
 const body={...f.storageReceipt.body,providerCreateReceiptSha256:digest};
 const signature={...f.storageReceipt.signature,
  signatureBase64:sign(null,phase1BdStorageBytes(body),
   f.provider.privateKey).toString('base64')};
 return {...f,storageReceipt:{body,pin:{...f.storageReceipt.pin},signature}};
}
test('Phase 1BD database writes reject production and unapproved staging',()=>{
 assert.throws(()=>bdWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_production'} as NodeJS.ProcessEnv));
 assert.throws(()=>bdWriteTarget({NODE_ENV:'production',CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci'} as NodeJS.ProcessEnv));
 assert.throws(()=>bdWriteTarget({DB_NAME:'aaditech_staging_test',
  BD_EVIDENCE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_SSL:'false'} as NodeJS.ProcessEnv));
});
test('Phase 1BD requires AZ, BB and BC independently held predecessor digests before review',async()=>{
 const f=bdFixture(log());
 await assert.rejects(review(f,1,null),/missing or quarantined AZ\/BB\/BC predecessor/);
 await prepare(f,{skipBC:true});
 await assert.rejects(review(f,1,null),/missing or quarantined AZ\/BB\/BC predecessor/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_bd_review_streams WHERE log_ref=?',
  [f.azPacket.archive.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('signed candidate review genesis and successor, exact replay, full readback remain held',async()=>{
 const f=bdFixture(log());await prepare(f);
 const first=await review(f,1,null);
 assert.equal(first.outcome,'RECORDED_UNVERIFIED');
 assert.equal(first.productionReleaseAuthorized,false);
 const prior=assessPhase1BdEvidenceReview(f).reviewDigestSha256 as string;
 const second=amended(f,h(910));
 assert.equal((await review(second,2,prior)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await review(second,2,prior)).outcome,'REPLAY');
 const r=await inspect(f.azPacket.archive.logRef);
 assert.equal(r.latestRevision,2);
 assert.equal(r.recordedAttempts,2);
 assert.equal(r.localReviewDigestHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.governanceState,'HELD_UNVERIFIED');
 assert.equal(r.externallyAuthenticatedAuthority,false);
 assert.equal(r.realEncryptedDRVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('two racing valid revisions with conflicting provider receipts quarantine one fork',async()=>{
 const f=bdFixture(log());await prepare(f);
 await review(f,1,null);
 const prior=assessPhase1BdEvidenceReview(f).reviewDigestSha256 as string;
 const a=amended(f,h(921)),b=amended(f,h(922));
 const outcomes=(await Promise.all([review(a,2,prior),review(b,2,prior)]))
  .map(r=>r.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const status=await inspect(f.azPacket.archive.logRef);
 assert.equal(status.governanceState,'QUARANTINED');
 assert.equal(status.latestRevision,2);
 assert.equal(status.recordedAttempts,3);
 assert.equal(status.localReviewDigestHistoryConsistent,true);
 const post=amended(f,h(923));
 assert.equal((await review(post,3,prior)).outcome,'POST_INCIDENT_QUARANTINED');
});
test('stale earlier review is recorded once as rollback incident, then idempotently blocked',async()=>{
 const f=bdFixture(log());await prepare(f);
 await review(f,1,null);
 const first=assessPhase1BdEvidenceReview(f).reviewDigestSha256 as string;
 const revised=amended(f,h(930));
 await review(revised,2,first);
 assert.equal((await review(f,1,null)).outcome,'ROLLBACK_QUARANTINED');
 assert.equal((await review(f,1,null)).outcome,'DUPLICATE_REJECTED');
 const result=await inspect(f.azPacket.archive.logRef);
 assert.equal(result.latestRevision,2);
 assert.equal(result.recordedAttempts,3);
 assert.equal(result.governanceState,'QUARANTINED');
});
test('missing prior digest and revision gap trigger sticky review quarantine',async()=>{
 const f=bdFixture(log());await prepare(f);
 await review(f,1,null);
 const next=amended(f,h(941));
 assert.equal((await review(next,2,h(999))).outcome,
  'PREDECESSOR_MISMATCH_QUARANTINED');
 const other=bdFixture(log());await prepare(other);
 assert.equal((await review(other,5,h(111))).outcome,'GAP_QUARANTINED');
 assert.equal((await inspect(other.azPacket.archive.logRef)).latestRevision,0);
});
test('forged signed reviewer or provider cannot create any persisted review',async()=>{
 const f=bdFixture(log());await prepare(f);
 f.recoveryAttestations[0].signature.signatureBase64=Buffer.alloc(64,5).toString('base64');
 await assert.rejects(review(f,1,null),/inconsistent candidate evidence/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_bd_review_streams WHERE log_ref=?',
  [f.azPacket.archive.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('isolated MySQL head corruption is detected, not treated as independent authority',async()=>{
 const f=bdFixture(log());await prepare(f);
 await review(f,1,null);
 const first=assessPhase1BdEvidenceReview(f).reviewDigestSha256;
 try{
  await pool.execute(
   'UPDATE inv_bd_review_streams SET last_review_sha256=? WHERE log_ref=?',
   [h(999),f.azPacket.archive.logRef]);
  const audit=await inspect(f.azPacket.archive.logRef);
  assert.equal(audit.localReviewDigestHistoryConsistent,false);
  assert.ok(audit.anomalyCodes.includes('REVIEW_HEAD_MISMATCH'));
  assert.equal(audit.productionReleaseAuthorized,false);
 }finally{
  await pool.execute(
   'UPDATE inv_bd_review_streams SET last_review_sha256=? WHERE log_ref=?',
   [first,f.azPacket.archive.logRef]);
 }
 assert.equal((await inspect(f.azPacket.archive.logRef)).localReviewDigestHistoryConsistent,true);
});
