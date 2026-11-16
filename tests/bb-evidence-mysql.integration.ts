import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {phase1BbSignedBytes,assessPhase1BbEvidenceIntake} from '../scripts/lib/phase1BbEvidenceIntake.mjs';
import {fixture,now,h} from './support/phase1bbFixture.mjs';
import {recordPhase1BbEvidence,inspectPhase1BbEvidence,bbWriteTarget}
 from '../server/evidenceIntake/durable';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('1BB tests require disposable CI MySQL only');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env;
const newLog=()=>('bb-log-'+randomUUID());
const hash=x=>createHash('sha256').update(x).digest('hex');
function reissue(f:any,suffix:string){
 return f.records.map((record:any,i:number)=>{
  const body={...record.body,
   challengeSha256:hash(Buffer.from('BB-RANDOMIZED-'+suffix+'-'+i))};
  return {...record,body,
   signature:{...record.signature,
    signatureBase64:sign(null,phase1BbSignedBytes(body),f.actors[i].privateKey).toString('base64')}};
 });
}
const record=(f:any,records:any[],seq:number,prior:string|null)=>
 recordPhase1BbEvidence(pool,{azPacket:f.azPacket,records,sequence:seq,
  previousBatchSha256:prior,now,env});
const inspect=(logRef:string)=>inspectPhase1BbEvidence(pool,logRef,env);
test('Phase 1BB refuses all production or unapproved staging write targets',()=>{
 assert.throws(()=>bbWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_production'} as NodeJS.ProcessEnv));
 assert.throws(()=>bbWriteTarget({NODE_ENV:'production',CRM_TEST_DB:'1',
   DB_NAME:'aaditech_ci'} as NodeJS.ProcessEnv));
 assert.throws(()=>bbWriteTarget({DB_NAME:'aaditech_staging_test',
  BB_EVIDENCE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_SSL:'false'} as NodeJS.ProcessEnv));
});
test('genesis and successor batches persist six nonce claims each, idempotent replay stays HOLD',async()=>{
 const f=fixture(newLog());
 const first=await record(f,f.records,1,null);
 assert.equal(first.outcome,'ACCEPTED_UNVERIFIED');
 const a=await inspect(f.azPacket.archive.logRef);
 assert.equal(a.acceptedSequence,1);
 assert.equal(a.localDigestHistoryConsistent,true,a.anomalyCodes.join(','));
 const second=reissue(f,'successor-'+f.azPacket.archive.logRef);
 const later=await record(f,second,2,hashFor(f.records,f));
 assert.equal(later.outcome,'ACCEPTED_UNVERIFIED');
 assert.equal((await record(f,second,2,hashFor(f.records,f))).outcome,'REPLAY');
 const report=await inspect(f.azPacket.archive.logRef);
 assert.equal(report.acceptedSequence,2);
 assert.equal(report.recordedAttempts,2);
 assert.equal(report.localDigestHistoryConsistent,true,report.anomalyCodes.join(','));
 assert.equal(report.governanceState,'HELD_UNVERIFIED');
 assert.equal(report.externalPublisherAuthenticated,false);
 assert.equal(report.productionReleaseAuthorized,false);
});
function hashFor(records:any[],f:any){
 return assessPhase1BbEvidenceIntake({azPacket:f.azPacket,records,now}).batchSha256 as string;
}
test('racing conflicting successor batches serialize to accepted + quarantined fork',async()=>{
 const f=fixture(newLog());
 await record(f,f.records,1,null);
 const head=hashFor(f.records,f);
 const left=reissue(f,'left-'+f.azPacket.archive.logRef);
 const right=reissue(f,'right-'+f.azPacket.archive.logRef);
 const outcomes=(await Promise.all([
  record(f,left,2,head),record(f,right,2,head)
 ])).map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['ACCEPTED_UNVERIFIED','FORK_QUARANTINED']);
 const report=await inspect(f.azPacket.archive.logRef);
 assert.equal(report.governanceState,'QUARANTINED');
 assert.equal(report.acceptedSequence,2);
 assert.equal(report.recordedAttempts,3);
 assert.equal(report.localDigestHistoryConsistent,true,report.anomalyCodes.join(','));
 const post=reissue(f,'post-'+f.azPacket.archive.logRef);
 assert.equal((await record(f,post,3,hashFor(left,f))).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(f.azPacket.archive.logRef)).acceptedSequence,2);
});
test('globally replayed challenge from another signed log quarantines second stream',async()=>{
 const a=fixture(newLog()),b=fixture(newLog());
 assert.equal((await record(a,a.records,1,null)).outcome,'ACCEPTED_UNVERIFIED');
 const reused=b.records[0];
 reused.body.challengeSha256=a.records[0].body.challengeSha256;
 reused.signature.signatureBase64=sign(null,phase1BbSignedBytes(reused.body),
   b.actors[0].privateKey).toString('base64');
 const result=await record(b,b.records,1,null);
 assert.equal(result.outcome,'NONCE_REPLAY_QUARANTINED');
 const audit=await inspect(b.azPacket.archive.logRef);
 assert.equal(audit.governanceState,'QUARANTINED');
 assert.equal(audit.acceptedSequence,0);
 assert.equal(audit.localDigestHistoryConsistent,true,audit.anomalyCodes.join(','));
});
test('previously accepted old sequence is a forensic rollback, then repeated replay is idempotent',async()=>{
 const f=fixture(newLog());
 await record(f,f.records,1,null);
 const first=hashFor(f.records,f);
 const second=reissue(f,'second-'+f.azPacket.archive.logRef);
 await record(f,second,2,first);
 assert.equal((await record(f,f.records,1,null)).outcome,'ROLLBACK_QUARANTINED');
 assert.equal((await record(f,f.records,1,null)).outcome,'DUPLICATE_REJECTED');
 const result=await inspect(f.azPacket.archive.logRef);
 assert.equal(result.recordedAttempts,3);
 assert.equal(result.governanceState,'QUARANTINED');
 assert.equal(result.localDigestHistoryConsistent,true);
});
test('missing prior hash and sequence gap are quarantined, never internally promoted',async()=>{
 const f=fixture(newLog());
 await record(f,f.records,1,null);
 const next=reissue(f,'wrongprior-'+f.azPacket.archive.logRef);
 assert.equal((await record(f,next,2,h(55))).outcome,'PREDECESSOR_QUARANTINED');
 const g=fixture(newLog());
 assert.equal((await record(g,g.records,3,h(77))).outcome,'GAP_QUARANTINED');
 assert.equal((await inspect(g.azPacket.archive.logRef)).acceptedSequence,0);
});
test('invalid signed claims never reach the database and no raw private evidence persists',async()=>{
 const f=fixture(newLog());
 f.records[0].signature.signatureBase64=Buffer.alloc(64,99).toString('base64');
 await assert.rejects(record(f,f.records,1,null),/conflicting digest claims/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_bb_evidence_streams WHERE log_ref=?',
  [f.azPacket.archive.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('tampered head is detected in disposable CI then locally repaired',async()=>{
 const f=fixture(newLog());await record(f,f.records,1,null);
 const expected=hashFor(f.records,f);
 try{
  await pool.execute('UPDATE inv_bb_evidence_streams SET last_batch_sha256=? WHERE log_ref=?',
   [h(999),f.azPacket.archive.logRef]);
  const r=await inspect(f.azPacket.archive.logRef);
  assert.equal(r.localDigestHistoryConsistent,false);
  assert.ok(r.anomalyCodes.includes('BATCH_HEAD_HISTORY_DIVERGENCE'));
 }finally{
  await pool.execute('UPDATE inv_bb_evidence_streams SET last_batch_sha256=? WHERE log_ref=?',
   [expected,f.azPacket.archive.logRef]);
 }
 assert.equal((await inspect(f.azPacket.archive.logRef)).localDigestHistoryConsistent,true);
});

test('racing across distinct logs on one signed nonce accepts exactly one global claimant',async()=>{
 const a=fixture(newLog()),b=fixture(newLog());
 b.records[2].body.challengeSha256=a.records[2].body.challengeSha256;
 b.records[2].signature.signatureBase64=sign(null,
  phase1BbSignedBytes(b.records[2].body),b.actors[2].privateKey).toString('base64');
 const results=await Promise.all([
  record(a,a.records,1,null),record(b,b.records,1,null)
 ]);
 assert.deepEqual(results.map(x=>x.outcome).sort(),
  ['ACCEPTED_UNVERIFIED','NONCE_REPLAY_QUARANTINED']);
 const audited=await Promise.all([
  inspect(a.azPacket.archive.logRef),inspect(b.azPacket.archive.logRef)
 ]);
 assert.deepEqual(audited.map(x=>x.acceptedSequence).sort(),[0,1]);
 assert.deepEqual(audited.map(x=>x.governanceState).sort(),
  ['HELD_UNVERIFIED','QUARANTINED']);
 assert.ok(audited.every(x=>x.localDigestHistoryConsistent));
 assert.ok(audited.every(x=>x.productionReleaseAuthorized===false));
});
test('deleted accepted challenge custody is detected on disposable CI readback',async()=>{
 const f=fixture(newLog());
 await record(f,f.records,1,null);
 const logRef=f.azPacket.archive.logRef;
 const challenge=f.records[0].body.challengeSha256;
 const batch=hashFor(f.records,f);
 try{
  await pool.execute('DELETE FROM inv_bb_evidence_nonce_claims WHERE challenge_sha256=?',
   [challenge]);
  const audit=await inspect(logRef);
  assert.equal(audit.localDigestHistoryConsistent,false);
  assert.ok(audit.anomalyCodes.includes('MISSING_OR_EXTRA_ACCEPTED_CHALLENGES'));
 }finally{
  await pool.execute(
   'INSERT INTO inv_bb_evidence_nonce_claims(challenge_sha256,log_ref,batch_sha256) VALUES(?,?,?)',
   [challenge,logRef,batch]);
 }
 assert.equal((await inspect(logRef)).localDigestHistoryConsistent,true);
});

test('repeated independent-log nonce collisions serialize without transient deadlocks',async()=>{
 for(let iteration=0;iteration<6;iteration++){
  const a=fixture(newLog()),b=fixture(newLog());
  const reused=b.records[iteration%6];
  reused.body.challengeSha256=a.records[iteration%6].body.challengeSha256;
  reused.signature.signatureBase64=sign(null,
   phase1BbSignedBytes(reused.body),b.actors[iteration%6].privateKey).toString('base64');
  const both=await Promise.all([
   record(a,a.records,1,null),record(b,b.records,1,null)
  ]);
  assert.deepEqual(both.map(x=>x.outcome).sort(),
   ['ACCEPTED_UNVERIFIED','NONCE_REPLAY_QUARANTINED']);
  const audits=await Promise.all([
   inspect(a.azPacket.archive.logRef),inspect(b.azPacket.archive.logRef)
  ]);
  assert.ok(audits.every(x=>x.localDigestHistoryConsistent));
  assert.deepEqual(audits.map(x=>x.acceptedSequence).sort(),[0,1]);
  assert.ok(audits.every(x=>x.productionReleaseAuthorized===false));
 }
});
