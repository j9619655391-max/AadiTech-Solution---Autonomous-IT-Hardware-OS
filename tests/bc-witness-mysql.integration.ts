import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {recordPhase1AzReadiness} from '../server/externalReadiness/durable';
import {recordPhase1BcWitnessCustody,inspectPhase1BcWitnessCustody,bcWitnessWriteTarget}
 from '../server/witnessCustody/durable';
import {phase1AzAssessReadiness} from '../scripts/lib/phase1AzExternalReadiness.mjs';
import {bcFixture} from './support/phase1bcFixture.mjs';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BC integration only runs in disposable CI MySQL');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,now=new Date('2026-11-16T18:00:00.000Z');
const newLog=()=>('bc-log-'+randomUUID());
const hash=n=>n.toString(16).padStart(64,'0');
async function preregister(f:any){
 const logRef=f.azPacket.archive.logRef;
 const r=await recordPhase1AzReadiness(pool,{logRef,packet:f.azPacket,now,env});
 assert.equal(r.outcome,'RECORDED_UNTRUSTED');
}
const write=(f:any,proof:any)=>recordPhase1BcWitnessCustody(pool,{
 azPacket:f.azPacket,observations:proof.observations,now,env});
const inspect=logRef=>inspectPhase1BcWitnessCustody(pool,logRef,env);

test('no witness ledger write on production/unapproved/untls staging',()=>{
 assert.throws(()=>bcWitnessWriteTarget({NODE_ENV:'production',
  DB_NAME:'aaditech_production'} as NodeJS.ProcessEnv));
 assert.throws(()=>bcWitnessWriteTarget({NODE_ENV:'production',
  DB_NAME:'aaditech_ci',CRM_TEST_DB:'1'} as NodeJS.ProcessEnv));
 assert.throws(()=>bcWitnessWriteTarget({DB_NAME:'aaditech_staging_test',
  BC_WITNESS_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_SSL:'false'} as NodeJS.ProcessEnv));
});
test('candidate Merkle genesis, monotonic extension and exact retry remain unverified HOLD',async()=>{
 const f=bcFixture(newLog());await preregister(f);
 const first=f.make(2,3);
 assert.equal((await write(f,first)).outcome,'GENESIS_UNVERIFIED');
 const next=f.make(3,5);
 assert.equal((await write(f,next)).outcome,'EXTENSION_UNVERIFIED');
 assert.equal((await write(f,next)).outcome,'REPLAY');
 const r=await inspect(f.azPacket.archive.logRef);
 assert.equal(r.latestCandidateTreeSize,5);
 assert.equal(r.observations,2);
 assert.equal(r.governanceState,'HELD_UNVERIFIED');
 assert.equal(r.localDigestHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.independentlyAuthenticatedSource,false);
 assert.equal(r.immutableWormVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('two concurrent independently signed split views serialize to one accepted and one quarantined fork',async()=>{
 const f=bcFixture(newLog());await preregister(f);
 await write(f,f.make(2,3));
 const first=f.make(3,5);
 const branch=[...f.leaves];branch[4]=Buffer.from('independent conflict signed branch');
 const second=f.make(3,5,branch);
 const outcomes=(await Promise.all([write(f,first),write(f,second)])).map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['EXTENSION_UNVERIFIED','FORK_QUARANTINED']);
 const r=await inspect(f.azPacket.archive.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.latestCandidateTreeSize,5);
 assert.equal(r.observations,3);
 assert.equal(r.localDigestHistoryConsistent,true,r.anomalyCodes.join(','));
 const later=f.make(5,6);
 assert.equal((await write(f,later)).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(f.azPacket.archive.logRef)).latestCandidateTreeSize,5);
});
test('stale accepted ancestor becomes recorded rollback and repeat incident is idempotent',async()=>{
 const f=bcFixture(newLog());await preregister(f);
 const old=f.make(2,3);
 await write(f,old);
 await write(f,f.make(3,6));
 assert.equal((await write(f,old)).outcome,'ROLLBACK_QUARANTINED');
 assert.equal((await write(f,old)).outcome,'DUPLICATE_REJECTED');
 const r=await inspect(f.azPacket.archive.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.observations,3);
 assert.equal(r.localDigestHistoryConsistent,true);
});
test('non-contiguous historical tree chain quarantines even with valid signatures',async()=>{
 const f=bcFixture(newLog());await preregister(f);
 await write(f,f.make(2,3));
 assert.equal((await write(f,f.make(2,5))).outcome,
  'HISTORICAL_HEAD_MISMATCH_QUARANTINED');
 assert.equal((await inspect(f.azPacket.archive.logRef)).governanceState,'QUARANTINED');
});
test('a new self-claimed witness identity must never silently replace the local pinned key set',async()=>{
 const logRef=newLog(),original=bcFixture(logRef);
 await preregister(original);
 await write(original,original.make(2,3));
 const replacement=bcFixture(logRef);
 const first=phase1AzAssessReadiness(original.azPacket,{now});
 replacement.azPacket.revision=2;
 replacement.azPacket.previousPacketSha256=first.packetSha256;
 const nextAz=await recordPhase1AzReadiness(pool,{
  logRef,packet:replacement.azPacket,env,now});
 assert.equal(nextAz.outcome,'RECORDED_UNTRUSTED');
 const result=await write(replacement,replacement.make(3,5));
 assert.equal(result.outcome,'WITNESS_PINSET_CHANGE_QUARANTINED');
 const audit=await inspect(logRef);
 assert.equal(audit.localDigestHistoryConsistent,true);
 assert.equal(audit.governanceState,'QUARANTINED');
 assert.equal(audit.latestCandidateTreeSize,3);
});
test('missing locally recorded AZ predecessor or forged signed proof cannot persist',async()=>{
 const logRef=newLog(),f=bcFixture(logRef);
 await assert.rejects(write(f,f.make(2,3)),/predecessor history/);
 await preregister(f);
 const forged=f.make(2,3);
 forged.observations[0].current.signature.signatureBase64=
  Buffer.alloc(64,7).toString('base64');
 await assert.rejects(write(f,forged),/invalid signed witness custody/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS total FROM inv_bc_witness_streams WHERE log_ref=?',[logRef]);
 assert.equal(Number(rows[0].total),0);
});
test('isolated database head tamper is detected and reversible only in disposable CI',async()=>{
 const f=bcFixture(newLog());await preregister(f);
 const v=f.make(2,3);
 await write(f,v);
 const logRef=f.azPacket.archive.logRef;
 const original=(await pool.execute<any[]>(
  'SELECT last_root_sha256 AS root FROM inv_bc_witness_streams WHERE log_ref=?',[logRef]))[0][0].root;
 try{
  await pool.execute('UPDATE inv_bc_witness_streams SET last_root_sha256=? WHERE log_ref=?',
   [hash(999),logRef]);
  const audit=await inspect(logRef);
  assert.equal(audit.localDigestHistoryConsistent,false);
  assert.ok(audit.anomalyCodes.includes('WITNESS_HEAD_HISTORY_DIVERGENCE'));
 }finally{
  await pool.execute('UPDATE inv_bc_witness_streams SET last_root_sha256=? WHERE log_ref=?',
   [original,logRef]);
 }
 assert.equal((await inspect(logRef)).localDigestHistoryConsistent,true);
});
