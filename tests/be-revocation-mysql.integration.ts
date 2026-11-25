import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {beFixture} from './support/phase1beFixture.mjs';
import {bcFixture} from './support/phase1bcFixture.mjs';
import {recordPhase1AzReadiness} from '../server/externalReadiness/durable';
import {recordPhase1BbEvidence} from '../server/evidenceIntake/durable';
import {recordPhase1BcWitnessCustody} from '../server/witnessCustody/durable';
import {recordPhase1BdEvidenceReview} from '../server/evidenceReview/durable';
import {recordPhase1BeRevocationFreeze,inspectPhase1BeRevocationFreeze,beFreezeWriteTarget}
 from '../server/revocationFreeze/durable';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BE tests only target disposable MySQL CI');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,log=()=>('be-log-'+randomUUID()),h=n=>n.toString(16).padStart(64,'0');
const record=(f:any)=>recordPhase1BeRevocationFreeze(pool,{...f,env});
const inspect=(logRef:string)=>inspectPhase1BeRevocationFreeze(pool,logRef,env);
async function prepare(f:any,{skipBD=false}={}){
 const dossier=f.bdEvidence,logRef=dossier.azPacket.archive.logRef;
 assert.equal((await recordPhase1AzReadiness(pool,{
  logRef,packet:dossier.azPacket,now:f.now,env})).outcome,'RECORDED_UNTRUSTED');
 assert.equal((await recordPhase1BbEvidence(pool,{
  azPacket:dossier.azPacket,records:dossier.bbRecords,sequence:1,
  previousBatchSha256:null,now:f.now,env})).outcome,'ACCEPTED_UNVERIFIED');
 const source={azPacket:dossier.azPacket,actors:dossier.actors,
  records:dossier.bbRecords,now:f.now};
 const bc=bcFixture(logRef,source);
 assert.equal((await recordPhase1BcWitnessCustody(pool,{
  azPacket:dossier.azPacket,observations:bc.make(2,3).observations,
  now:f.now,env})).outcome,'GENESIS_UNVERIFIED');
 if(!skipBD)
  assert.equal((await recordPhase1BdEvidenceReview(pool,{
   ...dossier,revision:1,previousReviewSha256:null,env
  })).outcome,'RECORDED_UNVERIFIED');
 return bc;
}
test('1BE freeze refuses production, unapproved, or non-TLS staging',()=>{
 assert.throws(()=>beFreezeWriteTarget({NODE_ENV:'production',
  CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'} as NodeJS.ProcessEnv));
 assert.throws(()=>beFreezeWriteTarget({NODE_ENV:'production',
  DB_NAME:'aaditech_production'} as NodeJS.ProcessEnv));
 assert.throws(()=>beFreezeWriteTarget({NODE_ENV:'test',
  BE_FREEZE_WRITE_APPROVED:'YES',DB_NAME:'aaditech_staging_private',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'false'} as NodeJS.ProcessEnv));
});
test('verified candidate AZ BB BC cannot assert a freeze without held BD reviewer lineage',async()=>{
 const f=beFixture(log());await prepare(f,{skipBD:true});
 await assert.rejects(record(f),/missing\/changed or quarantined AZ BB BC BD predecessor/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_be_freeze_streams WHERE log_ref=?',
  [f.body.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('signed suspected-key freeze is sticky, idempotent and always internal HOLD',async()=>{
 const f=beFixture(log());await prepare(f);
 const first=await record(f);
 assert.equal(first.outcome,'FROZEN_UNVERIFIED');
 assert.equal(first.productionReleaseAuthorized,false);
 assert.equal((await record(f)).outcome,'REPLAY');
 const r=await inspect(f.body.logRef);
 assert.equal(r.state,'FROZEN_UNVERIFIED');
 assert.equal(r.attempts,1);
 assert.equal(r.revokedWitnessRef,f.body.revokedWitnessRef);
 assert.equal(r.locallyConsistentHistory,true,r.anomalyCodes.join(','));
 assert.equal(r.sourceOfTruthAuthenticated,false);
 assert.equal(r.revocationExternallyPublished,false);
 assert.equal(r.cloudObjectLockVerified,false);
 assert.equal(r.encryptedDRWitnessed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('emergency freeze blocks upstream AZ packet and BB nonce intake, including replay, without mutating heads',async()=>{
 const f=beFixture(log());await prepare(f);
 await record(f);
 const dossier=f.bdEvidence,logRef=dossier.azPacket.archive.logRef;
 await assert.rejects(recordPhase1AzReadiness(pool,{
  logRef,packet:dossier.azPacket,now:f.now,env
 }),/Phase 1BE emergency witness revocation freeze blocks AZ packet writes/);
 await assert.rejects(recordPhase1BbEvidence(pool,{
  azPacket:dossier.azPacket,records:dossier.bbRecords,sequence:1,
  previousBatchSha256:null,now:f.now,env
 }),/Phase 1BE emergency witness revocation freeze blocks BB batch writes/);
 const [az]=await pool.execute<any[]>(
  'SELECT last_revision,governance_state FROM inv_az_readiness_streams WHERE log_ref=?',[logRef]);
 const [bb]=await pool.execute<any[]>(
  'SELECT last_sequence,governance_state FROM inv_bb_evidence_streams WHERE log_ref=?',[logRef]);
 assert.equal(Number(az[0].last_revision),1);
 assert.equal(az[0].governance_state,'HELD_UNVERIFIED');
 assert.equal(Number(bb[0].last_sequence),1);
 assert.equal(bb[0].governance_state,'HELD_UNVERIFIED');
 assert.equal((await inspect(logRef)).state,'FROZEN_UNVERIFIED');
 assert.equal((await inspect(logRef)).locallyConsistentHistory,true);
});
test('frozen log blocks further witness head writes AND BD review replay/new revision',async()=>{
 const f=beFixture(log()),bc=await prepare(f);
 await record(f);
 const proof=bc.make(3,5);
 await assert.rejects(recordPhase1BcWitnessCustody(pool,{
  azPacket:f.bdEvidence.azPacket,observations:proof.observations,now:f.now,env
 }),/Phase 1BE emergency witness revocation freeze blocks BC head writes/);
 await assert.rejects(recordPhase1BdEvidenceReview(pool,{
  ...f.bdEvidence,revision:1,previousReviewSha256:null,env
 }),/Phase 1BE emergency witness revocation freeze blocks BD reviews/);
 const later=await recordPhase1BdEvidenceReview(pool,{
  ...f.bdEvidence,revision:2,previousReviewSha256:f.body.bdReviewSha256,env
 }).catch(e=>e);
 assert.match(String(later),/Phase 1BE emergency witness revocation freeze blocks BD reviews/);
 assert.equal((await inspect(f.body.logRef)).locallyConsistentHistory,true);
});
test('two concurrent individually valid revocation incidents cannot replace same frozen head',async()=>{
 const f=beFixture(log());await prepare(f);
 const competing=beFixture(f.body.logRef);
 // Both use different synthetic signing keys, and each separate f carries
 // a different BD predecessor, so a successful replay should be rejected
 // before accepting the forged alternative. Use the SAME dossier instead.
 const second={...f,body:{...f.body,revocationNoticeSha256:h(922)}};
 f.body.revocationNoticeSha256=h(921);f.resign();
 second.survivingWitnessSignature=null;
 second.governanceSignatures=[];
 // Generate signatures for the competing copy against the shared actor keys.
 const {phase1BeFreezeSigningBytes}=await import('../scripts/lib/phase1BeRevocationFreeze.mjs');
 const {sign}=await import('node:crypto');
 const bytes=phase1BeFreezeSigningBytes(second.body),actors=f.bdEvidence.actors;
 const wrap=actor=>({pin:{...actor.pin},signature:{
  sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
  signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')
 }});
 second.survivingWitnessSignature=wrap(actors[1]);
 second.governanceSignatures=actors.slice(3).map(wrap);
 const outcomes=(await Promise.all([record(f),record(second)]))
  .map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['CONFLICT_QUARANTINED','FROZEN_UNVERIFIED']);
 const a=await inspect(f.body.logRef);
 assert.equal(a.state,'QUARANTINED');
 assert.equal(a.attempts,2);
 assert.equal(a.locallyConsistentHistory,true,a.anomalyCodes.join(','));
 assert.equal((await record(f)).outcome,'DUPLICATE_REJECTED');
 assert.equal((await record(second)).outcome,'DUPLICATE_REJECTED');
});
test('after a quarantined conflict, any additional valid incident remains quarantined',async()=>{
 const f=beFixture(log());await prepare(f);
 await record(f);
 const other={...f,body:{...f.body,revocationNoticeSha256:h(993)}};
 const {phase1BeFreezeSigningBytes}=await import('../scripts/lib/phase1BeRevocationFreeze.mjs');
 const {sign}=await import('node:crypto');
 const resign=x=>{
  const bytes=phase1BeFreezeSigningBytes(x.body);
  const actor=(who:any)=>({pin:{...who.pin},signature:{
   sourceRef:who.pin.sourceRef,keyId:who.pin.keyId,
   signatureBase64:sign(null,bytes,who.privateKey).toString('base64')}});
  x.survivingWitnessSignature=actor(f.bdEvidence.actors[1]);
  x.governanceSignatures=f.bdEvidence.actors.slice(3).map(actor);
 };
 resign(other);
 assert.equal((await record(other)).outcome,'CONFLICT_QUARANTINED');
 const third={...f,body:{...f.body,revocationNoticeSha256:h(994)}};
 resign(third);
 assert.equal((await record(third)).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(f.body.logRef)).attempts,3);
 assert.equal((await inspect(f.body.logRef)).locallyConsistentHistory,true);
});
test('forged survivor signature cannot register a freeze in durable MySQL',async()=>{
 const f=beFixture(log());await prepare(f);
 f.survivingWitnessSignature.signature.signatureBase64=Buffer.alloc(64,9).toString('base64');
 await assert.rejects(record(f),/inconsistent or unauthenticated freeze claim/);
 const [r]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_be_freeze_streams WHERE log_ref=?',[f.body.logRef]);
 assert.equal(Number(r[0].n),0);
});
test('local privileged DB head modification is detected but is not external WORM',async()=>{
 const f=beFixture(log());await prepare(f);
 await record(f);
 try{
  await pool.execute(
   'UPDATE inv_be_freeze_streams SET last_incident_sha256=? WHERE log_ref=?',
   [h(999),f.body.logRef]);
  const r=await inspect(f.body.logRef);
  assert.equal(r.locallyConsistentHistory,false);
  assert.ok(r.anomalyCodes.includes('FROZEN_HEAD_HISTORY_MISMATCH'));
  assert.equal(r.productionReleaseAuthorized,false);
 }finally{
  const {assessPhase1BeRevocationFreeze}=await import('../scripts/lib/phase1BeRevocationFreeze.mjs');
  const initial=assessPhase1BeRevocationFreeze(f).incidentSha256;
  await pool.execute(
   'UPDATE inv_be_freeze_streams SET last_incident_sha256=? WHERE log_ref=?',
   [initial,f.body.logRef]);
 }
 assert.equal((await inspect(f.body.logRef)).locallyConsistentHistory,true);
});
