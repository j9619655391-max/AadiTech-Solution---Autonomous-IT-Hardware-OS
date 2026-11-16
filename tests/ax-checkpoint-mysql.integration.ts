import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import mysql from 'mysql2/promise';
import {createHash,generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {getDatabaseConfig} from '../server/db';
import {axEvidenceWriteTarget,recordPhase1AxOfflineCheckpoint,inspectPhase1AxOfflineHistory}
 from '../server/checkpointGovernance/durable';
import {CHECKPOINT_PURPOSE,phase1AwCheckpointSigningBytes,phase1AwCheckpointReceiptSha256}
 from '../scripts/lib/phase1AwSignedCheckpoint.mjs';
import {PROVIDER_CODE,REQUESTED_SCOPE} from '../scripts/lib/providerAuthorityPreflight.mjs';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Phase 1AX integration tests require disposable CI MySQL');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,log=()=>('checkpoint-'+randomUUID()).slice(0,64);
const date=(deltaMs:number)=>new Date(Date.now()+deltaMs).toISOString();
function signers(){
 return (['LEGAL','SECURITY'] as const).map((role,i)=>{
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  return {role,reviewerRef:role.toLowerCase()+'-reviewer-00'+i,
   keyId:role.toLowerCase()+'-key-0000'+i,privateKey,
   publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
   publicKeySha256:createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')};
 });
}
type Signer=ReturnType<typeof signers>[number];
function checkpoint(keys:Signer[],sequence=1,prior:string|null=null,policyDigest='a'.repeat(64),
 times={issuedAt:date(-60_000),expiresAt:date(3_600_000)}){
 const body={
  schemaVersion:1,purpose:CHECKPOINT_PURPOSE,providerCode:PROVIDER_CODE,
  requestedScope:REQUESTED_SCOPE,sequence,issuedAt:times.issuedAt,
  expiresAt:times.expiresAt,priorCheckpointSha256:prior,
  journalEventCount:0,journalTailSha256:null,policySnapshotSha256:policyDigest,
  recoveryClaimSha256:null,releaseDecision:'HOLD'
 };
 const data=phase1AwCheckpointSigningBytes(body);
 return {...body,signatures:keys.map(k=>({role:k.role,reviewerRef:k.reviewerRef,keyId:k.keyId,
  signatureBase64:sign(null,data,k.privateKey).toString('base64')}))};
}
function pins(keys:Signer[]){
 return keys.map(({role,reviewerRef,keyId,publicKeyPem,publicKeySha256})=>
  ({role,reviewerRef,keyId,publicKeyPem,publicKeySha256}));
}
function record(logRef:string,cp:ReturnType<typeof checkpoint>,keys:Signer[]){
 return recordPhase1AxOfflineCheckpoint(pool,{logRef,checkpoint:cp,pins:pins(keys),env});
}
test('production and unapproved staging cannot write the checkpoint ledger',()=>{
 assert.throws(()=>axEvidenceWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_ci',CRM_TEST_DB:'1'} as NodeJS.ProcessEnv));
 assert.throws(()=>axEvidenceWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_prod'} as NodeJS.ProcessEnv));
 assert.throws(()=>axEvidenceWriteTarget({DB_NAME:'aaditech_staging_wrong',DB_SSL:'true'} as NodeJS.ProcessEnv));
});
test('genesis, chained progression, exact retry and readback are durable and held',async()=>{
 const keys=signers(),logRef=log(),first=checkpoint(keys);
 const accepted=await record(logRef,first,keys);
 assert.equal(accepted.outcome,'ACCEPTED_UNTRUSTED');
 assert.equal(accepted.productionReleaseAuthorized,false);
 const second=checkpoint(keys,2,phase1AwCheckpointReceiptSha256(first));
 const next=await record(logRef,second,keys);
 assert.equal(next.outcome,'ACCEPTED_UNTRUSTED');
 const replay=await record(logRef,second,keys);
 assert.equal(replay.outcome,'REPLAY');
 const report=await inspectPhase1AxOfflineHistory(pool,logRef,env);
 assert.equal(report.localHistoryConsistent,true);
 assert.equal(report.observationCount,2);
 assert.equal(report.acceptedSequence,2);
 assert.equal(report.governanceState,'HELD_UNVERIFIED');
 assert.equal(report.immutableExternalStorageVerified,false);
 assert.equal(report.productionReleaseAuthorized,false);
});
test('same signed claims with independently re-signed receipts are not falsely forked',async()=>{
 const keys=signers(),different=signers(),logRef=log();
 const body=checkpoint(keys),variant=checkpoint(different,1,null,body.policySnapshotSha256,
   {issuedAt:body.issuedAt,expiresAt:body.expiresAt});
 await record(logRef,body,keys);
 const r=await record(logRef,variant,different);
 assert.equal(r.outcome,'REPLAY_VARIANT');
 const report=await inspectPhase1AxOfflineHistory(pool,logRef,env);
 assert.equal(report.localHistoryConsistent,true);
 assert.equal(report.governanceState,'HELD_UNVERIFIED');
 assert.equal(report.observationCount,2);
});
test('concurrent signed contradictory next checkpoints serialize and quarantine',async()=>{
 const keys=signers(),logRef=log(),first=checkpoint(keys);
 await record(logRef,first,keys);
 const prior=phase1AwCheckpointReceiptSha256(first);
 const left=checkpoint(keys,2,prior,'b'.repeat(64));
 const right=checkpoint(keys,2,prior,'c'.repeat(64),{issuedAt:left.issuedAt,expiresAt:left.expiresAt});
 const results=await Promise.all([record(logRef,left,keys),record(logRef,right,keys)]);
 assert.deepEqual(results.map(r=>r.outcome).sort(),['ACCEPTED_UNTRUSTED','FORK']);
 const report=await inspectPhase1AxOfflineHistory(pool,logRef,env);
 assert.equal(report.localHistoryConsistent,true);
 assert.equal(report.governanceState,'QUARANTINED');
 assert.equal(report.acceptedSequence,2);
 assert.equal(report.observationCount,3);
 const later=checkpoint(keys,3,phase1AwCheckpointReceiptSha256(left));
 const held=await record(logRef,later,keys);
 assert.equal(held.outcome,'QUARANTINED_OBSERVATION');
 assert.equal((await inspectPhase1AxOfflineHistory(pool,logRef,env)).acceptedSequence,2);
});
test('rollback and sequence gaps quarantine even with otherwise valid Ed25519 signatures',async()=>{
 const keys=signers(),logRef=log(),first=checkpoint(keys);
 await record(logRef,first,keys);
 const r=await record(logRef,checkpoint(keys,4,phase1AwCheckpointReceiptSha256(first)),keys);
 assert.equal(r.outcome,'GAP');
 assert.equal(r.governanceState,'QUARANTINED');
 const differentLog=log(),genesis=checkpoint(keys);
 await record(differentLog,genesis,keys);
 const second=checkpoint(keys,2,phase1AwCheckpointReceiptSha256(genesis));
 await record(differentLog,second,keys);
 const rollback=await record(differentLog,checkpoint(keys,1,null,'f'.repeat(64)),keys);
 assert.equal(rollback.outcome,'ROLLBACK');
});
test('bad signature and wrong public pin fail before persistence',async()=>{
 const keys=signers(),logRef=log(),first=checkpoint(keys);
 const bad={...first,signatures:first.signatures.map(x=>({...x}))};
 bad.signatures[0].signatureBase64=Buffer.alloc(64,6).toString('base64');
 await assert.rejects(record(logRef,bad,keys),/signature/);
 const altered=pins(keys);altered[0].publicKeySha256='0'.repeat(64);
 await assert.rejects(recordPhase1AxOfflineCheckpoint(pool,{
  logRef,checkpoint:first,pins:altered,env}),/fingerprint/);
 const [rows]=await pool.execute<any[]>('SELECT COUNT(*) AS n FROM inv_ax_checkpoint_streams WHERE log_ref=?',[logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('disposable isolated-reconstruction drill detects a compromised fork and remains HOLD',async()=>{
 const keys=signers(),sourceLog=log(),restoredLog=log();
 const first=checkpoint(keys),next=checkpoint(keys,2,phase1AwCheckpointReceiptSha256(first));
 for(const stream of [sourceLog,restoredLog]){
  await record(stream,first,keys);await record(stream,next,keys);
 }
 const source=await inspectPhase1AxOfflineHistory(pool,sourceLog,env);
 const restored=await inspectPhase1AxOfflineHistory(pool,restoredLog,env);
 assert.equal(source.localHistoryConsistent,true);
 assert.equal(restored.localHistoryConsistent,true);
 assert.equal(restored.acceptedSequence,source.acceptedSequence);
 const compromise=checkpoint(keys,2,phase1AwCheckpointReceiptSha256(first),
  'd'.repeat(64),{issuedAt:next.issuedAt,expiresAt:next.expiresAt});
 assert.equal((await record(restoredLog,compromise,keys)).outcome,'FORK');
 const quarantined=await inspectPhase1AxOfflineHistory(pool,restoredLog,env);
 assert.equal(quarantined.governanceState,'QUARANTINED');
 assert.equal(quarantined.productionReleaseAuthorized,false);
});
test('independent readback detects tampered stored digest on disposable CI fixture',async()=>{
 const keys=signers(),logRef=log(),first=checkpoint(keys);
 await record(logRef,first,keys);
 const receipt=phase1AwCheckpointReceiptSha256(first);
 const [rows]=await pool.execute<any[]>(`SELECT claim_sha256 FROM
  inv_ax_checkpoint_observations WHERE log_ref=? AND receipt_sha256=?`,[logRef,receipt]);
 const actual=rows[0].claim_sha256;
 try{
  await pool.execute(`UPDATE inv_ax_checkpoint_observations SET claim_sha256=?
    WHERE log_ref=? AND receipt_sha256=?`,['0'.repeat(64),logRef,receipt]);
  const r=await inspectPhase1AxOfflineHistory(pool,logRef,env);
  assert.equal(r.localHistoryConsistent,false);
  assert.ok(r.anomalyCodes.includes('OBSERVATION_DIGEST_MISMATCH'));
 }finally{
  await pool.execute(`UPDATE inv_ax_checkpoint_observations SET claim_sha256=?
    WHERE log_ref=? AND receipt_sha256=?`,[actual,logRef,receipt]);
 }
 assert.equal((await inspectPhase1AxOfflineHistory(pool,logRef,env)).localHistoryConsistent,true);
});
