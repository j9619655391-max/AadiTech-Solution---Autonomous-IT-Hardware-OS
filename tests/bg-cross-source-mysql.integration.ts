import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,createHash,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {bgFixture,h} from './support/phase1bgFixture.mjs';
import {bcFixture} from './support/phase1bcFixture.mjs';
import {recordPhase1AzReadiness} from '../server/externalReadiness/durable';
import {recordPhase1BbEvidence} from '../server/evidenceIntake/durable';
import {recordPhase1BcWitnessCustody} from '../server/witnessCustody/durable';
import {recordPhase1BdEvidenceReview} from '../server/evidenceReview/durable';
import {recordPhase1BeRevocationFreeze} from '../server/revocationFreeze/durable';
import {recordPhase1BfPublication} from '../server/revocationPublication/durable';
import {recordPhase1BgCrossSource,inspectPhase1BgCrossSource,bgWriteTarget}
 from '../server/crossSourceAcceptance/durable';
import {assessPhase1BgEvidenceQuorum}
 from '../scripts/lib/phase1BgCrossSourceAcceptance.mjs';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BG integration requires disposable CI MySQL');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,newLog=()=>('bg-log-'+randomUUID());
const record=(f:any)=>recordPhase1BgCrossSource(pool,{...f,env});
const inspect=(logRef:string)=>inspectPhase1BgCrossSource(pool,logRef,env);
async function prepare(f:any,{skipPublication=false}={}){
 const pub=f.publication,be=pub.freezeEvidence,d=be.bdEvidence;
 const logRef=d.azPacket.archive.logRef;
 assert.equal((await recordPhase1AzReadiness(pool,{
  logRef,packet:d.azPacket,now:be.now,env})).outcome,'RECORDED_UNTRUSTED');
 assert.equal((await recordPhase1BbEvidence(pool,{
  azPacket:d.azPacket,records:d.bbRecords,sequence:1,
  previousBatchSha256:null,now:be.now,env})).outcome,'ACCEPTED_UNVERIFIED');
 const bc=bcFixture(logRef,{azPacket:d.azPacket,actors:d.actors,
  records:d.bbRecords,now:be.now});
 assert.equal((await recordPhase1BcWitnessCustody(pool,{
  azPacket:d.azPacket,observations:bc.make(2,3).observations,now:be.now,env
 })).outcome,'GENESIS_UNVERIFIED');
 assert.equal((await recordPhase1BdEvidenceReview(pool,{
  ...d,revision:1,previousReviewSha256:null,env
 })).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await recordPhase1BeRevocationFreeze(pool,{...be,env})).outcome,
  'FROZEN_UNVERIFIED');
 if(!skipPublication)assert.equal((await recordPhase1BfPublication(pool,{
  ...pub,env
 })).outcome,'RECORDED_UNVERIFIED');
}
function version(f:any,rev:number,prev:string|null,change:any={}){
 f.manifest={...f.manifest,reviewRevision:rev,previousReviewSha256:prev,...change};
 f.resign();
 return f;
}
function snapshot(f:any){
 return {publication:f.publication,manifest:{...f.manifest},
  auditors:structuredClone(f.auditors),now:f.now};
}
test('1BG denies production and non-TLS/unapproved staging connections',()=>{
 assert.throws(()=>bgWriteTarget({NODE_ENV:'production',DB_NAME:'aaditech_ci',
  CRM_TEST_DB:'1'} as NodeJS.ProcessEnv));
 assert.throws(()=>bgWriteTarget({DB_NAME:'aaditech_staging_temp',
  BG_CROSS_SOURCE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_SSL:'false'} as NodeJS.ProcessEnv));
});
test('without an actually persisted frozen BF publication, candidate audit cannot write',async()=>{
 const f=bgFixture(newLog());await prepare(f,{skipPublication:true});
 await assert.rejects(record(f),/missing or quarantined BF publication source/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_bg_cross_source_streams WHERE log_ref=?',
  [f.manifest.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('first cross-source quorum, readback and exact replay stay HELD_UNVERIFIED',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(f)).outcome,'REPLAY');
 const r=await inspect(f.manifest.logRef);
 assert.equal(r.lastCandidateReviewRevision,1);
 assert.equal(r.attempts,1);
 assert.equal(r.governanceState,'HELD_UNVERIFIED');
 assert.equal(r.localAuditHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.verifiedCrlOcspAuthority,false);
 assert.equal(r.actualWormVerified,false);
 assert.equal(r.actuallyWitnessedEncryptedDr,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('monotonic second and third claimed CRL/OCSP audits do not authenticate issuer',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 const old=assessPhase1BgEvidenceQuorum(f);
 await record(f);
 version(f,2,old.reviewSha256,{crlNumber:2,ocspResponseSha256:h(6111)});
 const middle=assessPhase1BgEvidenceQuorum(f);
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 version(f,3,middle.reviewSha256,{crlNumber:3,ocspResponseSha256:h(6112)});
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(f)).outcome,'REPLAY');
 const r=await inspect(f.manifest.logRef);
 assert.equal(r.lastCandidateReviewRevision,3);
 assert.equal(r.attempts,3);
 assert.equal(r.localAuditHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.verifiedCrlOcspAuthority,false);
});
test('two concurrently signed competing auditor CRL/OCSP claims quarantine the same revision',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 version(f,1,null,{ocspResponseSha256:h(6201)});
 const a=snapshot(f);
 version(f,1,null,{ocspResponseSha256:h(6202)});
 const b=snapshot(f);
 const outcomes=(await Promise.all([record(a),record(b)]))
  .map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const r=await inspect(f.manifest.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.lastCandidateReviewRevision,1);
 assert.equal(r.localAuditHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal((await record(a)).outcome,'DUPLICATE_REJECTED');
 assert.equal((await record(b)).outcome,'DUPLICATE_REJECTED');
 const next=version(f,2,assessPhase1BgEvidenceQuorum(b).reviewSha256,
  {ocspResponseSha256:h(6203)});
 assert.equal((await record(next)).outcome,'POST_INCIDENT_QUARANTINED');
});
test('old signed review replay after a valid newer CRL snapshot records rollback incident',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 const old=snapshot(f),first=assessPhase1BgEvidenceQuorum(old);
 await record(f);
 version(f,2,first.reviewSha256,{crlNumber:2,ocspResponseSha256:h(6301)});
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(old)).outcome,'ROLLBACK_QUARANTINED');
 assert.equal((await record(old)).outcome,'DUPLICATE_REJECTED');
 const r=await inspect(f.manifest.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.localAuditHistoryConsistent,true);
});
test('local review gaps, false predecessor, regression and auditor custody rotation quarantine',async()=>{
 for(const mode of ['gap','predecessor','crl','auditor']){
  const f=bgFixture(newLog());await prepare(f);
  f.manifest.crlNumber=4;f.resign();
  const first=assessPhase1BgEvidenceQuorum(f);
  await record(f);
  if(mode==='gap')version(f,3,first.reviewSha256,{crlNumber:5});
  else if(mode==='predecessor')version(f,2,h(6401),{crlNumber:5});
  else if(mode==='crl')version(f,2,first.reviewSha256,{crlNumber:3});
  else{
   const {publicKey,privateKey}=generateKeyPairSync('ed25519');
   f.actors[0]={privateKey,pin:{...f.actors[0].pin,
    keyId:'bg-audit-rotated-key-005',
    publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
    publicKeySha256:createHash('sha256').update(
     publicKey.export({format:'der',type:'spki'})).digest('hex')
   }};
   f.repin();
   version(f,2,first.reviewSha256,{crlNumber:5});
  }
  const expected=mode==='gap'?'GAP_QUARANTINED':mode==='predecessor'?
   'PREDECESSOR_MISMATCH_QUARANTINED':mode==='crl'?
    'CRL_REGRESSION_QUARANTINED':'AUDITOR_PINSET_CHANGE_QUARANTINED';
  assert.equal((await record(f)).outcome,expected,mode);
  const r=await inspect(f.manifest.logRef);
  assert.equal(r.governanceState,'QUARANTINED',mode);
  assert.equal(r.localAuditHistoryConsistent,true,r.anomalyCodes.join(','));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('incorrect or forged independent auditor signatures are refused before persistence',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 f.auditors[1].signature.signatureBase64=Buffer.alloc(64,5).toString('base64');
 await assert.rejects(record(f),/invalid or unbound three-source candidate audit/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS n FROM inv_bg_cross_source_streams WHERE log_ref=?',
  [f.manifest.logRef]);
 assert.equal(Number(rows[0].n),0);
});
test('local privileged MySQL review-head mutation is detected, not external WORM',async()=>{
 const f=bgFixture(newLog());await prepare(f);
 await record(f);
 try{
  await pool.execute('UPDATE inv_bg_cross_source_streams SET last_review_sha256=? WHERE log_ref=?',
   [h(6601),f.manifest.logRef]);
  const r=await inspect(f.manifest.logRef);
  assert.equal(r.localAuditHistoryConsistent,false);
  assert.ok(r.anomalyCodes.includes('AUDIT_HEAD_HISTORY_DIVERGENCE'));
  assert.equal(r.productionReleaseAuthorized,false);
 }finally{
  await pool.execute('UPDATE inv_bg_cross_source_streams SET last_review_sha256=? WHERE log_ref=?',
   [assessPhase1BgEvidenceQuorum(f).reviewSha256,f.manifest.logRef]);
 }
 assert.equal((await inspect(f.manifest.logRef)).localAuditHistoryConsistent,true);
});
