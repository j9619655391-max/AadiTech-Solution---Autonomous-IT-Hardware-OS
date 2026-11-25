import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash,generateKeyPairSync,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {bfFixture,h} from './support/phase1bfFixture.mjs';
import {bcFixture} from './support/phase1bcFixture.mjs';
import {recordPhase1AzReadiness} from '../server/externalReadiness/durable';
import {recordPhase1BbEvidence} from '../server/evidenceIntake/durable';
import {recordPhase1BcWitnessCustody} from '../server/witnessCustody/durable';
import {recordPhase1BdEvidenceReview} from '../server/evidenceReview/durable';
import {recordPhase1BeRevocationFreeze}
 from '../server/revocationFreeze/durable';
import {recordPhase1BfPublication,inspectPhase1BfPublication,
 bfPublicationWriteTarget} from '../server/revocationPublication/durable';
import {assessPhase1BfPublication,phase1BfPublicationSigningBytes}
 from '../scripts/lib/phase1BfRevocationPublication.mjs';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BF MySQL integration only targets disposable CI');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,newLog=()=>('bf-log-'+randomUUID());
const record=(f:any)=>recordPhase1BfPublication(pool,{...f,env});
const inspect=(logRef:string)=>inspectPhase1BfPublication(pool,logRef,env);
async function prepare(f:any,{skipFreeze=false}={}){
 const be=f.freezeEvidence,d=be.bdEvidence,logRef=d.azPacket.archive.logRef;
 assert.equal((await recordPhase1AzReadiness(pool,{
  logRef,packet:d.azPacket,now:be.now,env})).outcome,'RECORDED_UNTRUSTED');
 assert.equal((await recordPhase1BbEvidence(pool,{
  azPacket:d.azPacket,records:d.bbRecords,sequence:1,
  previousBatchSha256:null,now:be.now,env})).outcome,'ACCEPTED_UNVERIFIED');
 const bc=bcFixture(logRef,{
  azPacket:d.azPacket,records:d.bbRecords,actors:d.actors,now:be.now
 });
 assert.equal((await recordPhase1BcWitnessCustody(pool,{
  azPacket:d.azPacket,observations:bc.make(2,3).observations,now:be.now,env
 })).outcome,'GENESIS_UNVERIFIED');
 assert.equal((await recordPhase1BdEvidenceReview(pool,{
  ...d,revision:1,previousReviewSha256:null,env
 })).outcome,'RECORDED_UNVERIFIED');
 if(!skipFreeze)assert.equal((await recordPhase1BeRevocationFreeze(pool,{
  ...be,env
 })).outcome,'FROZEN_UNVERIFIED');
}
function version(f:any,seq:number,prev:string|null,changes:any={}){
 f.body={...f.body,publicationSequence:seq,previousPublicationSha256:prev,...changes};
 f.resign();
 return f;
}
function forked(f:any,seq:number,prev:string|null,first:any,second:any){
 const common={...f.body,publicationSequence:seq,previousPublicationSha256:prev};
 const a=version(f,seq,prev,first);
 const signedA={...a,body:{...a.body},publisher:structuredClone(a.publisher),
  survivingWitness:structuredClone(a.survivingWitness),
  securityReviewer:structuredClone(a.securityReviewer)};
 f.body={...common};
 const b=version(f,seq,prev,second);
 const signedB={...b,body:{...b.body},publisher:structuredClone(b.publisher),
  survivingWitness:structuredClone(b.survivingWitness),
  securityReviewer:structuredClone(b.securityReviewer)};
 return [signedA,signedB];
}
test('Phase 1BF publication ledger rejects production and non-TLS staging writes',()=>{
 assert.throws(()=>bfPublicationWriteTarget({
  NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'
 } as NodeJS.ProcessEnv));
 assert.throws(()=>bfPublicationWriteTarget({
  NODE_ENV:'test',DB_NAME:'aaditech_staging_remote',
  BF_PUBLICATION_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_SSL:'false'
 } as NodeJS.ProcessEnv));
});
test('unfrozen BE stream cannot accept self-signed revocation publisher proofs',async()=>{
 const f=bfFixture(newLog());await prepare(f,{skipFreeze:true});
 await assert.rejects(record(f),/missing, quarantined or altered emergency freeze predecessor/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS total FROM inv_bf_publication_streams WHERE log_ref=?',
  [f.body.logRef]);
 assert.equal(Number(rows[0].total),0);
});
test('first frozen signed publication is recorded as untrusted and exact replay is idempotent',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(f)).outcome,'REPLAY');
 const report=await inspect(f.body.logRef);
 assert.equal(report.governanceState,'HELD_UNVERIFIED');
 assert.equal(report.attempts,1);
 assert.equal(report.lastCandidatePublicationSequence,1);
 assert.equal(report.localDigestHistoryConsistent,true,report.anomalyCodes.join(','));
 assert.equal(report.actualRevocationExternallyVerified,false);
 assert.equal(report.genuineWormRetentionVerified,false);
 assert.equal(report.encryptedDRIndependentlyWitnessed,false);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.productionReleaseBlocked,true);
});
test('properly signed second/third publication advances only local candidate hash continuity',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 const first=assessPhase1BfPublication(f);
 await record(f);
 version(f,2,first.publicationSha256,{publisherPolicySha256:h(3101)});
 const second=assessPhase1BfPublication(f);
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 version(f,3,second.publicationSha256,{publisherPolicySha256:h(3102)});
 assert.equal((await record(f)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(f)).outcome,'REPLAY');
 const report=await inspect(f.body.logRef);
 assert.equal(report.attempts,3);
 assert.equal(report.lastCandidatePublicationSequence,3);
 assert.equal(report.localDigestHistoryConsistent,true,report.anomalyCodes.join(','));
 assert.equal(report.issuerIndependentlyAuthenticated,false);
});
test('two concurrent valid but conflicting signed first publications force permanent quarantine',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 const [a,b]=forked(f,1,null,{publisherPolicySha256:h(3201)},
  {publisherPolicySha256:h(3202)});
 const outcomes=(await Promise.all([record(a),record(b)])).map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const r=await inspect(f.body.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.attempts,2);
 assert.equal(r.localDigestHistoryConsistent,true,r.anomalyCodes.join(','));
 assert.equal((await record(a)).outcome,'DUPLICATE_REJECTED');
 assert.equal((await record(b)).outcome,'DUPLICATE_REJECTED');
 const future=version(f,2,assessPhase1BfPublication(a).publicationSha256,
  {publisherPolicySha256:h(3203)});
 assert.equal((await record(future)).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(f.body.logRef)).lastCandidatePublicationSequence,1);
});
test('stale signed publication rollback quarantines a previously growing chain',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 const old={...f,body:{...f.body},publisher:structuredClone(f.publisher),
  survivingWitness:structuredClone(f.survivingWitness),
  securityReviewer:structuredClone(f.securityReviewer)};
 const initial=assessPhase1BfPublication(old);
 await record(f);
 version(f,2,initial.publicationSha256,{publisherPolicySha256:h(3301)});
 await record(f);
 assert.equal((await record(old)).outcome,'ROLLBACK_QUARANTINED');
 assert.equal((await record(old)).outcome,'DUPLICATE_REJECTED');
 const r=await inspect(f.body.logRef);
 assert.equal(r.governanceState,'QUARANTINED');
 assert.equal(r.lastCandidatePublicationSequence,2);
 assert.equal(r.localDigestHistoryConsistent,true);
});
test('missing predecessor, sequence gap and unexpectedly rotated issuer key all quarantine',async()=>{
 for(const mode of ['gap','predecessor','issuer']){
  const f=bfFixture(newLog());await prepare(f);
  const head=assessPhase1BfPublication(f);
  await record(f);
  if(mode==='gap')version(f,3,head.publicationSha256);
  else if(mode==='predecessor')version(f,2,h(3401));
  else{
   version(f,2,head.publicationSha256);
   const {privateKey,publicKey}=generateKeyPairSync('ed25519');
   const spki=publicKey.export({format:'der',type:'spki'});
   f.body.publisherPublicKeySha256=createHash('sha256').update(spki).digest('hex');
   f.publisher.pin.publicKeySha256=f.body.publisherPublicKeySha256;
   f.publisher.pin.publicKeyPem=publicKey.export({format:'pem',type:'spki'}).toString();
   const bytes=phase1BfPublicationSigningBytes(f.body);
   f.publisher.signature.signatureBase64=sign(null,bytes,privateKey).toString('base64');
   // Other two signatures must also bind the updated publisher fingerprint.
   const d=f.freezeEvidence.bdEvidence;
   for(const [name,actor] of [['survivingWitness',d.actors[1]],
     ['securityReviewer',d.actors[3]]] as const){
    f[name].signature.signatureBase64=sign(null,bytes,actor.privateKey).toString('base64');
   }
  }
  const expected=mode==='gap'?'GAP_QUARANTINED':mode==='predecessor'?
   'PREDECESSOR_MISMATCH_QUARANTINED':'ISSUER_KEY_CHANGE_QUARANTINED';
  assert.equal((await record(f)).outcome,expected,mode);
  const r=await inspect(f.body.logRef);
  assert.equal(r.governanceState,'QUARANTINED');
  assert.equal(r.localDigestHistoryConsistent,true,r.anomalyCodes.join(','));
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('forged publisher signature cannot persist a candidate publication',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 f.publisher.signature.signatureBase64=Buffer.alloc(64,2).toString('base64');
 await assert.rejects(record(f),/invalid or unauthenticated publication claim/);
 const [rows]=await pool.execute<any[]>(
  'SELECT COUNT(*) AS total FROM inv_bf_publication_streams WHERE log_ref=?',[f.body.logRef]);
 assert.equal(Number(rows[0].total),0);
});
test('isolated privileged MySQL head tamper is detectable, never external WORM',async()=>{
 const f=bfFixture(newLog());await prepare(f);
 await record(f);
 try{
  await pool.execute(
   'UPDATE inv_bf_publication_streams SET last_publication_sha256=? WHERE log_ref=?',
   [h(3777),f.body.logRef]);
  const report=await inspect(f.body.logRef);
  assert.equal(report.localDigestHistoryConsistent,false);
  assert.ok(report.anomalyCodes.includes('PUBLICATION_HEAD_HISTORY_DIVERGENCE'));
  assert.equal(report.productionReleaseAuthorized,false);
 }finally{
  const fingerprint=assessPhase1BfPublication(f).publicationSha256;
  await pool.execute(
   'UPDATE inv_bf_publication_streams SET last_publication_sha256=? WHERE log_ref=?',
   [fingerprint,f.body.logRef]);
 }
 assert.equal((await inspect(f.body.logRef)).localDigestHistoryConsistent,true);
});
