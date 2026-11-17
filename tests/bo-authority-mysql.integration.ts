import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {buildLocalQuoteHistoryCommitment,canonicalCandidateWitnessBody,
 candidateWitnessReceiptDigest,type CandidatePinnedKey}
 from '../server/commercialIntegrity/quoteAnchors';
import {canonicalCandidateQuoteObservation,type CandidateHeadObservationBody}
 from '../server/commercialIntegrity/quoteHeadReconciliation';
import {recordCandidateQuoteCheckpoint}
 from '../server/commercialIntegrity/quoteCheckpointCustody';
import {recordCandidateQuoteReconciliation}
 from '../server/commercialIntegrity/quoteReconciliationCustody';
import {recordCandidateExternalAuthorityDossier,inspectCandidateExternalAuthorityDossier,
 readCandidateAuthorityExpectedUnderLock,
 inspectCandidateExternalAuthorityDossierOnConnection,boAuthorityDossierWriteTarget}
 from '../server/commercialIntegrity/quoteAuthorityCustody';
import {candidateExternalAuthorityDossierDigest}
 from '../server/commercialIntegrity/quoteAuthorityDossier';
import {boFixtureNow,boDossierFixture,boFixtureSha,boClone}
 from './bo-dossier-fixtures';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BO strictly requires disposable isolated CI MySQL');
const db=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>db.end());
const env=process.env;
function signer(keyId:string){
 const pair=generateKeyPairSync('ed25519');
 const pin:CandidatePinnedKey={keyId,status:'ACTIVE',
  publicKeySpkiPem:pair.publicKey.export({type:'spki',format:'pem'}).toString(),
  validFrom:'2026-01-01T00:00:00.000Z',
  validUntil:'2028-01-01T00:00:00.000Z'};
 return {pin,privateKey:pair.privateKey};
}
const wa=signer('bo-witness-a'),wb=signer('bo-witness-b');
async function fixture(){
 const owner=randomUUID(),customer=randomUUID(),product=randomUUID(),quote=randomUUID();
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [owner,'bo-'+owner+'@example.invalid','BO synthetic owner','fixture-only-hash','OWNER']);
 await db.execute('INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,?,?,?,?,?,?)',
  [customer,'BO applicant-managed synthetic customer','Fixture',
   'bo-'+customer+'@example.invalid','9888888888','Mumbai','Maharashtra']);
 await db.execute(`INSERT INTO crm_products
  (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,gstRate,hsn)
  VALUES (?,?,'Candidate','BO no-stock server','SERVER','no real stock',50,100,70,18,'8471')`,
  [product,'BO-'+product]);
 await db.execute(`INSERT INTO sales_quote_drafts
  (id,customer_id,created_by,status,currency,subtotal,tax_estimate,total_estimate)
  VALUES (?,?,?,'DRAFT','INR',100,18,118)`,[quote,customer,owner]);
 await db.execute(`INSERT INTO sales_quote_draft_items
  (id,quote_id,position,product_id,sku_snapshot,name_snapshot,hsn_snapshot,
  quantity,unit_cost,unit_price,gst_rate,line_subtotal,line_tax_estimate)
  VALUES (?,?,1,?,'BO-SKU','BO candidate server','8471',1,50,100,18,100,18)`,
  [randomUUID(),quote,product]);
 const [draft]=await db.query<any[]>(
  'SELECT q.*,c.deleted_at AS customer_deleted_at FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id WHERE q.id=?',[quote]);
 const [lines]=await db.query<any[]>(
  'SELECT * FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',[quote]);
 const source=buildLocalQuoteHistoryCommitment({draft:draft[0],lines,
  revisions:[],decisions:[],preparations:[]}).sourceCommitmentSha256;
 const bmSigner=signer('bo-checkpoint-fixture');
 const body={format:'aaditech-quote-history-witness-v1' as const,
  quoteId:quote,sequence:1,revisionNumber:0,
  sourceCommitmentSha256:source,previousReceiptSha256:null,
  witnessedAt:'2026-11-17T11:55:00.000Z',keyId:bmSigner.pin.keyId};
 const bmReceipt={body,signatureBase64:sign(null,
  Buffer.from(canonicalCandidateWitnessBody(body)),
  bmSigner.privateKey).toString('base64')};
 assert.equal((await recordCandidateQuoteCheckpoint(db,{
  quoteId:quote,receipts:[bmReceipt],pinnedKeys:[bmSigner.pin],env
 })).outcome,'RECORDED_UNVERIFIED');
 const bmReceiptSha=candidateWitnessReceiptDigest(bmReceipt);
 const observe=(who:ReturnType<typeof signer>,sourceId:string)=>{
  const body:CandidateHeadObservationBody={
   format:'aaditech-quote-head-observation-v1',quoteId:quote,sourceId,
   keyId:who.pin.keyId,sequence:1,receiptSha256:bmReceiptSha,sourceSha256:source,
   publishedAt:'2026-11-17T12:00:00.000Z',observedAt:'2026-11-17T12:04:00.000Z',
   revocationEpoch:4,revokedKeyIds:[],
   revocationThisUpdate:'2026-11-17T11:50:00.000Z',
   revocationNextUpdate:'2026-11-17T12:20:00.000Z'
  };
  return {body,signatureBase64:sign(null,
   Buffer.from(canonicalCandidateQuoteObservation(body)),
   who.privateKey).toString('base64')};
 };
 assert.equal((await recordCandidateQuoteReconciliation(db,{
  quoteId:quote,revision:1,previousPacketSha256:null,
  observations:[observe(wa,'bo-candidate-witness-one'),
   observe(wb,'bo-candidate-witness-two')],
  pinnedKeys:[wa.pin,wb.pin],
  now:new Date('2026-11-17T12:05:00.000Z'),env
 })).outcome,'RECORDED_UNVERIFIED');
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateAuthorityExpectedUnderLock(conn,quote);
  await conn.commit();
  assert.equal(expected.bnLocallyConsistent,true);
  assert.equal(expected.bmLocallyConsistent,true);
  return {quote,expected};
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
const record=(x:Awaited<ReturnType<typeof fixture>>,version:number,
 previousDossierSha256:string|null,
 dossier=boDossierFixture(x.expected))=>
 recordCandidateExternalAuthorityDossier(db,{quoteId:x.quote,version,
  previousDossierSha256,dossier,now:boFixtureNow,env});
const inspect=(quote:string)=>inspectCandidateExternalAuthorityDossier(db,quote,env);

test('BO denies all production/undeclared/non-TLS staging writer and migration targets',()=>{
 for(const environment of [
  {NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'},
  {NODE_ENV:'production',DB_SSL:'true',DB_NAME:'aaditech_staging_ci',
   BM_QUOTE_WRITE_APPROVED:'YES',BN_RECONCILIATION_WRITE_APPROVED:'YES',
   BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {NODE_ENV:'development',DB_SSL:'false',DB_NAME:'aaditech_staging_ci',
   BM_QUOTE_WRITE_APPROVED:'YES',BN_RECONCILIATION_WRITE_APPROVED:'YES',
   BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {NODE_ENV:'development',DB_SSL:'true',DB_NAME:'aaditech_staging_ci',
   BM_QUOTE_WRITE_APPROVED:'YES',BN_RECONCILIATION_WRITE_APPROVED:'YES',
   STAGING_DISPOSABLE_CONFIRMED:'YES'}
 ])assert.throws(()=>boAuthorityDossierWriteTarget(environment as NodeJS.ProcessEnv));
 assert.equal(boAuthorityDossierWriteTarget(env),'ci');
});
test('BO candidate dossier genesis, exact replay, monotonic append and permanent release HOLD',async()=>{
 const x=await fixture(),dossier=boDossierFixture(x.expected);
 assert.equal((await record(x,1,null,dossier)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(x,1,null,dossier)).outcome,'REPLAY');
 const first=await inspect(x.quote);
 assert.equal(first.candidateAuthorityDossierVersion,1);
 assert.equal(first.candidateAuthorityDossierLocallyConsistent,true,
  first.candidateAuthorityDossierAnomalyCodes.join(','));
 assert.equal(first.candidateAuthorityDossierGovernanceState,'HELD_UNVERIFIED');
 const next=boClone(dossier);next.enrollment.agreementSha256=boFixtureSha('e');
 assert.equal((await record(x,2,first.candidateAuthorityDossierSha256!,next)).outcome,
  'RECORDED_UNVERIFIED');
 const report=await inspect(x.quote);
 assert.equal(report.candidateAuthorityDossierVersion,2);
 assert.equal(report.candidateAuthorityDossierAttemptCount,2);
 assert.equal(report.independentKeyEnrollmentAuthenticated,false);
 assert.equal(report.trustedOutOfBandPublicationHeadVerified,false);
 assert.equal(report.actualEncryptedDrWitnessed,false);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.releaseDecision,'HOLD');
 const [rows]=await db.query<any[]>(
  'SELECT provider_enrolled,out_of_band_head_verified,independent_revocation_verified,encrypted_dr_witnessed,legal_signoffs_verified,production_release FROM quote_bo_candidate_authority_streams WHERE quote_id=?',
  [x.quote]);
 assert.deepEqual([
  rows[0].provider_enrolled,rows[0].out_of_band_head_verified,
  rows[0].independent_revocation_verified,rows[0].encrypted_dr_witnessed,
  rows[0].legal_signoffs_verified,rows[0].production_release],
  ['NO','NO','NO','NO','NO','HOLD']);
});
test('BO concurrent applicant-generated candidate dossier fork causes permanent quarantine',async()=>{
 const x=await fixture(),a=boDossierFixture(x.expected),
  b=boClone(a);
 b.publication.receiptEvidenceSha256=boFixtureSha('e');
 const results=(await Promise.all([record(x,1,null,a),record(x,1,null,b)]))
  .map(r=>r.outcome).sort();
 assert.deepEqual(results,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const state=await inspect(x.quote);
 assert.equal(state.candidateAuthorityDossierGovernanceState,'QUARANTINED');
 assert.equal(state.candidateAuthorityDossierVersion,1);
 assert.equal(state.candidateAuthorityDossierLocallyConsistent,true,
  state.candidateAuthorityDossierAnomalyCodes.join(','));
 const c=boClone(a);c.enrollment.agreementSha256=boFixtureSha('f');
 assert.equal((await record(x,2,state.candidateAuthorityDossierSha256!,c)).outcome,
  'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateAuthorityDossierVersion,1);
});
test('BO false out-of-band checkpoint or fake verified issuer claim freezes without granting authority',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 d.publication.claimedHeadSha256=boFixtureSha('e');
 assert.equal((await record(x,1,null,d)).outcome,'EVIDENCE_CONFLICT_QUARANTINED');
 const state=await inspect(x.quote);
 assert.equal(state.candidateAuthorityDossierGovernanceState,'QUARANTINED');
 assert.equal(state.candidateAuthorityDossierVersion,0);
 assert.equal(state.trustedOutOfBandPublicationHeadVerified,false);
});
test('BO applicant-provided CRL/OCSP downgrade and missing segregated reviewer precheck freeze',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 d.revocation.epoch=x.expected.bnRevocationEpoch-1;
 assert.equal((await record(x,1,null,d)).outcome,'REVOCATION_REGRESSION_QUARANTINED');
 const audit=await inspect(x.quote);
 assert.equal(audit.candidateAuthorityDossierGovernanceState,'QUARANTINED');
 assert.equal(audit.independentRevocationAndCrlOcspVerified,false);
 const y=await fixture(),bad=boDossierFixture(y.expected);
 bad.reviews[0].actorId=bad.reviews[1].actorId;
 assert.equal((await record(y,1,null,bad)).outcome,'EVIDENCE_CONFLICT_QUARANTINED');
 assert.equal((await inspect(y.quote)).productionReleaseAuthorized,false);
});
test('BO DR restore rollback claim is quarantined with no real backup restoration',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 d.disasterRecovery.recoveredSequence=0;
 assert.equal((await record(x,1,null,d)).outcome,'EVIDENCE_CONFLICT_QUARANTINED');
 const state=await inspect(x.quote);
 assert.equal(state.candidateAuthorityDossierGovernanceState,'QUARANTINED');
 assert.equal(state.actualEncryptedDrWitnessed,false);
});
test('BO forged local dossier head is detected, write denied, restoring local hash does not grant trust',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 await record(x,1,null,d);
 const digest=candidateExternalAuthorityDossierDigest(d);
 try{
  await db.execute(
   'UPDATE quote_bo_candidate_authority_streams SET last_dossier_sha256=? WHERE quote_id=?',
   [boFixtureSha('f'),x.quote]);
  const tampered=await inspect(x.quote);
  assert.equal(tampered.candidateAuthorityDossierLocallyConsistent,false);
  assert.ok(tampered.candidateAuthorityDossierAnomalyCodes.includes(
   'BO_DOSSIER_HEAD_HISTORY_DIVERGENCE'));
  const extension=boClone(d);extension.enrollment.agreementSha256=boFixtureSha('e');
  await assert.rejects(record(x,2,digest,extension),
   /cannot append to corrupt candidate dossier history/);
 }finally{
  await db.execute(
   'UPDATE quote_bo_candidate_authority_streams SET last_dossier_sha256=? WHERE quote_id=?',
   [digest,x.quote]);
 }
 assert.equal((await inspect(x.quote)).candidateAuthorityDossierLocallyConsistent,true);
 assert.equal((await inspect(x.quote)).independentKeyEnrollmentAuthenticated,false);
});
test('BO BM/BN upstream head alteration is detected in SQL rollback rehearsal without persistence',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 await record(x,1,null,d);
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await conn.execute(
   'UPDATE quote_bn_candidate_reconciliation_streams SET last_packet_sha256=? WHERE quote_id=?',
   [boFixtureSha('f'),x.quote]);
  const {expected}=await readCandidateAuthorityExpectedUnderLock(conn,x.quote);
  const alarm=await inspectCandidateExternalAuthorityDossierOnConnection(conn,x.quote,expected);
  assert.equal(alarm.candidateAuthorityDossierLocallyConsistent,false);
  assert.ok(alarm.candidateAuthorityDossierAnomalyCodes.includes(
   'BO_DOSSIER_UPSTREAM_BM_BN_CHANGED'));
 }finally{await conn.rollback().catch(()=>{});conn.release();}
 const restored=await inspect(x.quote);
 assert.equal(restored.candidateAuthorityDossierLocallyConsistent,true);
 assert.equal(restored.productionReleaseAuthorized,false);
});
test('BO underlying quoted line tax mutation produces source head drift and no external authority',async()=>{
 const x=await fixture(),d=boDossierFixture(x.expected);
 await record(x,1,null,d);
 try{
  await db.execute(
   'UPDATE sales_quote_draft_items SET line_tax_estimate=0.01 WHERE quote_id=?',
   [x.quote]);
  const changed=await inspect(x.quote);
  assert.equal(changed.candidateAuthorityDossierLocallyConsistent,false);
  assert.ok(changed.candidateAuthorityDossierAnomalyCodes.includes(
   'BO_DOSSIER_UPSTREAM_BM_BN_CHANGED'));
 }finally{
  await db.execute(
   'UPDATE sales_quote_draft_items SET line_tax_estimate=18.00 WHERE quote_id=?',
   [x.quote]);
 }
 assert.equal((await inspect(x.quote)).candidateAuthorityDossierLocallyConsistent,true);
});
