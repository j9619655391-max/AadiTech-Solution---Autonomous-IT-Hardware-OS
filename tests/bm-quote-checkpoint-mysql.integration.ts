import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {buildLocalQuoteHistoryCommitment,canonicalCandidateWitnessBody,
 candidateWitnessReceiptDigest,type CandidateWitnessReceipt,
 type CandidateWitnessBody,type CandidatePinnedKey} from '../server/commercialIntegrity/quoteAnchors';
import {recordCandidateQuoteCheckpoint,inspectCandidateQuoteCheckpoint,
 bmQuoteCheckpointWriteTarget} from '../server/commercialIntegrity/quoteCheckpointCustody';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
 process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BM strictly requires disposable CI MySQL');
const db=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>db.end());
const env=process.env;
async function quoteFixture(){
 const owner=randomUUID(),customer=randomUUID(),product=randomUUID(),quote=randomUUID();
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [owner,'bm-'+owner+'@example.invalid','CI Candidate Owner','ci_only_hash','OWNER']);
 await db.execute('INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,?,?,?,?,?,?)',
  [customer,'Phase BM Internal CI','CI Buyer','bm-'+customer+'@example.invalid','1234567890','Mumbai','Maharashtra']);
 await db.execute(`INSERT INTO crm_products
  (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,gstRate,hsn)
  VALUES (?,?,'Example','BM test server','SERVER','CI only',50,100,70,18,'8471')`,
  [product,'BM-'+product]);
 await db.execute(`INSERT INTO sales_quote_drafts
  (id,customer_id,created_by,status,currency,subtotal,tax_estimate,total_estimate)
  VALUES (?,?,?,'DRAFT','INR',100,18,118)`,[quote,customer,owner]);
 await db.execute(`INSERT INTO sales_quote_draft_items
  (id,quote_id,position,product_id,sku_snapshot,name_snapshot,hsn_snapshot,
   quantity,unit_cost,unit_price,gst_rate,line_subtotal,line_tax_estimate)
  VALUES (?,?,1,?,'BM-SKU','BM test server','8471',1,50,100,18,100,18)`,
  [randomUUID(),quote,product]);
 const digest=await sourceDigest(quote);
 return {quote,customer,owner,product,digest};
}
async function sourceDigest(quote:string){
 const [drafts]=await db.query<any[]>(
  'SELECT q.*,c.deleted_at AS customer_deleted_at FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id WHERE q.id=?',[quote]);
 const [lines]=await db.query<any[]>(
  'SELECT * FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',[quote]);
 const [revisions]=await db.query<any[]>(
  'SELECT * FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number',[quote]);
 const [decisions]=await db.query<any[]>(
  'SELECT d.*,u.role AS reviewer_role FROM sales_quote_review_decisions d JOIN auth_users u ON u.id=d.owner_user_id WHERE d.quote_id=?',[quote]);
 const [preparations]=await db.query<any[]>(
  `SELECT p.*,o.id AS outbox_id,o.event_type,o.dispatch_state,o.payload_sha256,
   (SELECT COUNT(*) FROM sales_quote_outbox_holds c WHERE c.release_preparation_id=p.id) AS outbox_count
   FROM sales_quote_release_preparations p LEFT JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id
   WHERE p.quote_id=?`,[quote]);
 return buildLocalQuoteHistoryCommitment({
  draft:drafts[0],lines,revisions,decisions,preparations}).sourceCommitmentSha256;
}
function witness(){
 const pair=generateKeyPairSync('ed25519');
 const pin:CandidatePinnedKey={keyId:'ci-witness-a',
  publicKeySpkiPem:pair.publicKey.export({type:'spki',format:'pem'}).toString(),
  validFrom:'2026-01-01T00:00:00.000Z',validUntil:'2028-01-01T00:00:00.000Z',
  status:'ACTIVE'};
 function receipt(quote:string,digest:string,seq:number,
   prev:string|null=null,at=12):CandidateWitnessReceipt{
  const body:CandidateWitnessBody={format:'aaditech-quote-history-witness-v1',
   quoteId:quote,sequence:seq,revisionNumber:0,
   sourceCommitmentSha256:digest,previousReceiptSha256:prev,
   witnessedAt:'2026-11-17T'+String(at).padStart(2,'0')+':00:00.000Z',
   keyId:pin.keyId};
  return {body,signatureBase64:sign(null,
   Buffer.from(canonicalCandidateWitnessBody(body)),
   pair.privateKey).toString('base64')};
 }
 return {pin,receipt};
}
const record=(quote:string,receipts:CandidateWitnessReceipt[],
 keys:CandidatePinnedKey[],claimedPublicationHeadSha256:string|null=null)=>
 recordCandidateQuoteCheckpoint(db,{quoteId:quote,receipts,pinnedKeys:keys,
  claimedPublicationHeadSha256,env});
const inspect=(quote:string)=>inspectCandidateQuoteCheckpoint(db,quote,env);
test('BM migration/writes are denied for production and non-TLS/unapproved staging',()=>{
 for(const e of [
  {NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'},
  {NODE_ENV:'production',DB_SSL:'true',DB_NAME:'aaditech_staging_ci',BM_QUOTE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {DB_NAME:'aaditech_staging_ci',BM_QUOTE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'false'},
  {NODE_ENV:'test',CRM_TEST_DB:'1',DB_NAME:'aaditech_staging_ci'},
  {DB_NAME:'aaditech_production',DB_SSL:'true',BM_QUOTE_WRITE_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'}
 ])assert.throws(()=>bmQuoteCheckpointWriteTarget(e as NodeJS.ProcessEnv));
 assert.equal(bmQuoteCheckpointWriteTarget(env),'ci');
});
test('BM persistent candidate genesis, extension, exact replay and readback are never authority',async()=>{
 const x=await quoteFixture(),w=witness();
 const r1=w.receipt(x.quote,x.digest,1);
 assert.equal((await record(x.quote,[r1],[w.pin])).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(x.quote,[r1],[w.pin])).outcome,'REPLAY');
 const a=await inspect(x.quote);
 assert.equal(a.candidateCheckpointSequence,1);
 assert.equal(a.candidateCheckpointGovernanceState,'HELD_UNVERIFIED');
 assert.equal(a.candidateCheckpointLocallyConsistent,true,a.candidateCheckpointAnomalyCodes.join(','));
 const r2=w.receipt(x.quote,x.digest,2,candidateWitnessReceiptDigest(r1),13);
 assert.equal((await record(x.quote,[r1,r2],[w.pin],
  candidateWitnessReceiptDigest(r2))).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(x.quote,[r1,r2],[w.pin])).outcome,'REPLAY');
 const b=await inspect(x.quote);
 assert.equal(b.candidateCheckpointSequence,2);
 assert.equal(b.candidateCheckpointAttemptCount,2);
 assert.equal(b.independentlyAuthenticatedWitness,false);
 assert.equal(b.externallyPublishedCheckpointVerified,false);
 assert.equal(b.authenticatedRevocationEvidence,false);
 assert.equal(b.productionReleaseAuthorized,false);
 assert.equal(b.releaseDecision,'HOLD');
});
test('BM concurrent signed fork serializes to one accepted head and sticky quarantine',async()=>{
 const x=await quoteFixture(),w=witness(),r1=w.receipt(x.quote,x.digest,1);
 await record(x.quote,[r1],[w.pin]);
 const parent=candidateWitnessReceiptDigest(r1);
 const a=w.receipt(x.quote,x.digest,2,parent,13);
 const b=w.receipt(x.quote,x.digest,2,parent,14);
 const outcomes=(await Promise.all([
  record(x.quote,[r1,a],[w.pin]),record(x.quote,[r1,b],[w.pin])
 ])).map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const audit=await inspect(x.quote);
 assert.equal(audit.candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal(audit.candidateCheckpointSequence,2);
 assert.equal(audit.candidateCheckpointLocallyConsistent,true,audit.candidateCheckpointAnomalyCodes.join(','));
 const r3=w.receipt(x.quote,x.digest,3,
  audit.candidateCheckpointReceiptSha256!,15);
 const prefix=audit.candidateCheckpointReceiptSha256===candidateWitnessReceiptDigest(a)?
  [r1,a,r3]:[r1,b,r3];
 assert.equal((await record(x.quote,prefix,[w.pin])).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateCheckpointSequence,2);
});
test('BM replay of old valid signed version and rollback incident cannot update candidate head',async()=>{
 const x=await quoteFixture(),w=witness(),a=w.receipt(x.quote,x.digest,1);
 await record(x.quote,[a],[w.pin]);
 const b=w.receipt(x.quote,x.digest,2,candidateWitnessReceiptDigest(a),13);
 await record(x.quote,[a,b],[w.pin]);
 assert.equal((await record(x.quote,[a],[w.pin])).outcome,'DUPLICATE_REJECTED');
 const differentOld=w.receipt(x.quote,x.digest,1,null,14);
 assert.equal((await record(x.quote,[differentOld],[w.pin])).outcome,'ROLLBACK_QUARANTINED');
 const r=await inspect(x.quote);
 assert.equal(r.candidateCheckpointSequence,2);
 assert.equal(r.candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal(r.candidateCheckpointLocallyConsistent,true);
});
test('BM mismatched claimed publication head quarantines without authenticating publication',async()=>{
 const x=await quoteFixture(),w=witness(),r=w.receipt(x.quote,x.digest,1);
 const outcome=await record(x.quote,[r],[w.pin],'f'.repeat(64));
 assert.equal(outcome.outcome,'PUBLICATION_MISMATCH_QUARANTINED');
 const report=await inspect(x.quote);
 assert.equal(report.candidateCheckpointSequence,0);
 assert.equal(report.candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal(report.externallyPublishedCheckpointVerified,false);
});
test('BM signed revocation claim freezes local candidate without external revocation proof',async()=>{
 const x=await quoteFixture(),w=witness(),r=w.receipt(x.quote,x.digest,1);
 await record(x.quote,[r],[w.pin]);
 const r2=w.receipt(x.quote,x.digest,2,candidateWitnessReceiptDigest(r),13);
 const rev={...w.pin,status:'REVOKED' as const};
 assert.equal((await record(x.quote,[r,r2],[rev])).outcome,'REVOCATION_CLAIM_QUARANTINED');
 const audit=await inspect(x.quote);
 assert.equal(audit.candidateCheckpointSequence,1);
 assert.equal(audit.candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal(audit.authenticatedRevocationEvidence,false);
});
test('BM changed MySQL quote HSN mismatches previously signed source and freezes, even after restoration',async()=>{
 const x=await quoteFixture(),w=witness(),r=w.receipt(x.quote,x.digest,1);
 await record(x.quote,[r],[w.pin]);
 try{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['9999',x.quote]);
  const drift=await inspect(x.quote);
  assert.equal(drift.candidateCheckpointLocallyConsistent,false);
  assert.ok(drift.candidateCheckpointAnomalyCodes.includes('CHECKPOINT_SOURCE_HEAD_DRIFT'));
  const attempted=w.receipt(x.quote,x.digest,2,candidateWitnessReceiptDigest(r),13);
  assert.equal((await record(x.quote,[r,attempted],[w.pin])).outcome,'SOURCE_MISMATCH_QUARANTINED');
 }finally{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 const audit=await inspect(x.quote);
 assert.equal(audit.candidateCheckpointLocallyConsistent,true,audit.candidateCheckpointAnomalyCodes.join(','));
 assert.equal(audit.candidateCheckpointGovernanceState,'QUARANTINED');
 assert.equal(audit.productionReleaseAuthorized,false);
});
test('BM stored candidate checkpoint head forgery is detected, restoration does not create trust',async()=>{
 const x=await quoteFixture(),w=witness(),r=w.receipt(x.quote,x.digest,1);
 await record(x.quote,[r],[w.pin]);
 try{
  await db.execute('UPDATE quote_bm_candidate_checkpoint_streams SET last_receipt_sha256=? WHERE quote_id=?',
   ['f'.repeat(64),x.quote]);
  const corrupted=await inspect(x.quote);
  assert.equal(corrupted.candidateCheckpointLocallyConsistent,false);
  assert.ok(corrupted.candidateCheckpointAnomalyCodes.includes('CHECKPOINT_HEAD_HISTORY_DIVERGENCE'));
  await assert.rejects(record(x.quote,[r],[w.pin]),/inconsistent candidate checkpoint ledger/);
 }finally{
  await db.execute('UPDATE quote_bm_candidate_checkpoint_streams SET last_receipt_sha256=? WHERE quote_id=?',
   [candidateWitnessReceiptDigest(r),x.quote]);
 }
 assert.equal((await inspect(x.quote)).candidateCheckpointLocallyConsistent,true);
 const [rows]=await db.query<any[]>(
  'SELECT independent_publication_verified,independent_revocation_verified,external_worm_verified,production_release FROM quote_bm_candidate_checkpoint_streams WHERE quote_id=?',[x.quote]);
 assert.equal(rows[0].independent_publication_verified,'NO');
 assert.equal(rows[0].independent_revocation_verified,'NO');
 assert.equal(rows[0].external_worm_verified,'NO');
 assert.equal(rows[0].production_release,'HOLD');
});
test('BM substituted pin, invalid signature and absent quote cannot be persisted',async()=>{
 const x=await quoteFixture(),w=witness(),r=w.receipt(x.quote,x.digest,1);
 const other=witness();
 const [badRows]=await db.query<any[]>(
  'SELECT COUNT(*) AS n FROM quote_bm_candidate_checkpoint_streams WHERE quote_id=?',[x.quote]);
 assert.equal(Number(badRows[0].n),0);
 await assert.rejects(record(x.quote,[r],[other.pin]),/candidate signature/);
 const forged=structuredClone(r);forged.signatureBase64=Buffer.alloc(64,8).toString('base64');
 await assert.rejects(record(x.quote,[forged],[w.pin]),/candidate signature/);
 await assert.rejects(record(randomUUID(),[r],[w.pin]),/unbound witness receipt/);
 const [stillRows]=await db.query<any[]>(
  'SELECT COUNT(*) AS n FROM quote_bm_candidate_checkpoint_streams WHERE quote_id=?',[x.quote]);
 assert.equal(Number(stillRows[0].n),0);
});
