import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {buildLocalQuoteHistoryCommitment,canonicalCandidateWitnessBody,
 candidateWitnessReceiptDigest,type CandidatePinnedKey} from '../server/commercialIntegrity/quoteAnchors';
import {canonicalCandidateQuoteObservation,canonicalCandidateQuoteRollover,
 assessCandidateQuoteHeadReconciliation,type CandidateHeadObservation,
 type CandidateHeadObservationBody,type CandidateKeyRolloverBody}
 from '../server/commercialIntegrity/quoteHeadReconciliation';
import {recordCandidateQuoteCheckpoint,inspectCandidateQuoteCheckpoint,
 inspectCandidateQuoteCheckpointOnConnection}
 from '../server/commercialIntegrity/quoteCheckpointCustody';
import {recordCandidateQuoteReconciliation,inspectCandidateQuoteReconciliation,
 inspectCandidateQuoteReconciliationOnConnection,bnReconciliationWriteTarget}
 from '../server/commercialIntegrity/quoteReconciliationCustody';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BN only operates on disposable CI MySQL');
const pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:8});
after(async()=>pool.end());
const env=process.env,now=new Date('2026-11-17T12:05:00.000Z');
const sha=(c:string)=>c.repeat(64);
const clone=<T>(v:T):T=>structuredClone(v);
function key(id:string){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pin:CandidatePinnedKey={keyId:id,
  publicKeySpkiPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  status:'ACTIVE',validFrom:'2026-01-01T00:00:00.000Z',
  validUntil:'2028-01-01T00:00:00.000Z'};
 return {pin,privateKey};
}
async function fixture(){
 const user=randomUUID(),customer=randomUUID(),product=randomUUID(),quote=randomUUID();
 await pool.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [user,'bn-'+user+'@example.invalid','BN synthetic owner','ci-only-placeholder','OWNER']);
 await pool.execute('INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,?,?,?,?,?,?)',
  [customer,'BN candidate customer','Fixture','bn-'+customer+'@example.invalid',
   '9876543210','Mumbai','Maharashtra']);
 await pool.execute(`INSERT INTO crm_products
  (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,gstRate,hsn)
  VALUES (?,?,'Candidate','BN proof server','SERVER','no real stock',
   50,100,70,18,'8471')`,
  [product,'BN-'+product]);
 await pool.execute(`INSERT INTO sales_quote_drafts
  (id,customer_id,created_by,status,currency,subtotal,tax_estimate,total_estimate)
  VALUES (?,?,?,'DRAFT','INR',100,18,118)`,[quote,customer,user]);
 await pool.execute(`INSERT INTO sales_quote_draft_items
  (id,quote_id,position,product_id,sku_snapshot,name_snapshot,hsn_snapshot,
  quantity,unit_cost,unit_price,gst_rate,line_subtotal,line_tax_estimate)
  VALUES (?,?,1,?,'BN-SKU','BN proof server','8471',1,50,100,18,100,18)`,
  [randomUUID(),quote,product]);
 const [draft]=await pool.query<any[]>(
  'SELECT q.*,c.deleted_at AS customer_deleted_at FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id WHERE q.id=?',[quote]);
 const [lines]=await pool.query<any[]>(
  'SELECT * FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',[quote]);
 const digest=buildLocalQuoteHistoryCommitment({draft:draft[0],lines,
  revisions:[],decisions:[],preparations:[]}).sourceCommitmentSha256;
 const bm=key('checkpoint-fixture');
 const body={format:'aaditech-quote-history-witness-v1' as const,quoteId:quote,
  sequence:1,revisionNumber:0,sourceCommitmentSha256:digest,
  previousReceiptSha256:null,witnessedAt:'2026-11-17T11:55:00.000Z',
  keyId:bm.pin.keyId};
 const receipt={body,signatureBase64:sign(null,
  Buffer.from(canonicalCandidateWitnessBody(body)),bm.privateKey).toString('base64')};
 assert.equal((await recordCandidateQuoteCheckpoint(pool,{
  quoteId:quote,receipts:[receipt],pinnedKeys:[bm.pin],env
 })).outcome,'RECORDED_UNVERIFIED');
 return {quote,digest,receiptSha:candidateWitnessReceiptDigest(receipt)};
}
const sourceA=key('witness-a'),sourceB=key('witness-b'),sourceC=key('witness-rotated');
function observation(q:{quote:string,digest:string,receiptSha:string},
 w:ReturnType<typeof key>,sourceId:string,changed:Partial<CandidateHeadObservationBody>={}){
 const body:CandidateHeadObservationBody={
  format:'aaditech-quote-head-observation-v1',quoteId:q.quote,sourceId,
  keyId:w.pin.keyId,sequence:1,receiptSha256:q.receiptSha,
  sourceSha256:q.digest,publishedAt:'2026-11-17T12:00:00.000Z',
  observedAt:'2026-11-17T12:04:00.000Z',revocationEpoch:4,
  revokedKeyIds:[],revocationThisUpdate:'2026-11-17T11:50:00.000Z',
  revocationNextUpdate:'2026-11-17T12:20:00.000Z',...changed};
 return {body,signatureBase64:sign(null,
  Buffer.from(canonicalCandidateQuoteObservation(body)),w.privateKey).toString('base64')};
}
function packet(x:Awaited<ReturnType<typeof fixture>>,change?:{
 a?:Partial<CandidateHeadObservationBody>,b?:Partial<CandidateHeadObservationBody>}){
 return [observation(x,sourceA,'witness-operator-one',change?.a),
  observation(x,sourceB,'witness-operator-two',change?.b)];
}
const keys=[sourceA.pin,sourceB.pin];
const record=(quote:string,revision:number,previousPacketSha256:string|null,
 observations:CandidateHeadObservation[],pinnedKeys:CandidatePinnedKey[]=keys,
 extra:Record<string,unknown>={})=>recordCandidateQuoteReconciliation(pool,{
 quoteId:quote,revision,previousPacketSha256,observations,pinnedKeys,now,env,...extra
});
const inspect=(quote:string)=>inspectCandidateQuoteReconciliation(pool,quote,env);
test('BN write target explicitly denies production, unapproved and non-TLS staging',()=>{
 assert.throws(()=>bnReconciliationWriteTarget({NODE_ENV:'production',
  CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'} as NodeJS.ProcessEnv));
 assert.throws(()=>bnReconciliationWriteTarget({NODE_ENV:'development',
  DB_NAME:'aaditech_staging_candidate',DB_SSL:'true',
  STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES'} as NodeJS.ProcessEnv));
 assert.throws(()=>bnReconciliationWriteTarget({NODE_ENV:'development',
  DB_NAME:'aaditech_staging_candidate',DB_SSL:'false',
  STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
  BN_RECONCILIATION_WRITE_APPROVED:'YES'} as NodeJS.ProcessEnv));
 assert.equal(bnReconciliationWriteTarget(env),'ci');
});
test('BN new candidate local quorum genesis, repeat, monotonic revision and denial of authority',async()=>{
 const x=await fixture(),claims=packet(x);
 assert.equal((await record(x.quote,1,null,claims)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await record(x.quote,1,null,claims)).outcome,'REPLAY');
 const first=await inspect(x.quote);
 assert.equal(first.candidateReconciliationRevision,1);
 assert.equal(first.candidateReconciliationLocallyConsistent,true,
  first.candidateReconciliationAnomalyCodes.join(','));
 const prior=first.candidateReconciliationPacketSha256!;
 assert.equal((await record(x.quote,2,prior,claims)).outcome,'RECORDED_UNVERIFIED');
 const report=await inspect(x.quote);
 assert.equal(report.candidateReconciliationRevision,2);
 assert.equal(report.candidateReconciliationAttemptCount,2);
 assert.equal(report.independentHeadAuthenticated,false);
 assert.equal(report.independentRevocationAuthenticated,false);
 assert.equal(report.realEncryptedDrWitnessed,false);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.releaseDecision,'HOLD');
});
test('BN two concurrent properly signed conflicting reconciliations serialize and freeze',async()=>{
 const x=await fixture(),first=packet(x),
  second=packet(x,{a:{observedAt:'2026-11-17T12:03:00.000Z'},
   b:{observedAt:'2026-11-17T12:03:00.000Z'}});
 const outcomes=(await Promise.all([
  record(x.quote,1,null,first),record(x.quote,1,null,second)
 ])).map(r=>r.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const state=await inspect(x.quote);
 assert.equal(state.candidateReconciliationGovernanceState,'QUARANTINED');
 assert.equal(state.candidateReconciliationRevision,1);
 assert.equal(state.candidateReconciliationLocallyConsistent,true,
  state.candidateReconciliationAnomalyCodes.join(','));
 assert.equal((await record(x.quote,2,state.candidateReconciliationPacketSha256!,
  first)).outcome,'POST_INCIDENT_QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateReconciliationGovernanceState,'QUARANTINED');
});
test('BN conflict in two claimed revocation sources quarantines; still not real CRL',async()=>{
 const x=await fixture(),claims=packet(x,{b:{revocationEpoch:5}});
 assert.equal((await record(x.quote,1,null,claims)).outcome,'CLAIM_CONFLICT_QUARANTINED');
 const state=await inspect(x.quote);
 assert.equal(state.candidateReconciliationRevision,0);
 assert.equal(state.candidateReconciliationGovernanceState,'QUARANTINED');
 assert.equal(state.candidateReconciliationLocallyConsistent,true);
 assert.equal(state.independentRevocationAuthenticated,false);
});
test('BN local candidate pin change requires out-of-band approval despite valid dual rollover signatures',async()=>{
 const x=await fixture(),claims=packet(x);
 await record(x.quote,1,null,claims);
 const prior=(await inspect(x.quote)).candidateReconciliationPacketSha256!;
 const body:CandidateKeyRolloverBody={
  format:'aaditech-quote-key-rollover-v1',quoteId:x.quote,
  oldKeyId:sourceA.pin.keyId,newKeyId:sourceC.pin.keyId,
  receiptSha256:x.receiptSha,effectiveAt:'2026-11-17T12:02:00.000Z',
  reason:'Signed fixture rollover, not external authority'
 };
 const rollover={body,oldSignatureBase64:sign(null,
  Buffer.from(canonicalCandidateQuoteRollover(body)),
  sourceA.privateKey).toString('base64'),
  newSignatureBase64:sign(null,Buffer.from(canonicalCandidateQuoteRollover(body)),
   sourceC.privateKey).toString('base64')};
 assert.equal((await record(x.quote,2,prior,claims,
  [...keys,sourceC.pin],{rollover})).outcome,
  'PINSET_ROLLOVER_UNVERIFIED_QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateReconciliationGovernanceState,'QUARANTINED');
});
test('BN candidate revocation-epoch regression quarantines even when signatures valid',async()=>{
 const x=await fixture(),claims=packet(x);
 await record(x.quote,1,null,claims);
 const prior=(await inspect(x.quote)).candidateReconciliationPacketSha256!;
 const older=packet(x,{a:{revocationEpoch:3},b:{revocationEpoch:3}});
 assert.equal((await record(x.quote,2,prior,older)).outcome,
  'REVOCATION_REGRESSION_QUARANTINED');
 assert.equal((await inspect(x.quote)).candidateReconciliationRevision,1);
});
test('BN DR rollback rehearsal on actual MySQL transaction never writes stock or acceptance',async()=>{
 const x=await fixture(),claims=packet(x);
 await record(x.quote,1,null,claims);
 const original=await inspectCandidateQuoteCheckpoint(pool,x.quote,env);
 assert.equal(original.candidateCheckpointSequence,1);
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // Simulate an older restored checkpoint in an UNCOMMITTED transaction.
  // No actual DR provider or remote backup is accessed.
  await conn.execute('UPDATE quote_bm_candidate_checkpoint_streams SET last_sequence=0,last_receipt_sha256=NULL,last_source_sha256=NULL,last_pinset_sha256=NULL,last_revision_number=0 WHERE quote_id=?',
   [x.quote]);
  const modified=await inspectCandidateQuoteCheckpointOnConnection(conn,x.quote,null);
  assert.equal(modified.candidateCheckpointLocallyConsistent,false);
  assert.ok(modified.candidateCheckpointAnomalyCodes.includes('CHECKPOINT_HEAD_HISTORY_DIVERGENCE'));
  const audit=await inspectCandidateQuoteReconciliationOnConnection(conn,x.quote,modified);
  assert.equal(audit.candidateReconciliationLocallyConsistent,false);
  assert.ok(audit.candidateReconciliationAnomalyCodes.includes(
   'BN_RECONCILIATION_UPSTREAM_CHECKPOINT_CHANGED'));
  const simulation=assessCandidateQuoteHeadReconciliation({
   quoteId:x.quote,checkpointSequence:original.candidateCheckpointSequence,
   checkpointReceiptSha256:original.candidateCheckpointReceiptSha256!,
   checkpointSourceSha256:original.candidateCheckpointSourceSha256!,
   observations:claims,pinnedKeys:keys,now,
   recoverySnapshot:{sequence:0,receiptSha256:sha('c'),sourceSha256:sha('d')}
  });
  assert.ok(simulation.candidateReconciliationAnomalyCodes.includes(
   'BN_DR_REHEARSAL_ROLLBACK_DETECTED'));
  assert.equal(simulation.realEncryptedDrRecoveryWitnessed,false);
 }finally{await conn.rollback().catch(()=>{});conn.release();}
 const restored=await inspect(x.quote);
 assert.equal(restored.candidateReconciliationLocallyConsistent,true,
  restored.candidateReconciliationAnomalyCodes.join(','));
 assert.equal(restored.productionReleaseAuthorized,false);
});
test('BN local stored head drift detected and refused until repaired, never authorized',async()=>{
 const x=await fixture(),claims=packet(x);
 await record(x.quote,1,null,claims);
 const first=await inspect(x.quote);
 try{
  await pool.execute('UPDATE quote_bn_candidate_reconciliation_streams SET last_packet_sha256=? WHERE quote_id=?',
   [sha('f'),x.quote]);
  const wrong=await inspect(x.quote);
  assert.equal(wrong.candidateReconciliationLocallyConsistent,false);
  assert.ok(wrong.candidateReconciliationAnomalyCodes.includes(
   'BN_RECONCILIATION_HEAD_HISTORY_DIVERGENCE'));
  await assert.rejects(record(x.quote,2,first.candidateReconciliationPacketSha256!,
   claims),/persisted candidate reconciliation history inconsistent/);
 }finally{
  await pool.execute('UPDATE quote_bn_candidate_reconciliation_streams SET last_packet_sha256=? WHERE quote_id=?',
   [first.candidateReconciliationPacketSha256,x.quote]);
 }
 const repaired=await inspect(x.quote);
 assert.equal(repaired.candidateReconciliationLocallyConsistent,true);
 assert.equal(repaired.independentHeadAuthenticated,false);
});
test('BN changed underlying quotation HSN detected against both BM and BN witness history',async()=>{
 const x=await fixture(),claims=packet(x);
 await record(x.quote,1,null,claims);
 try{
  await pool.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['0000',x.quote]);
  const alarm=await inspect(x.quote);
  assert.equal(alarm.candidateReconciliationLocallyConsistent,false);
  assert.ok(alarm.candidateReconciliationAnomalyCodes.includes(
   'BN_RECONCILIATION_UPSTREAM_CHECKPOINT_CHANGED'));
 }finally{
  await pool.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 const state=await inspect(x.quote);
 assert.equal(state.candidateReconciliationLocallyConsistent,true);
 assert.equal(state.productionReleaseAuthorized,false);
});
