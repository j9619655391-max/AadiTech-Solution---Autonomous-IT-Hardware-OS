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
import {issueCandidateIntakeChallenge,recordCandidateEvidenceIntake,
 inspectCandidateEvidenceIntake,readCandidateIntakeExpectedUnderLock,
 inspectCandidateEvidenceIntakeOnConnection,bpCandidateIntakeWriteTarget}
 from '../server/commercialIntegrity/quoteEvidenceCustody';
import {candidateIntakePacketDigest} from '../server/commercialIntegrity/quoteEvidenceIntake';
import {bpNow,bpSha,bpPins,bpPinsetSha,bpPacketFixture,bpResign,bpClone}
 from './bp-intake-fixtures';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BP strictly requires disposable isolated CI MySQL');
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


const bpEnv:NodeJS.ProcessEnv={...env,BP_INTAKE_PINSET_SHA256:bpPinsetSha};
async function bpFixture(){
 const upstream=await fixture();
 const dossier=boDossierFixture(upstream.expected);
 assert.equal((await record(upstream,1,null,dossier)).outcome,'RECORDED_UNVERIFIED');
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateIntakeExpectedUnderLock(conn,upstream.quote);
  await conn.commit();
  assert.equal(expected.boLocallyConsistent,true);
  assert.equal(expected.boDossierSha256,candidateExternalAuthorityDossierDigest(dossier));
  return {quote:upstream.quote,expected};
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
const nonce=async(quote:string,now=new Date('2026-11-17T14:58:00.000Z'))=>
 issueCandidateIntakeChallenge(db,{quoteId:quote,env:bpEnv,now});
const put=(quote:string,version:number,previousPacketSha256:string|null,
 packet:ReturnType<typeof bpPacketFixture>,envOverride:NodeJS.ProcessEnv=bpEnv)=>
 recordCandidateEvidenceIntake(db,{quoteId:quote,version,previousPacketSha256,
  packet,pinnedKeys:bpPins,env:envOverride,now:bpNow});
const examine=(quote:string)=>inspectCandidateEvidenceIntake(db,quote,bpEnv);

test('BP rejects production, unauthorized or non-TLS staging and non-enrolled pinset',async()=>{
 for(const e of [
  {NODE_ENV:'production',DB_NAME:'aaditech_ci',CRM_TEST_DB:'1'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_ci',DB_SSL:'false',
   BM_QUOTE_WRITE_APPROVED:'YES',BN_RECONCILIATION_WRITE_APPROVED:'YES',
   BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',BP_INTAKE_WRITE_APPROVED:'YES',
   STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_ci',DB_SSL:'true',
   BM_QUOTE_WRITE_APPROVED:'YES',BN_RECONCILIATION_WRITE_APPROVED:'YES',
   BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   STAGING_DISPOSABLE_CONFIRMED:'YES'}
 ])assert.throws(()=>bpCandidateIntakeWriteTarget(e as NodeJS.ProcessEnv));
 assert.equal(bpCandidateIntakeWriteTarget(bpEnv),'ci');
 const x=await bpFixture(),c=await nonce(x.quote);
 const p=bpPacketFixture(x.expected,c.challengeSha256);
 await assert.rejects(put(x.quote,1,null,p,{...bpEnv,
  BP_INTAKE_PINSET_SHA256:boFixtureSha('f')}),/pin substitution refused/);
 const a=await examine(x.quote);
 assert.equal(a.candidateIntakeVersion,0);
});
test('BP server issued nonce, candidate four-role signed genesis, replay and extension remain HOLD',async()=>{
 const x=await bpFixture(),c1=await nonce(x.quote);
 const p1=bpPacketFixture(x.expected,c1.challengeSha256);
 assert.equal((await put(x.quote,1,null,p1)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await put(x.quote,1,null,p1)).outcome,'REPLAY');
 const audit=await examine(x.quote);
 assert.equal(audit.candidateIntakeVersion,1);
 assert.equal(audit.candidateIntakeLocallyConsistent,true,
  audit.candidateIntakeAnomalyCodes.join(','));
 assert.equal(audit.authenticatedExternalKeyEnrollment,false);
 assert.equal(audit.trustedIndependentHeadRetrieved,false);
 assert.equal(audit.productionReleaseAuthorized,false);
 const c2=await nonce(x.quote);
 const p2=bpPacketFixture(x.expected,c2.challengeSha256);
 assert.equal((await put(x.quote,2,audit.candidateIntakePacketSha256!,p2)).outcome,
  'RECORDED_UNVERIFIED');
 const next=await examine(x.quote);
 assert.equal(next.candidateIntakeVersion,2);
 assert.equal(next.candidateIntakeAttemptCount,2);
 assert.equal(next.releaseDecision,'HOLD');
 const [r]=await db.query<any[]>('SELECT trusted_external_key_enrollment,independent_head_retrieved,crl_ocsp_authority_verified,real_worm_delete_denial_verified,actual_dr_witnessed,production_release FROM quote_bp_candidate_intake_streams WHERE quote_id=?',[x.quote]);
 assert.deepEqual([r[0].trusted_external_key_enrollment,r[0].independent_head_retrieved,
  r[0].crl_ocsp_authority_verified,r[0].real_worm_delete_denial_verified,
  r[0].actual_dr_witnessed,r[0].production_release],
  ['NO','NO','NO','NO','NO','HOLD']);
});
test('BP two concurrent separately signed candidate heads serialize and permanently quarantine',async()=>{
 const x=await bpFixture(),a=await nonce(x.quote),b=await nonce(x.quote);
 const p1=bpPacketFixture(x.expected,a.challengeSha256);
 const p2=bpPacketFixture(x.expected,b.challengeSha256);
 const results=(await Promise.all([
  put(x.quote,1,null,p1),put(x.quote,1,null,p2)
 ])).map(x=>x.outcome).sort();
 assert.deepEqual(results,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const report=await examine(x.quote);
 assert.equal(report.candidateIntakeVersion,1);
 assert.equal(report.candidateIntakeGovernanceState,'QUARANTINED');
 assert.equal(report.candidateIntakeLocallyConsistent,true,
  report.candidateIntakeAnomalyCodes.join(','));
 await assert.rejects(nonce(x.quote),/challenge issuance denied by local incident/);
});
test('BP reused server challenge with different signed head quarantines, not a valid replay',async()=>{
 const x=await bpFixture(),c=await nonce(x.quote);
 const p=bpPacketFixture(x.expected,c.challengeSha256);
 assert.equal((await put(x.quote,1,null,p)).outcome,'RECORDED_UNVERIFIED');
 const changed=bpResign(p,'ISSUER',{crlSha256:bpSha('f')});
 assert.equal((await put(x.quote,2,candidateIntakePacketDigest(p),changed)).outcome,
  'CHALLENGE_REPLAY_QUARANTINED');
 const audit=await examine(x.quote);
 assert.equal(audit.candidateIntakeGovernanceState,'QUARANTINED');
 assert.equal(audit.candidateIntakeVersion,1);
 assert.equal(audit.candidateIntakeLocallyConsistent,true,
  audit.candidateIntakeAnomalyCodes.join(','));
});
test('BP expired server nonce is frozen even with cryptographically correct four-role signatures',async()=>{
 const x=await bpFixture(),c=await nonce(x.quote,new Date('2026-11-17T14:00:00.000Z'));
 const packet=bpPacketFixture(x.expected,c.challengeSha256);
 assert.equal((await put(x.quote,1,null,packet)).outcome,'CHALLENGE_REPLAY_QUARANTINED');
 const r=await examine(x.quote);
 assert.equal(r.candidateIntakeGovernanceState,'QUARANTINED');
 assert.equal(r.candidateIntakeVersion,0);
 assert.equal(r.candidateIntakeLocallyConsistent,true);
});
test('BP detached signature forgery cannot create accepted candidate evidence',async()=>{
 const x=await bpFixture(),c=await nonce(x.quote);
 const p=bpClone(bpPacketFixture(x.expected,c.challengeSha256));
 p.claims[0].signatureBase64=Buffer.alloc(64,7).toString('base64');
 await assert.rejects(put(x.quote,1,null,p),/unsigned or malformed/);
 const state=await examine(x.quote);
 assert.equal(state.candidateIntakeVersion,0);
 assert.equal(state.candidateIntakeGovernanceState,'HELD_UNVERIFIED');
});
test('BP cross-source revocation disagreement, fake WORM deletion or restored fork quarantine',async()=>{
 const changes=[
  {revocationEpoch:5},{crlSha256:bpSha('e')},
  {deleteDenied:false},{restoredReceiptSha256:bpSha('e')},
  {publicationHeadSha256:bpSha('f')}
 ];
 for(const change of changes){
  const x=await bpFixture(),c=await nonce(x.quote);
  const p=bpResign(bpPacketFixture(x.expected,c.challengeSha256),
   'ISSUER',change);
  assert.equal((await put(x.quote,1,null,p)).outcome,
   'CROSS_SOURCE_CONFLICT_QUARANTINED');
  const report=await examine(x.quote);
  assert.equal(report.candidateIntakeLocallyConsistent,true,
   report.candidateIntakeAnomalyCodes.join(','));
  assert.equal(report.candidateIntakeGovernanceState,'QUARANTINED');
  assert.equal(report.productionReleaseAuthorized,false);
 }
});
test('BP forged BO dossier head and quote HSN source drift are detected and remain non-authoritative',async()=>{
 const x=await bpFixture(),c=await nonce(x.quote);
 const p=bpPacketFixture(x.expected,c.challengeSha256);
 await put(x.quote,1,null,p);
 const original=await examine(x.quote);
 assert.equal(original.candidateIntakeLocallyConsistent,true);
 try{
  await db.execute('UPDATE quote_bo_candidate_authority_streams SET last_dossier_sha256=? WHERE quote_id=?',
   [bpSha('f'),x.quote]);
  const drift=await examine(x.quote);
  assert.equal(drift.candidateIntakeLocallyConsistent,false);
  assert.ok(drift.candidateIntakeAnomalyCodes.includes('BP_UPSTREAM_BO_BN_BM_DRIFT'));
 }finally{
  await db.execute('UPDATE quote_bo_candidate_authority_streams SET last_dossier_sha256=? WHERE quote_id=?',
   [x.expected.boDossierSha256,x.quote]);
 }
 try{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['0000',x.quote]);
  const drift=await examine(x.quote);
  assert.equal(drift.candidateIntakeLocallyConsistent,false);
  assert.ok(drift.candidateIntakeAnomalyCodes.includes('BP_UPSTREAM_BO_BN_BM_DRIFT'));
 }finally{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 assert.equal((await examine(x.quote)).candidateIntakeLocallyConsistent,true);
 assert.equal((await examine(x.quote)).productionReleaseAuthorized,false);
});
test('BP forged local stream packet and missing consumed challenge are detected under actual MySQL',async()=>{
 const x=await bpFixture(),c=await nonce(x.quote);
 const p=bpPacketFixture(x.expected,c.challengeSha256);
 await put(x.quote,1,null,p);
 try{
  await db.execute('UPDATE quote_bp_candidate_intake_streams SET last_packet_sha256=? WHERE quote_id=?',
   [bpSha('f'),x.quote]);
  const drift=await examine(x.quote);
  assert.ok(drift.candidateIntakeAnomalyCodes.includes('BP_HEAD_EVENT_HISTORY_MISMATCH'));
  await assert.rejects(put(x.quote,2,null,p),/local intake history corrupt/);
 }finally{
  await db.execute('UPDATE quote_bp_candidate_intake_streams SET last_packet_sha256=? WHERE quote_id=?',
   [candidateIntakePacketDigest(p),x.quote]);
 }
 try{
  await db.execute("UPDATE quote_bp_candidate_intake_challenges SET status='ISSUED',consumed_packet_sha256=NULL WHERE quote_id=? AND challenge_sha256=?",
   [x.quote,c.challengeSha256]);
  const alarm=await examine(x.quote);
  assert.equal(alarm.candidateIntakeLocallyConsistent,false);
  assert.ok(alarm.candidateIntakeAnomalyCodes.includes(
   'BP_CHALLENGE_NOT_CONSUMED_OR_MISMATCHED'));
 }finally{
  await db.execute("UPDATE quote_bp_candidate_intake_challenges SET status='CONSUMED',consumed_packet_sha256=? WHERE quote_id=? AND challenge_sha256=?",
   [candidateIntakePacketDigest(p),x.quote,c.challengeSha256]);
 }
 assert.equal((await examine(x.quote)).candidateIntakeLocallyConsistent,true);
});
