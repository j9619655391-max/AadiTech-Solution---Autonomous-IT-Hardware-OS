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
import {issueCandidateRemoteChallenge,recordCandidateRemoteEvidence,
 inspectCandidateRemoteEvidence,readCandidateRemoteExpectedUnderLock,
 inspectCandidateRemoteEvidenceOnConnection,bqRemoteWriteTarget}
 from '../server/commercialIntegrity/quoteRemoteCustody';
import {candidateRemotePacketDigest} from '../server/commercialIntegrity/quoteRemoteEvidence';
import {bqNow,bqSha,bqRoot,bqRootSha,bqCollectors,bqCollectorsSha,
 bqEndpoints,bqEndpointsSha,bqPacketFixture,bqResignCapture,
 bqResignManifest,bqClone}
 from './bq-remote-fixtures';
import {readCandidateByteExpectedUnderLock,recordCandidateProviderBytes,
 inspectCandidateProviderBytes,inspectCandidateProviderBytesOnConnection,
 brCandidateByteWriteTarget}
 from '../server/commercialIntegrity/quoteByteCustody';
import {candidateBytePacketDigest}
 from '../server/commercialIntegrity/quoteProviderBytes';
import {brFixture,brNow,brRootPem,brRootSha,brOrigin,brHex,brClone}
 from './br-provider-byte-fixtures';
import {readCandidateSignedRevocationExpectedUnderLock,
 recordCandidateSignedRevocation,inspectCandidateSignedRevocation,
 inspectCandidateSignedRevocationOnConnection,
 bsSignedRevocationWriteTarget}
 from '../server/commercialIntegrity/quoteRevocationCustody';
import {bsSignedFixture,bsNow,type BsFixtureOptions}
 from './bs-revocation-fixtures';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BS strictly requires disposable isolated CI MySQL');
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


const bqEnv:NodeJS.ProcessEnv={...env,BQ_REGISTRAR_PIN_SHA256:bqRootSha,
 BQ_COLLECTOR_PINSET_SHA256:bqCollectorsSha,
 BQ_ENDPOINT_CONFIG_SHA256:bqEndpointsSha};
async function bqFixture(){
 const x=await bpFixture();
 const bpNonce=await nonce(x.quote);
 const signed=bpPacketFixture(x.expected,bpNonce.challengeSha256);
 assert.equal((await put(x.quote,1,null,signed)).outcome,'RECORDED_UNVERIFIED');
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateRemoteExpectedUnderLock(conn,x.quote);
  await conn.commit();
  assert.equal(expected.bpExists,true);
  assert.equal(expected.bpLocallyConsistent,true);
  assert.equal(expected.bpPacketSha256,candidateIntakePacketDigest(signed));
  return {quote:x.quote,expected};
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
const challenge=async(quote:string,when=new Date('2026-11-17T14:58:00.000Z'))=>
 issueCandidateRemoteChallenge(db,{quoteId:quote,env:bqEnv,now:when});
const putRemote=(x:Awaited<ReturnType<typeof bqFixture>>,version:number,
 previousPacketSha256:string|null,
 packet:ReturnType<typeof bqPacketFixture>,override:NodeJS.ProcessEnv=bqEnv)=>
 recordCandidateRemoteEvidence(db,{quoteId:x.quote,version,previousPacketSha256,
  packet,registrarPin:bqRoot,collectorPins:bqCollectors,endpoints:bqEndpoints,
  now:bqNow,env:override});
const inspectRemote=(quote:string)=>inspectCandidateRemoteEvidence(db,quote,bqEnv);


const brEnv:NodeJS.ProcessEnv={...bqEnv,BR_ROOT_CERT_SHA256:brRootSha,
 BR_PROVIDER_ORIGIN:brOrigin};
async function brMysqlFixture(){
 const x=await bqFixture(),nonce=await challenge(x.quote);
 const material=brFixture(x.expected,nonce.challengeSha256,brNow);
 assert.equal((await putRemote(x,1,null,material.bq)).outcome,'RECORDED_UNVERIFIED');
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateByteExpectedUnderLock(conn,x.quote);
  await conn.commit();
  assert.equal(expected.bqPacketSha256,candidateRemotePacketDigest(material.bq));
  assert.equal(expected.bqLocallyConsistent,true);
  return {quote:x.quote,material,expected};
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
const writeBytes=(x:Awaited<ReturnType<typeof brMysqlFixture>>,
 version:number,previousPacketSha256:string|null,
 packet=x.material.packet,overrides:NodeJS.ProcessEnv=brEnv)=>
 recordCandidateProviderBytes(db,{quoteId:x.quote,version,previousPacketSha256,
  packet,bqPacket:x.material.bq,rootCertificatePem:brRootPem,
  now:brNow,env:overrides});
const readBytes=(quote:string)=>inspectCandidateProviderBytes(db,quote,brEnv);


const bsEnv:NodeJS.ProcessEnv={...brEnv,BS_ISSUER_ROOT_SHA256:brRootSha};
async function bsMysqlFixture(options:BsFixtureOptions={}){
 const x=await bqFixture(),n=await challenge(x.quote);
 const signed=bsSignedFixture(x.expected,n.challengeSha256,bsNow,options);
 assert.equal((await putRemote(x,1,null,signed.material.bq)).outcome,
  'RECORDED_UNVERIFIED');
 assert.equal((await recordCandidateProviderBytes(db,{
  quoteId:x.quote,version:1,previousPacketSha256:null,
  packet:signed.material.packet,bqPacket:signed.material.bq,
  rootCertificatePem:brRootPem,now:bsNow,env:brEnv
 })).outcome,'RECORDED_UNVERIFIED');
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const {expected}=await readCandidateSignedRevocationExpectedUnderLock(conn,x.quote);
  await conn.commit();
  assert.equal(expected.brPacketSha256,candidateBytePacketDigest(signed.material.packet));
  assert.equal(expected.brLocallyConsistent,true);
  return {quote:x.quote,signed,expected};
 }catch(e){await conn.rollback().catch(()=>{});throw e;}
 finally{conn.release();}
}
const putStatus=(x:Awaited<ReturnType<typeof bsMysqlFixture>>,
 version:number,previousPacketSha256:string|null,
 envOverride:NodeJS.ProcessEnv=bsEnv)=>
 recordCandidateSignedRevocation(db,{
  quoteId:x.quote,version,previousPacketSha256,
  brPacket:x.signed.material.packet,
  issuerCertificatePem:brRootPem,
  now:bsNow,env:envOverride
 });
const getStatus=(quote:string,now=bsNow)=>inspectCandidateSignedRevocation(db,quote,bsEnv,now);

test('BS production and non-TLS staging refused, independent candidate root substitution fails',async()=>{
 for(const e of [
  {NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_test',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES',BQ_REMOTE_WRITE_APPROVED:'YES',
   BR_BYTE_INTAKE_APPROVED:'YES',BS_SIGNED_REVOCATION_WRITE_APPROVED:'YES'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_test',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES',BQ_REMOTE_WRITE_APPROVED:'YES',
   BR_BYTE_INTAKE_APPROVED:'YES'}
 ])assert.throws(()=>bsSignedRevocationWriteTarget(e as NodeJS.ProcessEnv));
 assert.equal(bsSignedRevocationWriteTarget(bsEnv),'ci');
 const x=await bsMysqlFixture();
 await assert.rejects(putStatus(x,1,null,
  {...bsEnv,BS_ISSUER_ROOT_SHA256:brHex('f')}),/root substitution denied/);
 assert.equal((await getStatus(x.quote)).candidateSignedRevocationVersion,0);
});
test('BS real signed candidate CRL and OCSP good serial/nonce genesis exact replay and schema HOLD',async()=>{
 const x=await bsMysqlFixture();
 assert.equal((await putStatus(x,1,null)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await putStatus(x,1,null)).outcome,'REPLAY');
 const s=await getStatus(x.quote);
 assert.equal(s.candidateSignedRevocationExists,true);
 assert.equal(s.candidateSignedRevocationVersion,1);
 assert.equal(s.candidateSignedRevocationLocallyConsistent,true,
  s.candidateSignedRevocationAnomalyCodes.join(','));
 assert.equal(s.genuineRCAIorCCAIssuerPolicyVerified,false);
 assert.equal(s.liveOcspRequestResponseAuthenticated,false);
 assert.equal(s.productionReleaseAuthorized,false);
 const [rows]=await db.query<any[]>(
  'SELECT authorized_real_issuer_enrolled,real_signed_crl_distribution_verified,live_authorized_ocsp_responder_verified,independent_revocation_monotonicity_proven,production_release FROM quote_bs_candidate_revocation_streams WHERE quote_id=?',
  [x.quote]);
 assert.deepEqual([
  rows[0].authorized_real_issuer_enrolled,
  rows[0].real_signed_crl_distribution_verified,
  rows[0].live_authorized_ocsp_responder_verified,
  rows[0].independent_revocation_monotonicity_proven,
  rows[0].production_release
 ],['NO','NO','NO','NO','HOLD']);
});
test('BS synthetic signed CRL target serial revocation and OCSP unknown/revoked status quarantine',async()=>{
 for(const change of [{crlRevoked:true},{ocspStatus:'REVOKED' as const},
  {ocspStatus:'UNKNOWN' as const}]){
  const x=await bsMysqlFixture(change);
  assert.equal((await putStatus(x,1,null)).outcome,
   'SOURCE_REVOCATION_CONFLICT_QUARANTINED');
  const report=await getStatus(x.quote);
  assert.equal(report.candidateSignedRevocationVersion,0);
  assert.equal(report.candidateSignedRevocationGovernanceState,'QUARANTINED');
  assert.equal(report.candidateSignedRevocationLocallyConsistent,true,
   report.candidateSignedRevocationAnomalyCodes.join(','));
  assert.equal(report.productionReleaseAuthorized,false);
 }
});
test('BS signed response nonce/serial/responder spoof fails closed and quarantine is sticky',async()=>{
 for(const change of [{ocspNonceHex:brHex('f')},
  {ocspSerial:777777n},{ocspResponderWrong:true}]){
  const x=await bsMysqlFixture(change);
  assert.equal((await putStatus(x,1,null)).outcome,
   'SOURCE_REVOCATION_CONFLICT_QUARANTINED');
  assert.equal((await getStatus(x.quote)).candidateSignedRevocationGovernanceState,
   'QUARANTINED');
  assert.equal((await putStatus(x,1,null)).outcome,'DUPLICATE_REJECTED');
 }
});
test('BS signed CRL number rollback or stale response quarantines independently of byte digests',async()=>{
 for(const [change,outcome] of [
  [{crlNumber:3},'CRL_EPOCH_REGRESSION_QUARANTINED'],
  [{crlUpdatedMinutesAgo:65},'STATUS_STALE_QUARANTINED'],
  [{ocspNextMinutes:-1},'STATUS_STALE_QUARANTINED']
 ] as const){
  const x=await bsMysqlFixture(change);
  assert.equal((await putStatus(x,1,null)).outcome,outcome);
  assert.equal((await getStatus(x.quote)).candidateSignedRevocationVersion,0);
 }
});
test('BS actual DER signature tampering denied with zero persisted candidate authority',async()=>{
 for(const change of [{crlUnsigned:true},{ocspUnsigned:true}]){
  const x=await bsMysqlFixture(change);
  await assert.rejects(putStatus(x,1,null),/unsigned or malformed issuer status rejected/);
  const audit=await getStatus(x.quote);
  assert.equal(audit.candidateSignedRevocationExists,false);
  assert.equal(audit.candidateSignedRevocationGovernanceState,'ABSENT');
 }
});
test('BS signature-valid local status expires independently during owner readback, never grants release',async()=>{
 const x=await bsMysqlFixture();
 await putStatus(x,1,null);
 const later=await getStatus(x.quote,new Date(bsNow.getTime()+35*60000));
 assert.equal(later.candidateSignedRevocationLocallyConsistent,false);
 assert.ok(later.candidateSignedRevocationAnomalyCodes.includes('BS_SIGNED_STATUS_EXPIRED'));
 assert.equal(later.productionReleaseAuthorized,false);
});
test('BS signed status held stream tamper and upstream BR packet spoof detected transactionally',async()=>{
 const x=await bsMysqlFixture();
 await putStatus(x,1,null);
 const original=await getStatus(x.quote);
 try{
  await db.execute(
   'UPDATE quote_bs_candidate_revocation_streams SET last_packet_sha256=? WHERE quote_id=?',
   [brHex('f'),x.quote]);
  const bad=await getStatus(x.quote);
  assert.ok(bad.candidateSignedRevocationAnomalyCodes.includes(
   'BS_HEAD_HISTORY_DIVERGENCE'));
  await assert.rejects(putStatus(x,2,original.candidateSignedRevocationPacketSha256),
   /local source ledger corrupt/);
 }finally{
  await db.execute(
   'UPDATE quote_bs_candidate_revocation_streams SET last_packet_sha256=? WHERE quote_id=?',
   [original.candidateSignedRevocationPacketSha256,x.quote]);
 }
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await conn.execute(
   'UPDATE quote_br_candidate_byte_streams SET last_packet_sha256=? WHERE quote_id=?',
   [brHex('e'),x.quote]);
  const {expected}=await readCandidateSignedRevocationExpectedUnderLock(conn,x.quote);
  const bad=await inspectCandidateSignedRevocationOnConnection(conn,x.quote,expected,bsNow);
  assert.ok(bad.candidateSignedRevocationAnomalyCodes.includes(
   'BS_UPSTREAM_BR_HEAD_CHANGED'));
 }finally{await conn.rollback().catch(()=>{});conn.release();}
 assert.equal((await getStatus(x.quote)).candidateSignedRevocationLocallyConsistent,true);
});
test('BS independent quote HSN source mutation is detected across BM through BR and BS',async()=>{
 const x=await bsMysqlFixture();
 await putStatus(x,1,null);
 try{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['0000',x.quote]);
  const report=await getStatus(x.quote);
  assert.equal(report.candidateSignedRevocationLocallyConsistent,false);
  assert.ok(report.candidateSignedRevocationAnomalyCodes.includes(
   'BS_UPSTREAM_BR_HEAD_CHANGED'));
 }finally{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 assert.equal((await getStatus(x.quote)).candidateSignedRevocationLocallyConsistent,true);
 assert.equal((await getStatus(x.quote)).releaseDecision,'HOLD');
});
