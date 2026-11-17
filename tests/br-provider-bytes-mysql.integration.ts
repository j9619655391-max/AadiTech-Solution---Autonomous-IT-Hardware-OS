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

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci')
 throw Error('Phase 1BR strictly requires disposable isolated CI MySQL');
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

test('BR denies production, missing isolated TLS staging consent and applicant CA substitution',async()=>{
 for(const e of [
  {NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_fixture',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES',BQ_REMOTE_WRITE_APPROVED:'YES',
   BR_BYTE_INTAKE_APPROVED:'YES'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_fixture',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES',BQ_REMOTE_WRITE_APPROVED:'YES'}
 ])assert.throws(()=>brCandidateByteWriteTarget(e as NodeJS.ProcessEnv));
 assert.equal(brCandidateByteWriteTarget(brEnv),'ci');
 const x=await brMysqlFixture();
 await assert.rejects(writeBytes(x,1,null,x.material.packet,
  {...brEnv,BR_ROOT_CERT_SHA256:brHex('f')}),/trust root substituted/);
 assert.equal((await readBytes(x.quote)).candidateByteVersion,0);
});
test('BR pinned ephemeral root, signed raw checkpoint genesis and exact replay never authorize production',async()=>{
 const x=await brMysqlFixture();
 assert.equal((await writeBytes(x,1,null)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await writeBytes(x,1,null)).outcome,'REPLAY');
 const report=await readBytes(x.quote);
 assert.equal(report.candidateByteLocallyConsistent,true,
  report.candidateByteAnomalyCodes.join(','));
 assert.equal(report.candidateByteVersion,1);
 assert.equal(report.candidateByteGovernanceState,'HELD_UNVERIFIED');
 assert.equal(report.signedCrlOcspAndResponderAuthorized,false);
 assert.equal(report.liveTlsProviderSessionVerified,false);
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.releaseDecision,'HOLD');
 const [rows]=await db.query<any[]>(
  'SELECT provider_root_independently_authenticated,live_provider_tls_attested,issuer_policy_and_chain_authorized,signed_crl_ocsp_authorized,independent_worm_verified,actual_dr_restore_witnessed,production_release FROM quote_br_candidate_byte_streams WHERE quote_id=?',[x.quote]);
 assert.deepEqual([rows[0].provider_root_independently_authenticated,
  rows[0].live_provider_tls_attested,rows[0].issuer_policy_and_chain_authorized,
  rows[0].signed_crl_ocsp_authorized,rows[0].independent_worm_verified,
  rows[0].actual_dr_restore_witnessed,rows[0].production_release],
  ['NO','NO','NO','NO','NO','NO','HOLD']);
});
test('BR two independently submitted byte records race and sticky quarantine one fork',async()=>{
 const x=await brMysqlFixture(),a=x.material.packet,b=brClone(a);
 // A second raw byte report is byte-different but structurally valid. It
 // carries a mismatched raw WORM object, so must quarantine rather than GO.
 const changed=JSON.parse(Buffer.from(b.wormReceiptUtf8Base64,'base64').toString());
 changed.objectId='other-candidate-object';
 b.wormReceiptUtf8Base64=Buffer.from(JSON.stringify(changed)).toString('base64');
 assert.equal((await writeBytes(x,1,null,a)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await writeBytes(x,1,null,b)).outcome,'RAW_BYTES_CONFLICT_QUARANTINED');
 const state=await readBytes(x.quote);
 assert.equal(state.candidateByteVersion,1);
 assert.equal(state.candidateByteGovernanceState,'QUARANTINED');
 assert.equal(state.candidateByteLocallyConsistent,true,
  state.candidateByteAnomalyCodes.join(','));
});
test('BR CRL/OCSP swapped DER bytes produce quarantine and never issuer validity',async()=>{
 for(const key of ['crlDerBase64','ocspDerBase64'] as const){
  const x=await brMysqlFixture(),p=brClone(x.material.packet);
  p[key]=Buffer.from([0x30,0x06,0x02,0x01,0x02,0x02,0x01,0x09]).toString('base64');
  assert.equal((await writeBytes(x,1,null,p)).outcome,'RAW_BYTES_CONFLICT_QUARANTINED');
  const audit=await readBytes(x.quote);
  assert.equal(audit.candidateByteGovernanceState,'QUARANTINED');
  assert.equal(audit.candidateByteLocallyConsistent,true);
  assert.equal(audit.signedCrlOcspAndResponderAuthorized,false);
 }
});
test('BR forged signed provider checkpoint payload is denied before insertion',async()=>{
 const x=await brMysqlFixture(),p=brClone(x.material.packet);
 const raw=Buffer.from(p.checkpointUtf8Base64,'base64');
 raw[raw.length-1]^=1;p.checkpointUtf8Base64=raw.toString('base64');
 await assert.rejects(writeBytes(x,1,null,p),/malformed or unsigned/);
 const audit=await readBytes(x.quote);
 assert.equal(audit.candidateByteVersion,0);
 assert.equal(audit.candidateByteGovernanceState,'HELD_UNVERIFIED');
});
test('BR DR rollback and forged WORM offline receipts are quarantined',async()=>{
 for(const [key,change] of [
  ['drTranscriptUtf8Base64',{sequence:0}],
  ['wormReceiptUtf8Base64',{deniedDelete:false}]
 ] as const){
  const x=await brMysqlFixture(),p=brClone(x.material.packet);
  const payload=JSON.parse(Buffer.from(p[key],'base64').toString());
  Object.assign(payload,change);
  p[key]=Buffer.from(JSON.stringify(payload)).toString('base64');
  assert.equal((await writeBytes(x,1,null,p)).outcome,'RAW_BYTES_CONFLICT_QUARANTINED');
  const audit=await readBytes(x.quote);
  assert.equal(audit.candidateByteVersion,0);
  assert.equal(audit.candidateByteGovernanceState,'QUARANTINED');
  assert.equal(audit.realEncryptedDrRestorationWitnessed,false);
 }
});
test('BR SQL stored head forgery and upstream BQ tamper detected with no release',async()=>{
 const x=await brMysqlFixture();
 assert.equal((await writeBytes(x,1,null)).outcome,'RECORDED_UNVERIFIED');
 const digest=candidateBytePacketDigest(x.material.packet);
 try{
  await db.execute('UPDATE quote_br_candidate_byte_streams SET last_packet_sha256=? WHERE quote_id=?',
   [brHex('f'),x.quote]);
  const bad=await readBytes(x.quote);
  assert.ok(bad.candidateByteAnomalyCodes.includes('BR_HEAD_LEDGER_DIVERGENCE'));
  await assert.rejects(writeBytes(x,2,digest),/local byte custody tamper detected/);
 }finally{
  await db.execute('UPDATE quote_br_candidate_byte_streams SET last_packet_sha256=? WHERE quote_id=?',
   [digest,x.quote]);
 }
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await conn.execute('UPDATE quote_bq_candidate_remote_streams SET last_packet_sha256=? WHERE quote_id=?',
   [brHex('e'),x.quote]);
  const {expected}=await readCandidateByteExpectedUnderLock(conn,x.quote);
  const alarm=await inspectCandidateProviderBytesOnConnection(conn,x.quote,expected);
  assert.ok(alarm.candidateByteAnomalyCodes.includes('BR_UPSTREAM_BQ_CHANGED'));
 }finally{await conn.rollback().catch(()=>{});conn.release();}
 assert.equal((await readBytes(x.quote)).candidateByteLocallyConsistent,true);
});
test('BR quote source mutation propagates BM/BN/BO/BP/BQ to BR and never becomes production authority',async()=>{
 const x=await brMysqlFixture();
 await writeBytes(x,1,null);
 try{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['0000',x.quote]);
  const bad=await readBytes(x.quote);
  assert.equal(bad.candidateByteLocallyConsistent,false);
  assert.ok(bad.candidateByteAnomalyCodes.includes('BR_UPSTREAM_BQ_CHANGED'));
 }finally{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 assert.equal((await readBytes(x.quote)).candidateByteLocallyConsistent,true);
 assert.equal((await readBytes(x.quote)).productionReleaseAuthorized,false);
});
