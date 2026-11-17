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

test('BQ denies production, non-TLS staging, missing approval and applicant pin substitution',async()=>{
 for(const environment of [
  {NODE_ENV:'production',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_ci',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES',BQ_REMOTE_WRITE_APPROVED:'YES'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_ci',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',BM_QUOTE_WRITE_APPROVED:'YES',
   BN_RECONCILIATION_WRITE_APPROVED:'YES',BO_AUTHORITY_DOSSIER_WRITE_APPROVED:'YES',
   BP_INTAKE_WRITE_APPROVED:'YES'}
 ])assert.throws(()=>bqRemoteWriteTarget(environment as NodeJS.ProcessEnv));
 assert.equal(bqRemoteWriteTarget(bqEnv),'ci');
 const x=await bqFixture(),c=await challenge(x.quote);
 await assert.rejects(putRemote(x,1,null,bqPacketFixture(x.expected,c.challengeSha256),
  {...bqEnv,BQ_ENDPOINT_CONFIG_SHA256:bqSha('f')}),/independent candidate registrar\/endpoint config mismatch/);
 assert.equal((await inspectRemote(x.quote)).candidateRemoteVersion,0);
});
test('BQ registrar and two-collector captured offline candidate genesis/replay/extension stay HARD HOLD',async()=>{
 const x=await bqFixture(),c=await challenge(x.quote);
 const p=bqPacketFixture(x.expected,c.challengeSha256);
 assert.equal((await putRemote(x,1,null,p)).outcome,'RECORDED_UNVERIFIED');
 assert.equal((await putRemote(x,1,null,p)).outcome,'REPLAY');
 const report=await inspectRemote(x.quote);
 assert.equal(report.candidateRemoteVersion,1);
 assert.equal(report.candidateRemoteLocallyConsistent,true,
  report.candidateRemoteAnomalyCodes.join(','));
 assert.equal(report.authenticatedRegistrarEnrollment,false);
 assert.equal(report.liveRemoteCheckpointRetrieved,false);
 assert.equal(report.liveSignedCrlOcspValidated,false);
 assert.equal(report.productionReleaseAuthorized,false);
 const next=await challenge(x.quote);
 const p2=bqPacketFixture(x.expected,next.challengeSha256);
 assert.equal((await putRemote(x,2,report.candidateRemotePacketSha256!,p2)).outcome,
  'RECORDED_UNVERIFIED');
 const second=await inspectRemote(x.quote);
 assert.equal(second.candidateRemoteVersion,2);
 assert.equal(second.candidateRemoteAttemptCount,2);
 assert.equal(second.releaseDecision,'HOLD');
 const [rows]=await db.query<any[]>(
  'SELECT authenticated_registrar_enrollment,remotely_retrieved_head_verified,live_issuer_crl_ocsp_verified,independent_worm_verified,actual_dr_recovery_witnessed,production_release FROM quote_bq_candidate_remote_streams WHERE quote_id=?',
  [x.quote]);
 assert.deepEqual([rows[0].authenticated_registrar_enrollment,
  rows[0].remotely_retrieved_head_verified,
  rows[0].live_issuer_crl_ocsp_verified,rows[0].independent_worm_verified,
  rows[0].actual_dr_recovery_witnessed,rows[0].production_release],
  ['NO','NO','NO','NO','NO','HOLD']);
});
test('BQ concurrently signed different challenges fork and permanent quarantine',async()=>{
 const x=await bqFixture(),a=await challenge(x.quote),b=await challenge(x.quote);
 const p=bqPacketFixture(x.expected,a.challengeSha256),
  q=bqPacketFixture(x.expected,b.challengeSha256);
 const outcomes=(await Promise.all([putRemote(x,1,null,p),
  putRemote(x,1,null,q)])).map(x=>x.outcome).sort();
 assert.deepEqual(outcomes,['FORK_QUARANTINED','RECORDED_UNVERIFIED']);
 const held=await inspectRemote(x.quote);
 assert.equal(held.candidateRemoteGovernanceState,'QUARANTINED');
 assert.equal(held.candidateRemoteVersion,1);
 assert.equal(held.candidateRemoteLocallyConsistent,true,
  held.candidateRemoteAnomalyCodes.join(','));
 await assert.rejects(challenge(x.quote),/challenge blocked by previous incident/);
});
test('BQ altered signed remote head with consumed challenge quarantines as replay attack',async()=>{
 const x=await bqFixture(),c=await challenge(x.quote);
 const p=bqPacketFixture(x.expected,c.challengeSha256);
 await putRemote(x,1,null,p);
 const changed=bqResignCapture(p,'PRIMARY',{crlSha256:bqSha('f')});
 assert.equal((await putRemote(x,2,candidateRemotePacketDigest(p),changed)).outcome,
  'CHALLENGE_REPLAY_QUARANTINED');
 const report=await inspectRemote(x.quote);
 assert.equal(report.candidateRemoteVersion,1);
 assert.equal(report.candidateRemoteGovernanceState,'QUARANTINED');
 assert.equal(report.candidateRemoteLocallyConsistent,true,
  report.candidateRemoteAnomalyCodes.join(','));
});
test('BQ expired remote capture challenge fails closed on valid signatures',async()=>{
 const x=await bqFixture(),c=await challenge(x.quote,new Date('2026-11-17T14:00:00.000Z'));
 const p=bqPacketFixture(x.expected,c.challengeSha256);
 assert.equal((await putRemote(x,1,null,p)).outcome,'CHALLENGE_REPLAY_QUARANTINED');
 const held=await inspectRemote(x.quote);
 assert.equal(held.candidateRemoteGovernanceState,'QUARANTINED');
 assert.equal(held.candidateRemoteVersion,0);
 assert.equal(held.liveRemoteCheckpointRetrieved,false);
});
test('BQ forged registrar or collector Ed25519 signatures never persist candidate head',async()=>{
 for(const tamper of ['registrar','collector']){
  const x=await bqFixture(),c=await challenge(x.quote);
  const p=bqClone(bqPacketFixture(x.expected,c.challengeSha256));
  if(tamper==='registrar')
   p.manifestSignatureBase64=Buffer.alloc(64,8).toString('base64');
  else p.captures[0].signatureBase64=Buffer.alloc(64,8).toString('base64');
  await assert.rejects(putRemote(x,1,null,p),/malformed\/unsigned candidate receipt rejected/);
  const audit=await inspectRemote(x.quote);
  assert.equal(audit.candidateRemoteVersion,0);
  assert.equal(audit.candidateRemoteGovernanceState,'HELD_UNVERIFIED');
 }
});
test('BQ signed split head, issuer CRL downgrade, incorrect TLS pin, WORM denial or DR rollback freeze',async()=>{
 for(const change of [
  {remoteSequence:2},{remoteReceiptSha256:bqSha('f')},
  {revocationEpoch:3},{crlSha256:bqSha('f')},
  {tlsSpkiSha256:bqSha('f')},{wormDeleteDenied:false},
  {drRestoredSequence:0},{drTranscriptSha256:bqSha('f')}
 ]){
  const x=await bqFixture(),c=await challenge(x.quote);
  const p=bqResignCapture(bqPacketFixture(x.expected,c.challengeSha256),
   'SECONDARY',change);
  assert.equal((await putRemote(x,1,null,p)).outcome,
   'REMOTE_CLAIM_CONFLICT_QUARANTINED');
  const audit=await inspectRemote(x.quote);
  assert.equal(audit.candidateRemoteLocallyConsistent,true,
   audit.candidateRemoteAnomalyCodes.join(','));
  assert.equal(audit.candidateRemoteGovernanceState,'QUARANTINED');
  assert.equal(audit.productionReleaseAuthorized,false);
 }
});
test('BQ forged stored stream packet or consumed nonce is detected before further writes',async()=>{
 const x=await bqFixture(),c=await challenge(x.quote);
 const p=bqPacketFixture(x.expected,c.challengeSha256);
 await putRemote(x,1,null,p);
 const packetSha=candidateRemotePacketDigest(p);
 try{
  await db.execute(
   'UPDATE quote_bq_candidate_remote_streams SET last_packet_sha256=? WHERE quote_id=?',
   [bqSha('f'),x.quote]);
  const audit=await inspectRemote(x.quote);
  assert.ok(audit.candidateRemoteAnomalyCodes.includes(
   'BQ_STORED_HEAD_HISTORY_DIVERGENCE'));
  await assert.rejects(putRemote(x,2,packetSha,p),/local history corrupt/);
 }finally{
  await db.execute(
   'UPDATE quote_bq_candidate_remote_streams SET last_packet_sha256=? WHERE quote_id=?',
   [packetSha,x.quote]);
 }
 try{
  await db.execute(
   "UPDATE quote_bq_candidate_remote_challenges SET status='ISSUED',consumed_packet_sha256=NULL WHERE challenge_sha256=?",
   [c.challengeSha256]);
  const audit=await inspectRemote(x.quote);
  assert.ok(audit.candidateRemoteAnomalyCodes.includes(
   'BQ_CHALLENGE_CONSUMPTION_TAMPERED'));
 }finally{
  await db.execute(
   "UPDATE quote_bq_candidate_remote_challenges SET status='CONSUMED',consumed_packet_sha256=? WHERE challenge_sha256=?",
   [packetSha,c.challengeSha256]);
 }
 assert.equal((await inspectRemote(x.quote)).candidateRemoteLocallyConsistent,true);
});
test('BQ BO/BP parent source tampering and staged rollback are detected without trust promotion',async()=>{
 const x=await bqFixture(),c=await challenge(x.quote);
 const p=bqPacketFixture(x.expected,c.challengeSha256);
 await putRemote(x,1,null,p);
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  await conn.execute(
   'UPDATE quote_bp_candidate_intake_streams SET last_packet_sha256=? WHERE quote_id=?',
   [bqSha('f'),x.quote]);
  const {expected}=await readCandidateRemoteExpectedUnderLock(conn,x.quote);
  const audit=await inspectCandidateRemoteEvidenceOnConnection(conn,x.quote,expected);
  assert.equal(audit.candidateRemoteLocallyConsistent,false);
  assert.ok(audit.candidateRemoteAnomalyCodes.includes('BQ_UPSTREAM_BP_CHANGED'));
 }finally{await conn.rollback().catch(()=>{});conn.release();}
 try{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['0000',x.quote]);
  const drift=await inspectRemote(x.quote);
  assert.ok(drift.candidateRemoteAnomalyCodes.includes('BQ_UPSTREAM_BP_CHANGED'));
 }finally{
  await db.execute('UPDATE sales_quote_draft_items SET hsn_snapshot=? WHERE quote_id=?',
   ['8471',x.quote]);
 }
 assert.equal((await inspectRemote(x.quote)).candidateRemoteLocallyConsistent,true);
 assert.equal((await inspectRemote(x.quote)).productionReleaseAuthorized,false);
});
