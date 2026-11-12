import test,{after} from 'node:test';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/externalTrust/ownerRouter';
import providerOwnerRouter from '../server/providerBridge/ownerRouter';
import providerReviewRouter from '../server/providerBridge/reviewRouter';
import sandboxOwnerRouter from '../server/providerSandbox/ownerRouter';
import sandboxReviewRouter from '../server/providerSandbox/reviewRouter';
import reviewRouter from '../server/externalTrust/reviewRouter';
import lifecycleOwnerRouter from '../server/keyLifecycle/ownerRouter';
import lifecycleReviewRouter from '../server/keyLifecycle/reviewRouter';
import proofOwnerRouter from '../server/proofFoundation/ownerRouter';
import proofReviewRouter from '../server/proofFoundation/reviewRouter';
import {readHeldGrnSource} from '../server/stockFoundation/integrity';
import {releaseSnapshot,releaseHoldSnapshot} from '../server/stockFoundation/validation';
import {claimDigest,heldGrnSnapshot} from '../server/evidenceChain/validation';
import {checkHeldSource,checkClaim,checkQuarantine,makePack} from '../server/evidenceChain/integrity';
import {dispatchManifest,sha} from '../server/dispatch/validation';
import {validateInbound,canonicalIntakeHash} from '../server/intake/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Provider sandbox integration allowed only on disposable CI MySQL');
const db=getPool();if(!db)throw Error('Disposable CI database required');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),
 reviewerToken=newSecret(),csrf=newSecret(),ownerPass='CI-evidence-owner-2026-pass',
 reviewerPass='CI-evidence-reviewer-2026-pass';
let ownerStep='',reviewerStep='',base='';
let close:(()=>Promise<void>)|undefined;
after(async()=>{if(close)await close();await db.end();});
type Fixture={preparationId:string;outboxId:string;holdId:string;observationId:string;
 supplierId:string;productId:string;lotProductId:string;claimId?:string};
let a:Fixture,b:Fixture,c:Fixture;
async function call(path:string,method='GET',body?:unknown,as:'owner'|'reviewer'|'anon'='owner',
 opts:{csrf?:boolean;stepUp?:boolean}={}){
 const headers:Record<string,string>={};
 if(as!=='anon')headers.cookie='aaditech_session='+(as==='owner'?ownerToken:reviewerToken);
 if(body!==undefined)headers['content-type']='application/json';
 if(method!=='GET'&&opts.csrf!==false)headers['x-csrf-token']=csrf;
 if(opts.stepUp!==false){
  const token=as==='owner'?ownerStep:reviewerStep;
  if(token)headers['x-step-up-token']=token;
 }
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON response'};}}
 return {status:response.status,data};
}
async function fixture(label:string):Promise<Fixture>{
 const supplierId=randomUUID(),productId=randomUUID(),lotProductId=randomUUID();
 const siteId=randomUUID(),requestId=randomUUID(),reviewId=randomUUID(),
  holdId=randomUUID(),destinationId=randomUUID(),preparationId=randomUUID(),
  dispatchReviewId=randomUUID(),outboxId=randomUUID(),observationId=randomUUID(),
  inspectionId=randomUUID();
 const code='EC'+randomUUID().replace(/-/g,'').slice(0,12).toUpperCase();
 const email='ec-'+randomUUID().replace(/-/g,'').slice(0,10)+'@example.invalid';
 await db.execute(`INSERT INTO inventory_sites(id,code,name,created_by)
  VALUES(?,?,?,?)`,[siteId,code,'Isolated CI '+label,owner]);
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,status,evidence_ref,created_by,reviewed_by)
  VALUES(?,?,?,'REVIEWED_INTERNAL',?,?,?)`,
  [supplierId,code,'CI internal only '+label,'SUPPLIER-ID-REF-2026',owner,reviewer]);
 const skus=[{productId,sku:'EC-SER-'+productId,name:'CI serial server',quantity:2,
  quotedUnitCost:'100.00',lineSubtotal:'200.00'},
 {productId:lotProductId,sku:'EC-LOT-'+lotProductId,name:'CI lot component',quantity:3,
  quotedUnitCost:'20.00',lineSubtotal:'60.00'}];
 for(const l of skus){
  await db.execute(`INSERT INTO crm_products
   (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,hsn)
   VALUES(?,?,?,?,'SERVER',?,'20.00','120.00','20.00','8471')`,
   [l.productId,l.sku,'CI',l.name,'No real stock']);
 }
 await db.execute(`INSERT INTO proc_requests
  (id,supplier_id,site_id,created_by,quote_evidence_ref,subtotal,status)
  VALUES(?,?,?,?,?,'260.00','APPROVED_INTERNAL')`,
  [requestId,supplierId,siteId,owner,'SYNTH-QUOTE-EVID-2026']);
 for(let i=0;i<skus.length;i++){
  const l=skus[i];
  await db.execute(`INSERT INTO proc_request_items
   (id,request_id,position,product_id,sku_snapshot,name_snapshot,quantity,
    quoted_unit_cost,line_subtotal) VALUES (?,?,?,?,?,?,?,?,?)`,
   [randomUUID(),requestId,i+1,l.productId,l.sku,l.name,l.quantity,
    l.quotedUnitCost,l.lineSubtotal]);
 }
 await db.execute(`INSERT INTO proc_review_decisions
  (id,request_id,reviewer_id,decision,reason,evidence_attested)
  VALUES(?,?,?,'APPROVED_INTERNAL',?,1)`,
  [reviewId,requestId,reviewer,'CI internal synthetic purchase review']);
 const hold={format:'aaditech-internal-po-hold-v1',requestId,supplierId,
  supplierCode:code,supplierName:'CI internal only '+label,siteId,
  supplierQuoteEvidenceRef:'SYNTH-QUOTE-EVID-2026',subtotal:'260.00',
  reviewId,lines:skus};
 const holdSha=sha(JSON.stringify(hold));
 await db.execute(`INSERT INTO proc_po_holds
  (id,request_id,decision_id,prepared_by,snapshot_sha256,snapshot_json)
  VALUES(?,?,?,?,?,?)`,
  [holdId,requestId,reviewId,owner,holdSha,JSON.stringify(hold)]);
 await db.execute(`INSERT INTO proc_delivery_destinations
  (id,supplier_id,email,evidence_ref,status,created_by,reviewed_by,review_evidence_ref,review_reason)
  VALUES(?,?,?,?,'REVIEWED_INTERNAL',?,?,?,?)`,
  [destinationId,supplierId,email,'SYNTH-CONTACT-REF-2026',owner,reviewer,
   'REVIEWED-CONTACT-REF-2026','Internally reviewed but unverified email address']);
 const manifest=dispatchManifest({holdId,holdSha256:holdSha,destinationId,
  supplierId,email,authorizationEvidenceRef:'SYNTH-DISP-AUTH-2026'});
 const manifestSha=sha(JSON.stringify(manifest));
 await db.execute(`INSERT INTO proc_dispatch_preparations
  (id,hold_id,destination_id,prepared_by,authorization_evidence_ref,
   hold_sha256,manifest_sha256,manifest_json,status)
  VALUES(?,?,?,?,?,?,?,?,'APPROVED_INTERNAL')`,
  [preparationId,holdId,destinationId,owner,'SYNTH-DISP-AUTH-2026',
   holdSha,manifestSha,JSON.stringify(manifest)]);
 await db.execute(`INSERT INTO proc_dispatch_review_decisions
  (id,preparation_id,reviewer_id,decision,reason,evidence_ref,destination_attested)
  VALUES (?,?,?,'APPROVED_INTERNAL',?,?,1)`,
  [dispatchReviewId,preparationId,reviewer,'Synthetic internal dispatch review',
   'SYNTH-DISPATCH-REVIEW-2026']);
 const outbox={format:'aaditech-supplier-PO-outbox-HELD-v1',preparationId,
  manifestSha256:manifestSha,decisionId:dispatchReviewId,
  dispatchState:'DISABLED',externalPoIssued:false};
 await db.execute(`INSERT INTO proc_dispatch_outbox_holds
  (id,preparation_id,decision_id,snapshot_sha256,snapshot_json)
  VALUES(?,?,?,?,?)`,
  [outboxId,preparationId,dispatchReviewId,sha(JSON.stringify(outbox)),JSON.stringify(outbox)]);
 const items=[{productId,quantity:2,trackingMode:'SERIAL',lotCode:null,
   serialNumbers:[('EC-'+label+'-'+randomUUID().replace(/-/g,'').slice(0,12)).toUpperCase(),
    ('EC-'+label+'-'+randomUUID().replace(/-/g,'').slice(0,12)).toUpperCase()]},
  {productId:lotProductId,quantity:3,trackingMode:'LOT',lotCode:'LOT-'+label.toUpperCase()+'-2026',serialNumbers:[]}];
 const intake=validateInbound({holdId,deliveryEvidenceRef:'SYNTH-DELIVERY-REF-2026',
  physicalCountRef:'SYNTH-COUNT-REF-2026',items});
 const obsHash=canonicalIntakeHash({...intake,
  items:[...intake.items].sort((x,y)=>x.productId.localeCompare(y.productId))});
 await db.execute(`INSERT INTO inv_inbound_observations
  (id,hold_id,request_id,site_id,recorded_by,delivery_evidence_ref,physical_count_ref,
   payload_sha256,status) VALUES(?,?,?,?,?,?,?,?,'QUARANTINED_INTERNAL')`,
  [observationId,holdId,requestId,siteId,owner,intake.deliveryEvidenceRef,
   intake.physicalCountRef,obsHash]);
 await db.execute(`INSERT INTO inv_inbound_decisions
  (id,observation_id,reviewer_id,outcome,inspection_evidence_ref,reason)
  VALUES(?,?,?,'ACCEPT_QUARANTINE',?,?)`,
  [inspectionId,observationId,reviewer,'SYNTH-INSPECTION-2026',
   'CI internally inspected synthetic quarantine units']);
 for(const l of items){
  const lineId=randomUUID();
  await db.execute(`INSERT INTO inv_inbound_lines
   (id,observation_id,product_id,quantity,tracking_mode,lot_code,serials_json)
   VALUES(?,?,?,?,?,?,?)`,
   [lineId,observationId,l.productId,l.quantity,l.trackingMode,l.lotCode,
    JSON.stringify(l.serialNumbers)]);
  await db.execute(`INSERT INTO inv_quarantine_custody_events
   (id,observation_id,line_id,site_id,product_id,quantity,recorded_by)
   VALUES(?,?,?,?,?,?,?)`,
   [randomUUID(),observationId,lineId,siteId,l.productId,l.quantity,reviewer]);
  for(const serial of l.serialNumbers){
   await db.execute(`INSERT INTO inv_quarantine_serials
    (id,observation_id,product_id,site_id,serial_number) VALUES(?,?,?,?,?)`,
    [randomUUID(),observationId,l.productId,siteId,serial]);
  }
 }
 return {preparationId,outboxId,holdId,observationId,supplierId,productId,lotProductId};
}
function claimBody(f:Fixture){
 return {preparationId:f.preparationId,supplierAckRef:'CLAIM-ONLY-2026-'+f.preparationId.slice(0,8).toUpperCase(),
  evidenceRef:'CLAIM-DOC-REF-2026',documentSha256:sha('Synthetic offline claimant evidence '+f.preparationId)};
}
const attest={decision:'ATTESTED_INTERNAL',reason:'Inspected the operator supplied claim document and recorded discrepancies',
 reviewEvidenceRef:'REVIEW-DOCUMENT-2026',documentInspected:true};
const holdDecision={decision:'HELD_INTERNAL',reason:'Inspected internal quarantined serial and lot custody; GRN remains held',
 reviewEvidenceRef:'INTERNAL-GRN-WITNESS-2026',custodyInspected:true};


type HeldFixture=Fixture&{heldGrnId:string;claimId:string;packId:string};
let main:HeldFixture,second:HeldFixture;
async function withHeldSource(f:Fixture):Promise<HeldFixture>{
 const conn=await db.getConnection();await conn.beginTransaction();
 try{
  const src=await checkHeldSource(conn,f.preparationId);
  const claimId=randomUUID(),claimData={
   preparationId:f.preparationId,supplierAckRef:'SYNTH-ACK-'+randomUUID().slice(0,8).toUpperCase(),
   evidenceRef:'SYNTH-CLAIM-REF-2026',
   documentSha256:sha('UNVERIFIED-SYNTH-DOC-'+f.preparationId)};
  const claimSha=claimDigest(claimData,src.outboxSha256);
  await conn.execute(`INSERT INTO proc_ack_claims
   (id,preparation_id,outbox_id,recorded_by,supplier_ack_ref,evidence_ref,
    document_sha256,outbox_sha256,claim_sha256,status)
   VALUES (?,?,?,?,?,?,?,?,?,'ATTESTED_INTERNAL')`,
   [claimId,f.preparationId,src.outboxId,owner,claimData.supplierAckRef,
    claimData.evidenceRef,claimData.documentSha256,src.outboxSha256,claimSha]);
  await conn.execute(`INSERT INTO proc_ack_claim_decisions
   (id,claim_id,reviewer_id,decision,reason,review_evidence_ref,document_inspected)
   VALUES (?,?,?,'ATTESTED_INTERNAL',?,?,1)`,
   [randomUUID(),claimId,reviewer,'Synthetic internal supplier document checked',
    'SYNTH-ACK-REVIEW-2026']);
  const claimed=await checkClaim(conn,claimId,src);
  const observation=await checkQuarantine(conn,f.observationId,src);
  const pack=makePack(src,claimed,observation),packId=randomUUID(),
   decisionId=randomUUID(),packSha=sha(JSON.stringify(pack));
  await conn.execute(`INSERT INTO inv_grn_reconciliation_packs
   (id,claim_id,observation_id,prepared_by,pack_sha256,pack_json,status)
   VALUES (?,?,?,?,?,?,'HELD_INTERNAL')`,
   [packId,claimId,f.observationId,owner,packSha,JSON.stringify(pack)]);
  await conn.execute(`INSERT INTO inv_grn_reconciliation_decisions
   (id,pack_id,reviewer_id,decision,reason,review_evidence_ref,custody_inspected)
   VALUES (?,?,?,'HELD_INTERNAL',?,?,1)`,
   [decisionId,packId,reviewer,'Synthetic internal GRN evidence checked',
    'SYNTH-GRN-WITNESS-2026']);
  const heldGrnId=randomUUID(),held=heldGrnSnapshot(packId,packSha,decisionId);
  await conn.execute(`INSERT INTO inv_grn_held_records
   (id,pack_id,decision_id,snapshot_sha256,snapshot_json)
   VALUES (?,?,?,?,?)`,
   [heldGrnId,packId,decisionId,sha(JSON.stringify(held)),JSON.stringify(held)]);
  await conn.commit();return {...f,heldGrnId,claimId,packId};
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}

async function stockRelease(f:HeldFixture):Promise<string>{
 const conn=await db.getConnection();await conn.beginTransaction();
 try{
  const source=await readHeldGrnSource(conn,f.heldGrnId);
  const snapshot=releaseSnapshot(source),digest=sha(JSON.stringify(snapshot));
  const id=randomUUID(),reviewId=randomUUID();
  for(const l of source.lines)await conn.execute(`INSERT IGNORE INTO inv_stock_position_gates
    (site_id,product_id) VALUES(?,?)`,[source.siteId,l.productId]);
  await conn.execute(`INSERT INTO inv_stock_release_intents
   (id,held_grn_id,observation_id,site_id,prepared_by,source_sha256,
    intent_sha256,intent_json,status)
   VALUES(?,?,?,?,?,?,?,?,'REVIEWED_HELD')`,
   [id,source.heldGrnId,source.observationId,source.siteId,owner,
    source.heldGrnSha256,digest,JSON.stringify(snapshot)]);
  for(const l of source.lines)await conn.execute(`INSERT INTO inv_stock_release_intent_lines
   (id,release_intent_id,product_id,site_id,observed_quantity,tracking_mode,
    lot_code,serials_json) VALUES(?,?,?,?,?,?,?,?)`,
   [randomUUID(),id,l.productId,source.siteId,l.quantity,l.trackingMode,
    l.lotCode,JSON.stringify([...l.serialNumbers].sort())]);
  await conn.execute(`INSERT INTO inv_stock_release_decisions
   (id,release_intent_id,reviewer_id,decision,reason,evidence_ref,source_inspected)
   VALUES(?,?,?,'REVIEWED_HELD',?,?,1)`,
   [reviewId,id,reviewer,'Independent CI synthetic evidence held only',
    'EVIDENCE-REVIEW-CI-2026']);
  const hold=releaseHoldSnapshot(id,digest,reviewId);
  await conn.execute(`INSERT INTO inv_stock_release_holds
   (id,release_intent_id,decision_id,snapshot_sha256,snapshot_json)
   VALUES(?,?,?,?,?)`,[randomUUID(),id,reviewId,sha(JSON.stringify(hold)),JSON.stringify(hold)]);
  await conn.commit();return id;
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
let releaseA='',releaseB='',journalA='',journalB='';

const supplierKeyPair=generateKeyPairSync('ed25519');
const warehouseKeyPair=generateKeyPairSync('ed25519');
let supplierKeyId='',warehouseKeyId='',supplierClaimId='',warehouseClaimId='';
const keyReview={decision:'REVIEWED_UNTRUSTED',
 reason:'Inspected the candidate DER key only; supplier identity is NOT established',
 evidenceRef:'INTERNAL-KEY-CHECK-2026',documentInspected:true};
const claimReview={decision:'REVIEWED_CRYPTO_ONLY',
 reason:'Verified detached Ed25519 bytes and original HELD-source digest only',
 evidenceRef:'INTERNAL-SIGNATURE-CHECK-2026',documentInspected:true};

const pairOld=generateKeyPairSync('ed25519'),pairNew=generateKeyPairSync('ed25519'),
 pairEmergency=generateKeyPairSync('ed25519');
let oldKey='',newKey='',emergencyKey='',oldReceipt='',newReceipt='',rotationId='';
const reason={reason:'Independently inspected offline candidate key possession against original hash',
 evidenceRef:'CI-LIFECYCLE-2026'};
const positive={...reason,decision:'REVIEWED_UNTRUSTED',possessionInspected:true};

const issuerPair=generateKeyPairSync('ed25519');
const vendorPair=generateKeyPairSync('ed25519');
let issuerId='',vendorKeyId='',authorityId='',vendorFingerprint='';
const reviewIssuer={decision:'REVIEWED_HELD',
 reason:'Inspected self-submitted registry claim but have NOT authenticated legal organization',
 evidenceRef:'EXT-CLAIM-REVIEW-2026',evidenceInspected:true};
const reviewAuthority={decision:'REVIEWED_CRYPTO_HELD',
 reason:'Inspected issuer signature math, NOT external source or authorization',
 evidenceRef:'EXT-SIGNATURE-REVIEW-2026',evidenceInspected:true};
const iso=(d:Date)=>new Date(Math.floor(d.getTime()/1000)*1000).toISOString();
const utc=(offset:number)=>iso(new Date(Date.now()+offset));
async function signTemplate(path:string,payload:object){
 const t=await call(path,'POST',payload);
 assert.equal(t.status,200,JSON.stringify(t));
 return sign(null,Buffer.from(t.data.canonicalUtf8,'utf8'),
  issuerPair.privateKey).toString('base64');
}
test('isolated synthetic source, authenticated role separation and API mount',async()=>{
 for(const [id,token,role,password] of [[owner,ownerToken,'OWNER',ownerPass],
  [reviewer,reviewerToken,'REVIEWER',reviewerPass]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES(?,?,?,?,?)',
   [id,'external-'+id+'@example.invalid','External Candidate CI',
    await hashPassword(password),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES(?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 main=await withHeldSource(await fixture('EXTERNAL_CI'));
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/proof-foundation/review',proofReviewRouter);
 app.use('/api/proof-foundation',proofOwnerRouter);
 app.use('/api/key-lifecycle/review',lifecycleReviewRouter);
 app.use('/api/key-lifecycle',lifecycleOwnerRouter);
 app.use('/api/external-trust/review',reviewRouter);
 app.use('/api/external-trust',ownerRouter);
 app.use('/api/provider-bridge/review',providerReviewRouter);
 app.use('/api/provider-bridge',providerOwnerRouter);
 app.use('/api/provider-sandbox/review',sandboxReviewRouter);
 app.use('/api/provider-sandbox',sandboxOwnerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API route'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('registration requires OWNER, CSRF, step-up and registry review remains HELD/UNVERIFIED',async()=>{
 const payload={partyKind:'SUPPLIER',partyId:main.supplierId,
  organizationRegistration:'REG-EXTERNAL-CI-2026',
  issuerSpkiB64:issuerPair.publicKey.export({format:'der',type:'spki'}).toString('base64'),
  evidenceRef:'OFFLINE-ISSUER-TICKET-2026'};
 assert.equal((await call('/api/external-trust/issuers','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/external-trust/issuers','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/external-trust/review/issuers','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/external-trust/issuers','POST',payload)).status,403);
 const [a,b]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass}),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(a.status,200);assert.equal(b.status,200);
 ownerStep=String(a.data.stepUpToken);reviewerStep=String(b.data.stepUpToken);
 assert.equal((await call('/api/external-trust/issuers','POST',payload,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/external-trust/issuers','POST',{...payload,issuerIsTrusted:true})).status,400);
 const r=await call('/api/external-trust/issuers','POST',payload);
 assert.equal(r.status,201,JSON.stringify(r));issuerId=r.data.id;
 assert.equal(r.data.externallyAuthenticated,false);
 const repeat=await call('/api/external-trust/issuers','POST',payload);
 assert.equal(repeat.status,200);assert.equal(repeat.data.id,issuerId);
 assert.equal((await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',{...reviewIssuer,decision:'EXTERNALLY_TRUSTED'},'reviewer')).status,400);
 assert.equal((await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',reviewIssuer,'owner')).status,403);
 assert.equal((await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',{...reviewIssuer,evidenceInspected:false},'reviewer')).status,400);
 const reviewed=await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',reviewIssuer,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.issuerIdentityExternallyVerified,false);
 assert.equal((await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',reviewIssuer,'reviewer')).status,409);
});
test('1AI candidate key plus independently checked 1AJ Ed25519 possession is required',async()=>{
 const p={partyKind:'SUPPLIER',partyId:main.supplierId,
  publicKeySpkiB64:vendorPair.publicKey.export({format:'der',type:'spki'}).toString('base64'),
  evidenceRef:'VENDOR-CANDIDATE-EVIDENCE-2026'};
 const created=await call('/api/proof-foundation/keys','POST',p);
 assert.equal(created.status,201,JSON.stringify(created));vendorKeyId=created.data.id;
 const reviewed=await call('/api/proof-foundation/review/keys/'+vendorKeyId+'/decide','POST',{
  decision:'REVIEWED_UNTRUSTED',
  reason:'Inspected candidate key format with no external identity authority',
  evidenceRef:'INTERNAL-PROOF-KEY-CI-2026',documentInspected:true},'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 const claimBase={issuerId,keyId:vendorKeyId,purpose:'SUPPLIER_ACK',
  validFrom:utc(-60_000),validUntil:utc(3_600_000)};
 assert.equal((await call('/api/external-trust/authority-template','POST',claimBase)).status,409);
 const challenge=await call('/api/key-lifecycle/challenges','POST',{keyId:vendorKeyId});
 assert.equal(challenge.status,201,JSON.stringify(challenge));
 const signatureB64=sign(null,Buffer.from(challenge.data.canonicalUtf8,'utf8'),
  vendorPair.privateKey).toString('base64');
 const receipt=await call('/api/key-lifecycle/responses','POST',
  {challengeId:challenge.data.challengeId,nonceB64:challenge.data.message.nonceB64,signatureB64});
 assert.equal(receipt.status,201,JSON.stringify(receipt));
 const pos=await call('/api/key-lifecycle/review/receipts/'+receipt.data.receiptId+'/decide','POST',{
  decision:'REVIEWED_UNTRUSTED',reason:'Verified possession of self-registered private key only',
  evidenceRef:'CI-POSSESSION-WITNESS-2026',possessionInspected:true},'reviewer');
 assert.equal(pos.status,201,JSON.stringify(pos));
 const [finger]=await db.query<any[]>(`SELECT fingerprint_sha256 AS fp
  FROM inv_proof_key_candidates WHERE id=?`,[vendorKeyId]);
 vendorFingerprint=finger[0].fp;
});
test('signed organizational authority is mathematically verified but never externally trusted',async()=>{
 const payload={issuerId,keyId:vendorKeyId,purpose:'SUPPLIER_ACK' as const,
  validFrom:utc(-60_000),validUntil:utc(3_600_000)};
 const signatureB64=await signTemplate('/api/external-trust/authority-template',payload);
 assert.equal((await call('/api/external-trust/attestations','POST',
  {...payload,signatureB64:Buffer.alloc(64).toString('base64')})).status,409);
 assert.equal((await call('/api/external-trust/attestations','POST',
  {...payload,signatureB64,externallyAuthenticated:true})).status,400);
 const recorded=await call('/api/external-trust/attestations','POST',{...payload,signatureB64});
 assert.equal(recorded.status,201,JSON.stringify(recorded));authorityId=recorded.data.id;
 assert.equal(recorded.data.organizationAuthorityVerified,false);
 const replay=await call('/api/external-trust/attestations','POST',{...payload,signatureB64});
 assert.equal(replay.status,200);assert.equal(replay.data.id,authorityId);
 assert.equal((await call('/api/external-trust/readiness/'+authorityId)).status,409);
 assert.equal((await call('/api/external-trust/review/attestations/'+authorityId+'/decide',
  'POST',reviewAuthority,'owner')).status,403);
 const [state]=await db.query<any[]>(`SELECT statement_json AS payload
  FROM inv_external_authority_attestations WHERE id=?`,[authorityId]);
 await db.execute(`UPDATE inv_external_authority_attestations SET statement_json=? WHERE id=?`,
  [JSON.stringify({...state[0].payload,organizationAuthorityVerified:true}),authorityId]);
 assert.equal((await call('/api/external-trust/review/attestations/'+authorityId,
  'GET',undefined,'reviewer')).status,409);
 await db.execute(`UPDATE inv_external_authority_attestations SET statement_json=? WHERE id=?`,
  [JSON.stringify(state[0].payload),authorityId]);
 const reviewed=await call('/api/external-trust/review/attestations/'+authorityId+'/decide',
  'POST',reviewAuthority,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.externallyVerifiedOrganization,false);
 assert.equal((await call('/api/external-trust/review/attestations/'+authorityId+'/decide',
  'POST',reviewAuthority,'reviewer')).status,409);
});
async function signedFeed(sequenceNumber:number,revokedFingerprints:string[],
 issuedAt=utc(-60_000),expiresAt=utc(3_600_000)){
 const base={issuerId,sequenceNumber,issuedAt,expiresAt,revokedFingerprints};
 const sig=await signTemplate('/api/external-trust/revocation-template',base);
 return {...base,signatureB64:sig};
}
test('revocation feed requires contiguous sequence, valid issuer signature, cumulative fingerprint set',async()=>{
 const first=await signedFeed(1,[]);
 assert.equal((await call('/api/external-trust/revocations','POST',
  {...first,signatureB64:Buffer.alloc(64).toString('base64')})).status,409);
 const created=await call('/api/external-trust/revocations','POST',first);
 assert.equal(created.status,201,JSON.stringify(created));
 assert.equal(created.data.externalPublisherAuthenticated,false);
 const retry=await call('/api/external-trust/revocations','POST',first);
 assert.equal(retry.status,200);assert.equal(retry.data.id,created.data.id);
 const ready=await call('/api/external-trust/readiness/'+authorityId);
 assert.equal(ready.status,200,JSON.stringify(ready));
 assert.equal(ready.data.cryptographicallyConsistentInternalEvidence,true);
 assert.equal(ready.data.productionReady,false);
 assert.equal(ready.data.externalIdentityVerified,false);
 assert.equal(ready.data.officialGrnAuthenticated,false);
 assert.equal(ready.data.availableToSell,null);
 const [prev]=await db.query<any[]>(`SELECT manifest_sha256 AS digest
  FROM inv_external_revocation_bundles WHERE id=?`,[created.data.id]);
 await db.execute(`UPDATE inv_external_revocation_bundles SET manifest_sha256=?
  WHERE id=?`,['f'.repeat(64),created.data.id]);
 assert.equal((await call('/api/external-trust/readiness/'+authorityId)).status,409);
 await db.execute(`UPDATE inv_external_revocation_bundles SET manifest_sha256=?
  WHERE id=?`,[prev[0].digest,created.data.id]);
 // Still AFTER issuedAt, but already expired relative to current UTC time.
 const expiredAt=utc(-30_000);
 await db.execute(`UPDATE inv_external_revocation_bundles SET expires_at=?
  WHERE id=?`,[expiredAt.replace('T',' ').replace('.000Z',''),created.data.id]);
 assert.equal((await call('/api/external-trust/readiness/'+authorityId)).status,409);
 await db.execute(`UPDATE inv_external_revocation_bundles SET expires_at=?
  WHERE id=?`,[first.expiresAt.replace('T',' ').replace('.000Z',''),created.data.id]);
 const skipped=await signedFeed(3,[]);
 assert.equal((await call('/api/external-trust/revocations','POST',skipped)).status,409);
 const second=await signedFeed(2,[vendorFingerprint]);
 const changed=await call('/api/external-trust/revocations','POST',second);
 assert.equal(changed.status,201,JSON.stringify(changed));
 assert.equal((await call('/api/external-trust/readiness/'+authorityId)).status,409);
 const sourced='/api/proof-foundation/message-template?'+new URLSearchParams({
  keyId:vendorKeyId,kind:'SUPPLIER_ACK_ASSERTION',sourceId:main.preparationId,
  reference:'CI-EXT-REVOCATION-2026',
  documentSha256:'a'.repeat(64),issuedAt:utc(-60_000)}).toString();
 assert.equal((await call(sourced)).status,409);
 const undo=await signedFeed(3,[]);
 assert.equal((await call('/api/external-trust/revocations','POST',undo)).status,409);
 await assert.rejects(db.execute(`UPDATE inv_external_authority_attestations
  SET external_authority_state='VERIFIED' WHERE id=?`,[authorityId]));
 await assert.rejects(db.execute(`UPDATE inv_external_issuer_candidates
  SET external_root_state='TRUSTED' WHERE id=?`,[issuerId]));
 await assert.rejects(db.execute(`UPDATE inv_external_revocation_bundles
  SET external_publisher_authenticated='YES' WHERE id=?`,[created.data.id]));
});
test('compromised issuer freeze is irreversible and no official GRN / stock endpoints exist',async()=>{
 const r=await call('/api/external-trust/issuers/'+issuerId+'/freeze','POST',{
  reason:'Issuer candidate signing key potentially compromised; block all use',
  evidenceRef:'CI-ISSUER-INCIDENT-2026'});
 assert.equal(r.status,201,JSON.stringify(r));
 assert.equal(r.data.irreversiblyFrozen,true);
 assert.equal((await call('/api/external-trust/issuers/'+issuerId+'/freeze','POST',{
  reason:'Repeated compromise report must not re-enable root',
  evidenceRef:'CI-ISSUER-INCIDENT-2026'})).status,409);
 assert.equal((await call('/api/external-trust/readiness/'+authorityId)).status,409);
 assert.equal((await call('/api/external-trust/revocation-template','POST',
  {issuerId,sequenceNumber:3,issuedAt:utc(-60_000),
   expiresAt:utc(3_600_000),revokedFingerprints:[vendorFingerprint]})).status,409);
 assert.equal((await call('/api/external-trust/authenticate-org','POST',{})).status,404);
 assert.equal((await call('/api/external-trust/post-grn','POST',{})).status,404);
 const auth=await call('/api/external-trust/authority');
 assert.equal(auth.status,200);
 assert.equal(auth.data.externalRootAuthenticated,false);
 assert.equal(auth.data.productionReady,false);
 const [stock]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,
  picked_quantity,posted_quantity FROM inv_stock_position_gates`);
 assert.ok(stock.length>0);
 assert.ok(stock.every(x=>Object.values(x).every(v=>Number(v)===0)));
});

const bridgeRoot=generateKeyPairSync('ed25519'),bridgeIssuer=generateKeyPairSync('ed25519');
let pinId='',bridgeIssuerId='',bridgeCredentialId='',bridgeFingerprint='';
function utcBridge(offset:number){
 return new Date(Math.floor((Date.now()+offset)/1000)*1000).toISOString();
}
function signBridge(v:object){
 return sign(null,Buffer.from(JSON.stringify(v),'utf8'),bridgeRoot.privateKey).toString('base64');
}
async function bridgeTemplate(path:string,body:object){
 const v=await call('/api/provider-bridge/'+path,'POST',body);
 assert.equal(v.status,200,JSON.stringify(v));
 assert.equal(v.data.message.externallyAuthenticatedRoot??v.data.message.externalPublisherVerified??false,false);
 return {...body,signatureB64:signBridge(v.data.message)};
}
const bridgePinReview={decision:'REVIEWED_HELD',
 reason:'Inspected server pinned key bytes only; external provider origin remains unverified',
 evidenceRef:'CI-PROVIDER-PIN-REVIEW-2026',evidenceInspected:true};
const bridgeCredReview={decision:'REVIEWED_CRYPTO_HELD',
 reason:'Rechecked root signed credential and organizational claim without legal identity proof',
 evidenceRef:'CI-PROVIDER-CRED-REVIEW-2026',evidenceInspected:true};
test('pin registration from SERVER ENV ONLY and independent reviewer cannot elevate root trust',async()=>{
 const publicDer=bridgeRoot.publicKey.export({format:'der',type:'spki'});
 const rootHash=(await import('node:crypto')).createHash('sha256').update(publicDer).digest('hex');
 process.env.PROVIDER_CODE='CI_SANDBOX_PROVIDER_2026';
 process.env.PROVIDER_HTTPS_ORIGIN='https://provider.example.invalid';
 process.env.PROVIDER_ROOT_SPKI_B64=publicDer.toString('base64');
 process.env.PROVIDER_ROOT_SHA256=rootHash;
 process.env.PROVIDER_TLS_SPKI_SHA256='c'.repeat(64);
 assert.equal((await call('/api/provider-bridge/pins','POST',
  {evidenceRef:'CI-PIN-EVIDENCE-2026',trusted:true})).status,400);
 assert.equal((await call('/api/provider-bridge/pins','POST',
  {evidenceRef:'CI-PIN-EVIDENCE-2026'},'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/provider-bridge/pins','POST',
  {evidenceRef:'CI-PIN-EVIDENCE-2026'},'reviewer')).status,403);
 const candidate=await call('/api/provider-bridge/pins','POST',
  {evidenceRef:'CI-PIN-EVIDENCE-2026'});
 assert.equal(candidate.status,201,JSON.stringify(candidate));
 pinId=candidate.data.id;assert.equal(candidate.data.externallyAuthenticated,false);
 const replay=await call('/api/provider-bridge/pins','POST',
  {evidenceRef:'CI-PIN-EVIDENCE-2026'});
 assert.equal(replay.status,200);assert.equal(replay.data.id,pinId);
 assert.equal((await call('/api/provider-bridge/review/pins','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/provider-bridge/review/pins/'+pinId+'/decide',
  'POST',{...bridgePinReview,decision:'TRUSTED_EXTERNAL'},'reviewer')).status,400);
 assert.equal((await call('/api/provider-bridge/review/pins/'+pinId+'/decide',
  'POST',{...bridgePinReview,evidenceInspected:false},'reviewer')).status,400);
 const reviewed=await call('/api/provider-bridge/review/pins/'+pinId+'/decide',
  'POST',bridgePinReview,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.externallyAuthenticated,false);
 assert.equal((await call('/api/provider-bridge/review/pins/'+pinId+'/decide',
  'POST',bridgePinReview,'reviewer')).status,409);
 const disabled=await call('/api/provider-bridge/feeds/pull-pinned-preview',
  'POST',{pinId});
 assert.equal(disabled.status,409,JSON.stringify(disabled));
});
test('root credential requires independent Phase 1AK issuer candidate and no external KYC',async()=>{
 const p={partyKind:'SUPPLIER',partyId:main.supplierId,
  organizationRegistration:'REG-BRIDGE-SUPPLIER-2026',
  issuerSpkiB64:bridgeIssuer.publicKey.export({format:'der',type:'spki'}).toString('base64'),
  evidenceRef:'CI-BRIDGE-ISSUER-CANDIDATE-2026'};
 const issuer=await call('/api/external-trust/issuers','POST',p);
 assert.equal(issuer.status,201,JSON.stringify(issuer));
 bridgeIssuerId=issuer.data.id;
 const rev=await call('/api/external-trust/review/issuers/'+bridgeIssuerId+'/decide',
  'POST',reviewIssuer,'reviewer');
 assert.equal(rev.status,201,JSON.stringify(rev));
 const [key]=await db.query<any[]>(`SELECT fingerprint_sha256 AS fp
  FROM inv_external_issuer_candidates WHERE id=?`,[bridgeIssuerId]);
 bridgeFingerprint=key[0].fp;
 const params={pinId,issuerId:bridgeIssuerId,purpose:'SUPPLIER_ACK',
  validFrom:utcBridge(-60_000),validUntil:utcBridge(3_600_000)};
 assert.equal((await call('/api/provider-bridge/credential-template',
  'POST',{...params,independentlyAuthenticated:true})).status,400);
 const signed=await bridgeTemplate('credential-template',params);
 assert.equal((await call('/api/provider-bridge/credentials','POST',
  {...signed,signatureB64:Buffer.alloc(64).toString('base64')})).status,409);
 const issued=await call('/api/provider-bridge/credentials','POST',signed);
 assert.equal(issued.status,201,JSON.stringify(issued));
 bridgeCredentialId=issued.data.id;
 assert.equal(issued.data.corporateIdentityVerified,false);
 const repeat=await call('/api/provider-bridge/credentials','POST',signed);
 assert.equal(repeat.status,200);assert.equal(repeat.data.id,bridgeCredentialId);
 assert.equal((await call('/api/provider-bridge/readiness/'+bridgeCredentialId)).status,409);
 assert.equal((await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId,
  'GET',undefined,'owner')).status,403);
 const detail=await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId,
  'GET',undefined,'reviewer');
 assert.equal(detail.status,200,JSON.stringify(detail));
 assert.equal(detail.data.rootSignatureMathMatched,true);
 assert.equal(detail.data.corporateIdentityVerified,false);
 const [original]=await db.query<any[]>(`SELECT message_json AS payload
  FROM inv_provider_org_credentials WHERE id=?`,[bridgeCredentialId]);
 await db.execute('UPDATE inv_provider_org_credentials SET message_json=? WHERE id=?',
  [JSON.stringify({...original[0].payload,independentCorporateVerification:true}),bridgeCredentialId]);
 assert.equal((await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId,
  'GET',undefined,'reviewer')).status,409);
 await db.execute('UPDATE inv_provider_org_credentials SET message_json=? WHERE id=?',
  [JSON.stringify(original[0].payload),bridgeCredentialId]);
 assert.equal((await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId+'/decide',
  'POST',{...bridgeCredReview,decision:'TRUSTED'},'reviewer')).status,400);
 const decided=await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId+'/decide',
  'POST',bridgeCredReview,'reviewer');
 assert.equal(decided.status,201,JSON.stringify(decided));
 assert.equal(decided.data.externalRootAuthenticated,false);
 assert.equal((await call('/api/provider-bridge/review/credentials/'+bridgeCredentialId+'/decide',
  'POST',bridgeCredReview,'reviewer')).status,409);
});
test('root-signed revocation snapshots are contiguous, cumulative, fresh and always non-authorizing',async()=>{
 const data={pinId,sequenceNumber:1,publishedAt:utcBridge(-60_000),
  validUntil:utcBridge(3_600_000),revokedFingerprints:[] as string[]};
 const first=await bridgeTemplate('feed-template',data);
 assert.equal((await call('/api/provider-bridge/feeds','POST',
  {...first,signatureB64:Buffer.alloc(64).toString('base64')})).status,409);
 const imported=await call('/api/provider-bridge/feeds','POST',first);
 assert.equal(imported.status,201,JSON.stringify(imported));
 assert.equal(imported.data.publisherExternallyVerified,false);
 const replay=await call('/api/provider-bridge/feeds','POST',first);
 assert.equal(replay.status,200);assert.equal(replay.data.id,imported.data.id);
 const ready=await call('/api/provider-bridge/readiness/'+bridgeCredentialId);
 assert.equal(ready.status,200,JSON.stringify(ready));
 assert.equal(ready.data.cryptographicSourceConsistent,true);
 assert.equal(ready.data.productionReady,false);
 assert.equal(ready.data.externalProviderAuthenticated,false);
 assert.equal(ready.data.availableToSell,null);
 const [prev]=await db.query<any[]>(`SELECT message_sha256 AS digest
  FROM inv_provider_revocation_feeds WHERE id=?`,[imported.data.id]);
 await db.execute('UPDATE inv_provider_revocation_feeds SET message_sha256=? WHERE id=?',
  ['a'.repeat(64),imported.data.id]);
 assert.equal((await call('/api/provider-bridge/readiness/'+bridgeCredentialId)).status,409);
 await db.execute('UPDATE inv_provider_revocation_feeds SET message_sha256=? WHERE id=?',
  [prev[0].digest,imported.data.id]);
 await db.execute('UPDATE inv_provider_revocation_feeds SET valid_until=? WHERE id=?',
  [utcBridge(-30_000).replace('T',' ').replace('.000Z',''),imported.data.id]);
 assert.equal((await call('/api/provider-bridge/readiness/'+bridgeCredentialId)).status,409);
 await db.execute('UPDATE inv_provider_revocation_feeds SET valid_until=? WHERE id=?',
  [data.validUntil.replace('T',' ').replace('.000Z',''),imported.data.id]);
 const gap=await bridgeTemplate('feed-template',{...data,sequenceNumber:3});
 assert.equal((await call('/api/provider-bridge/feeds','POST',gap)).status,409);
 const second=await bridgeTemplate('feed-template',
  {...data,sequenceNumber:2,revokedFingerprints:[bridgeFingerprint]});
 const banned=await call('/api/provider-bridge/feeds','POST',second);
 assert.equal(banned.status,201,JSON.stringify(banned));
 assert.equal((await call('/api/provider-bridge/readiness/'+bridgeCredentialId)).status,409);
 const undo=await bridgeTemplate('feed-template',{...data,sequenceNumber:3});
 assert.equal((await call('/api/provider-bridge/feeds','POST',undo)).status,409);
 await assert.rejects(db.execute(
  `UPDATE inv_provider_pin_candidates SET external_root_state='TRUSTED' WHERE id=?`,[pinId]));
 await assert.rejects(db.execute(
  `UPDATE inv_provider_org_credentials SET corporate_identity_state='VERIFIED' WHERE id=?`,
  [bridgeCredentialId]));
 await assert.rejects(db.execute(
  `UPDATE inv_provider_revocation_feeds SET external_publisher_state='TRUSTED' WHERE id=?`,
  [banned.data.id]));
});

const sandboxLeafKey=generateKeyPairSync('ed25519');
let sandboxCaseId='',sandboxCertId='',sandboxIssuerFingerprint='';
function ephemeralOneHopCerts(){
 const dir=mkdtempSync(join(tmpdir(),'aaditech-sandbox-chain-'));
 try{
  writeFileSync(join(dir,'root.key'),bridgeRoot.privateKey.export({type:'pkcs8',format:'pem'}));
  writeFileSync(join(dir,'leaf.key'),sandboxLeafKey.privateKey.export({type:'pkcs8',format:'pem'}));
  const run=(args:string[])=>execFileSync('openssl',args,{cwd:dir,stdio:'pipe'});
  run(['req','-x509','-new','-key','root.key','-out','root.crt','-days','4',
   '-subj','/CN=CI Provider CA/O=Testing Only',
   '-addext','basicConstraints=critical,CA:TRUE',
   '-addext','keyUsage=critical,keyCertSign,cRLSign']);
  run(['req','-new','-key','leaf.key','-out','leaf.csr',
   '-subj','/CN=CI Signatory/O=Testing Only']);
  writeFileSync(join(dir,'leaf.ext'),
   'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
  run(['x509','-req','-in','leaf.csr','-CA','root.crt','-CAkey','root.key',
   '-CAcreateserial','-out','leaf.crt','-days','2','-extfile','leaf.ext']);
  return {rootCertificatePem:readFileSync(join(dir,'root.crt'),'utf8'),
   leafCertificatePem:readFileSync(join(dir,'leaf.crt'),'utf8')};
 }finally{rmSync(dir,{recursive:true,force:true});}
}
const caseApproval={decision:'REVIEWED_EVIDENCE_HELD',
 reason:'Inspected document hashes and claimed signatory; actual registry not contacted',
 evidenceRef:'CI-CORPORATE-SANDBOX-REVIEW-2026',
 registryInspected:true,signatoryInspected:true};
const certificateApproval={decision:'REVIEWED_CRYPTO_HELD',
 reason:'Inspected ephemeral CA and leaf signature, not real provider or complete PKIX policy',
 evidenceRef:'CI-CERTIFICATE-REVIEW-2026',
 certificateInspected:true,policyGapsAcknowledged:true};
test('Phase 1AM onboarding case only records claimed organizational and delegated signatory evidence',async()=>{
 const issuerPayload={partyKind:'SUPPLIER',partyId:main.supplierId,
  organizationRegistration:'REG-SANDBOX-CI-2026',
  issuerSpkiB64:sandboxLeafKey.publicKey.export({format:'der',type:'spki'}).toString('base64'),
  evidenceRef:'CI-SANDBOX-ISSUER-REGISTRATION'};
 const issuer=await call('/api/external-trust/issuers','POST',issuerPayload);
 assert.equal(issuer.status,201,JSON.stringify(issuer));
 const issuerId=issuer.data.id;
 const issuerReviewed=await call('/api/external-trust/review/issuers/'+issuerId+'/decide',
  'POST',reviewIssuer,'reviewer');
 assert.equal(issuerReviewed.status,201,JSON.stringify(issuerReviewed));
 const [keys]=await db.query<any[]>(`SELECT fingerprint_sha256 AS fp FROM inv_external_issuer_candidates WHERE id=?`,[issuerId]);
 sandboxIssuerFingerprint=keys[0].fp;
 const claim={pinId,issuerId,purpose:'SUPPLIER_ACK',
  registryReference:issuerPayload.organizationRegistration,
  identityDocumentSha256:'a'.repeat(64),signatoryReference:'SANDBOX-SIGNATORY-TICKET-2026',
  signatoryDocumentSha256:'b'.repeat(64),evidenceRef:'CI-ORGANIZATION-CLAIM-2026'};
 assert.equal((await call('/api/provider-sandbox/cases','POST',
  {...claim,corporateIdentityVerified:true})).status,400);
 assert.equal((await call('/api/provider-sandbox/cases','POST',claim,'reviewer')).status,403);
 assert.equal((await call('/api/provider-sandbox/cases','POST',claim,'owner',{csrf:false})).status,403);
 const c=await call('/api/provider-sandbox/cases','POST',claim);
 assert.equal(c.status,201,JSON.stringify(c));sandboxCaseId=c.data.id;
 assert.equal(c.data.corporateIdentityVerified,false);
 const replay=await call('/api/provider-sandbox/cases','POST',claim);
 assert.equal(replay.status,200);assert.equal(replay.data.id,sandboxCaseId);
 assert.equal((await call('/api/provider-sandbox/cases','POST',
  {...claim,signatoryDocumentSha256:'c'.repeat(64)})).status,409);
 assert.equal((await call('/api/provider-sandbox/review/cases','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/provider-sandbox/review/cases/'+sandboxCaseId+'/decide',
  'POST',{...caseApproval,decision:'EXTERNALLY_AUTHENTICATED'},'reviewer')).status,400);
 assert.equal((await call('/api/provider-sandbox/review/cases/'+sandboxCaseId+'/decide',
  'POST',{...caseApproval,signatoryInspected:false},'reviewer')).status,400);
 const reviewed=await call('/api/provider-sandbox/review/cases/'+sandboxCaseId+'/decide',
  'POST',caseApproval,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.corporateIdentityAuthenticated,false);
 assert.equal((await call('/api/provider-sandbox/review/cases/'+sandboxCaseId+'/decide',
  'POST',caseApproval,'reviewer')).status,409);
});
test('Phase 1AM X509 one-hop pinned CA crypto check is HELD and independent reviewer cannot authorize production',async()=>{
 const pair=ephemeralOneHopCerts(),body={caseId:sandboxCaseId,...pair};
 assert.equal((await call('/api/provider-sandbox/certificates','POST',
  {...body,realProviderIssued:true})).status,400);
 assert.equal((await call('/api/provider-sandbox/certificates','POST',
  {...body,rootCertificatePem:pair.leafCertificatePem})).status,409);
 const created=await call('/api/provider-sandbox/certificates','POST',body);
 assert.equal(created.status,201,JSON.stringify(created));sandboxCertId=created.data.id;
 assert.equal(created.data.fullRfc5280PathValidated,false);
 assert.equal(created.data.providerIssuedAuthenticated,false);
 const replay=await call('/api/provider-sandbox/certificates','POST',body);
 assert.equal(replay.status,200);assert.equal(replay.data.id,sandboxCertId);
 assert.equal((await call('/api/provider-sandbox/readiness/'+sandboxCertId)).status,409);
 assert.equal((await call('/api/provider-sandbox/review/certificates/'+sandboxCertId,
  'GET',undefined,'owner')).status,403);
 const detail=await call('/api/provider-sandbox/review/certificates/'+sandboxCertId,
  'GET',undefined,'reviewer');
 assert.equal(detail.status,200,JSON.stringify(detail));
 assert.equal(detail.data.oneHopSignatureMatched,true);
 assert.equal(detail.data.fullRfc5280PathValidated,false);
 const [original]=await db.query<any[]>(`SELECT leaf_certificate_sha256 AS digest
  FROM inv_sandbox_cert_packages WHERE id=?`,[sandboxCertId]);
 await db.execute('UPDATE inv_sandbox_cert_packages SET leaf_certificate_sha256=? WHERE id=?',
  ['f'.repeat(64),sandboxCertId]);
 assert.equal((await call('/api/provider-sandbox/review/certificates/'+sandboxCertId,
  'GET',undefined,'reviewer')).status,409);
 await db.execute('UPDATE inv_sandbox_cert_packages SET leaf_certificate_sha256=? WHERE id=?',
  [original[0].digest,sandboxCertId]);
 assert.equal((await call('/api/provider-sandbox/review/certificates/'+sandboxCertId+'/decide',
  'POST',{...certificateApproval,decision:'PRODUCTION_READY'},'reviewer')).status,400);
 assert.equal((await call('/api/provider-sandbox/review/certificates/'+sandboxCertId+'/decide',
  'POST',{...certificateApproval,policyGapsAcknowledged:false},'reviewer')).status,400);
 const reviewed=await call('/api/provider-sandbox/review/certificates/'+sandboxCertId+'/decide',
  'POST',certificateApproval,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.fullRfc5280PathValidated,false);
 const ready=await call('/api/provider-sandbox/readiness/'+sandboxCertId);
 assert.equal(ready.status,200,JSON.stringify(ready));
 assert.equal(ready.data.productionReady,false);
 assert.equal(ready.data.corporateIdentityVerified,false);
 assert.equal(ready.data.stockPostingEnabled,false);
 const checked=await call('/api/provider-sandbox/revocation-checks','POST',{certId:sandboxCertId});
 assert.equal(checked.status,201,JSON.stringify(checked));
 assert.equal(checked.data.status,'CHECKED_HELD');
 assert.equal(checked.data.actualPublisherAuthenticated,false);
 const again=await call('/api/provider-sandbox/revocation-checks','POST',{certId:sandboxCertId});
 assert.equal(again.status,200);assert.equal(again.data.id,checked.data.id);
 await assert.rejects(db.execute(
  `UPDATE inv_sandbox_onboarding_cases SET corporate_identity_state='VERIFIED' WHERE id=?`,
  [sandboxCaseId]));
 await assert.rejects(db.execute(
  `UPDATE inv_sandbox_cert_packages SET rfc5280_path_validated='YES' WHERE id=?`,
  [sandboxCertId]));
});
test('Phase 1AM new provider-signed revocation of sandbox leaf fails closed, cannot un-revoke',async()=>{
 const signed=await bridgeTemplate('feed-template',{pinId,sequenceNumber:3,
  publishedAt:utcBridge(-60_000),validUntil:utcBridge(3_600_000),
  revokedFingerprints:[bridgeFingerprint,sandboxIssuerFingerprint].sort()});
 const imported=await call('/api/provider-bridge/feeds','POST',signed);
 assert.equal(imported.status,201,JSON.stringify(imported));
 assert.equal((await call('/api/provider-sandbox/readiness/'+sandboxCertId)).status,409);
 assert.equal((await call('/api/provider-sandbox/revocation-checks','POST',
  {certId:sandboxCertId})).status,409);
 const antiRollback=await bridgeTemplate('feed-template',{pinId,sequenceNumber:4,
  publishedAt:utcBridge(-60_000),validUntil:utcBridge(3_600_000),
  revokedFingerprints:[sandboxIssuerFingerprint]});
 assert.equal((await call('/api/provider-bridge/feeds','POST',antiRollback)).status,409);
 assert.equal((await call('/api/provider-sandbox/official-grn','POST',{})).status,404);
 assert.equal((await call('/api/provider-sandbox/stock-post','POST',{})).status,404);
 const status=await call('/api/provider-sandbox/authority');
 assert.equal(status.status,200);
 assert.equal(status.data.productionReady,false);
 assert.equal(status.data.independentlyVerifiedCorporateIdentity,false);
 const [stock]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,
  picked_quantity,posted_quantity FROM inv_stock_position_gates`);
 assert.ok(stock.length>0);
 assert.ok(stock.every(x=>Object.values(x).every(v=>Number(v)===0)));
});
test('emergency pinned provider freeze blocks all signed evidence and stock never moves',async()=>{
 const revoked=await call('/api/provider-bridge/pins/'+pinId+'/freeze','POST',
  {reason:'Suspected provider root compromise, quarantine before next evidence import',
   evidenceRef:'CI-PIN-COMPROMISE-2026'});
 assert.equal(revoked.status,201,JSON.stringify(revoked));
 assert.equal(revoked.data.permanentlyFrozen,true);
 assert.equal((await call('/api/provider-bridge/readiness/'+bridgeCredentialId)).status,409);
 assert.equal((await call('/api/provider-bridge/pins/'+pinId+'/freeze','POST',
  {reason:'Repeated incident; must remain permanently frozen',
   evidenceRef:'CI-PIN-COMPROMISE-2026'})).status,409);
 const authority=await call('/api/provider-bridge/authority');
 assert.equal(authority.status,200);
 assert.equal(authority.data.externalTrustProviderAuthenticated,false);
 assert.equal(authority.data.productionReady,false);
 assert.equal((await call('/api/provider-bridge/official-grn','POST',{})).status,404);
 assert.equal((await call('/api/provider-bridge/post-stock','POST',{})).status,404);
 const [rows]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,
  picked_quantity,posted_quantity FROM inv_stock_position_gates`);
 assert.ok(rows.length);
 assert.ok(rows.every(x=>Object.values(x).every(v=>Number(v)===0)));
});
