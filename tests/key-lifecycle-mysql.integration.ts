import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync,sign} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/keyLifecycle/ownerRouter';
import reviewRouter from '../server/keyLifecycle/reviewRouter';
import proofOwnerRouter from '../server/proofFoundation/ownerRouter';
import proofReviewRouter from '../server/proofFoundation/reviewRouter';
import {readHeldGrnSource} from '../server/stockFoundation/integrity';
import {releaseSnapshot,releaseHoldSnapshot} from '../server/stockFoundation/validation';
import {claimDigest,heldGrnSnapshot} from '../server/evidenceChain/validation';
import {checkHeldSource,checkClaim,checkQuarantine,makePack} from '../server/evidenceChain/integrity';
import {dispatchManifest,sha} from '../server/dispatch/validation';
import {validateInbound,canonicalIntakeHash} from '../server/intake/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Key lifecycle integration allowed only on disposable CI MySQL');
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
test('isolated 1AC–1AF source and independent actor auth for key lifecycle',async()=>{
 for(const [id,token,role,password] of [[owner,ownerToken,'OWNER',ownerPass],
  [reviewer,reviewerToken,'REVIEWER',reviewerPass]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
   [id,'lifecycle-'+id+'@example.invalid','Key Lifecycle CI',
    await hashPassword(password),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES(?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 main=await withHeldSource(await fixture('LIFECYCLE_MAIN'));
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/proof-foundation/review',proofReviewRouter);
 app.use('/api/proof-foundation',proofOwnerRouter);
 app.use('/api/key-lifecycle/review',reviewRouter);
 app.use('/api/key-lifecycle',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
async function registerCandidate(p:typeof pairOld){
 const key={partyKind:'SUPPLIER',partyId:main.supplierId,
  publicKeySpkiB64:p.publicKey.export({format:'der',type:'spki'}).toString('base64'),
  evidenceRef:'CANDIDATE-KEY-TICKET-2026'};
 const registered=await call('/api/proof-foundation/keys','POST',key);
 assert.equal(registered.status,201,JSON.stringify(registered));
 const keyId=registered.data.id as string;
 const reviewed=await call('/api/proof-foundation/review/keys/'+keyId+'/decide','POST',{
  decision:'REVIEWED_UNTRUSTED',
  reason:'Key candidate format inspected independently; external supplier owner unknown',
  evidenceRef:'CI-KEY-WITNESS-2026',documentInspected:true},'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 return keyId;
}
test('owner/reviewer role segregation, CSRF and privileged step-up protect challenge',async()=>{
 assert.equal((await call('/api/key-lifecycle/keys','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/key-lifecycle/keys','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/key-lifecycle/review/receipts','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/key-lifecycle/challenges','POST',{keyId:randomUUID()})).status,403);
 const [a,b]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass}),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(a.status,200);assert.equal(b.status,200);
 ownerStep=String(a.data.stepUpToken);reviewerStep=String(b.data.stepUpToken);
 oldKey=await registerCandidate(pairOld);
 newKey=await registerCandidate(pairNew);
 emergencyKey=await registerCandidate(pairEmergency);
 assert.equal((await call('/api/key-lifecycle/challenges','POST',{keyId:oldKey},'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/key-lifecycle/challenges','POST',{keyId:oldKey},'reviewer')).status,403);
 assert.equal((await call('/api/key-lifecycle/challenges','POST',{keyId:oldKey,trust:true})).status,400);
});
async function possession(keyId:string,privateKey:typeof pairOld.privateKey){
 const created=await call('/api/key-lifecycle/challenges','POST',{keyId});
 assert.equal(created.status,201,JSON.stringify(created));
 assert.equal(created.data.identityAuthenticated,false);
 const message=created.data.message,canonical=created.data.canonicalUtf8 as string;
 assert.equal(message.keyId,keyId);
 assert.equal(canonical,JSON.stringify(message));
 const sig=sign(null,Buffer.from(canonical,'utf8'),privateKey).toString('base64');
 const claim={challengeId:created.data.challengeId,nonceB64:message.nonceB64,signatureB64:sig};
 assert.equal((await call('/api/key-lifecycle/responses','POST',
  {...claim,signatureB64:Buffer.alloc(64).toString('base64')})).status,409);
 assert.equal((await call('/api/key-lifecycle/responses','POST',
  {...claim,nonceB64:Buffer.alloc(32).toString('base64')})).status,409);
 const sent=await call('/api/key-lifecycle/responses','POST',claim);
 assert.equal(sent.status,201,JSON.stringify(sent));
 assert.equal(sent.data.externallyVerifiedKeyOwner,false);
 assert.equal((await call('/api/key-lifecycle/responses','POST',claim)).status,409);
 const id=sent.data.receiptId as string;
 assert.equal((await call('/api/key-lifecycle/review/receipts/'+id)).status,403);
 const inspected=await call('/api/key-lifecycle/review/receipts/'+id,
  'GET',undefined,'reviewer');
 assert.equal(inspected.status,200,JSON.stringify(inspected));
 assert.equal(inspected.data.signatureMatched,true);
 assert.equal(inspected.data.actualSupplierIdentityVerified,false);
 assert.equal((await call('/api/key-lifecycle/review/receipts/'+id+'/decide',
  'POST',{...positive,decision:'TRUSTED'},'reviewer')).status,400);
 assert.equal((await call('/api/key-lifecycle/review/receipts/'+id+'/decide',
  'POST',positive,'owner')).status,403);
 const reviewed=await call('/api/key-lifecycle/review/receipts/'+id+'/decide',
  'POST',positive,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.status,'REVIEWED_UNTRUSTED');
 assert.equal((await call('/api/key-lifecycle/review/receipts/'+id+'/decide',
  'POST',positive,'reviewer')).status,409);
 return id;
}
test('Ed25519 nonce possession one-shot, deterministic source and reviewer independently attest only UNTRUSTED',async()=>{
 oldReceipt=await possession(oldKey,pairOld.privateKey);
 newReceipt=await possession(newKey,pairNew.privateKey);
 const [receipts]=await db.query<any[]>(`SELECT p.id,p.status,c.status AS challenge_status,
  c.consumed_at,c.message_sha256,v.decision FROM inv_key_possession_receipts p
  JOIN inv_key_possession_challenges c ON c.id=p.challenge_id
  JOIN inv_key_possession_reviews v ON v.receipt_id=p.id
  WHERE p.key_id=?`,[oldKey]);
 assert.equal(receipts.length,1);
 assert.equal(receipts[0].status,'MATCHED_INTERNAL');
 assert.equal(receipts[0].challenge_status,'MATCHED_INTERNAL');
 assert.equal(receipts[0].decision,'REVIEWED_UNTRUSTED');
});
test('expired challenge and changed stored digest are rejected; no possession receipt created',async()=>{
 const made=await call('/api/key-lifecycle/challenges','POST',{keyId:emergencyKey});
 assert.equal(made.status,201);
 const claim={challengeId:made.data.challengeId,nonceB64:made.data.message.nonceB64,
  signatureB64:sign(null,Buffer.from(made.data.canonicalUtf8,'utf8'),
   pairEmergency.privateKey).toString('base64')};
 const [prev]=await db.query<any[]>(`SELECT message_sha256 FROM inv_key_possession_challenges WHERE id=?`,
  [claim.challengeId]);
 await db.execute('UPDATE inv_key_possession_challenges SET message_sha256=? WHERE id=?',
  ['a'.repeat(64),claim.challengeId]);
 assert.equal((await call('/api/key-lifecycle/responses','POST',claim)).status,409);
 await db.execute('UPDATE inv_key_possession_challenges SET message_sha256=?,expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND) WHERE id=?',
  [prev[0].message_sha256,claim.challengeId]);
 assert.equal((await call('/api/key-lifecycle/responses','POST',claim)).status,409);
 const [receipts]=await db.query<any[]>(`SELECT COUNT(*) AS n FROM inv_key_possession_receipts
  WHERE challenge_id=?`,[claim.challengeId]);
 assert.equal(Number(receipts[0].n),0);
});
function sourceTemplate(keyId:string){
 return '/api/proof-foundation/message-template?'+new URLSearchParams({
  keyId,kind:'SUPPLIER_ACK_ASSERTION',sourceId:main.preparationId,
  reference:'CI-KEY-ROTATION-2026',
  documentSha256:'a'.repeat(64),issuedAt:'2026-11-12T00:00:00.000Z'}).toString();
}
test('independent rotation suspends both keys, retires old atomically, keeps new UNTRUSTED',async()=>{
 assert.equal(((await call(sourceTemplate(oldKey))).status),200);
 const request={oldKeyId:oldKey,newKeyId:newKey,
  reason:'Rotate candidate key only after two witnessed offline possession checks',
  evidenceRef:'CI-ROTATION-TICKET-2026'};
 assert.equal((await call('/api/key-lifecycle/rotations','POST',
  {...request,trustNewKey:true})).status,400);
 const made=await call('/api/key-lifecycle/rotations','POST',request);
 assert.equal(made.status,201,JSON.stringify(made));
 rotationId=made.data.rotationId;
 assert.equal(made.data.oldKeySuspended,true);
 assert.equal(((await call(sourceTemplate(oldKey))).status),409);
 assert.equal(((await call(sourceTemplate(newKey))).status),409);
 assert.equal((await call('/api/key-lifecycle/review/rotations/'+rotationId+'/decide',
  'POST',positive,'owner')).status,403);
 assert.equal((await call('/api/key-lifecycle/review/rotations/'+rotationId+'/decide',
  'POST',{...positive,possessionInspected:false},'reviewer')).status,400);
 const reviewed=await call('/api/key-lifecycle/review/rotations/'+rotationId+'/decide',
  'POST',positive,'reviewer');
 assert.equal(reviewed.status,201,JSON.stringify(reviewed));
 assert.equal(reviewed.data.oldKeyRetired,true);
 assert.equal(reviewed.data.newKeyExternalTrustEstablished,false);
 assert.equal((await call('/api/key-lifecycle/review/rotations/'+rotationId+'/decide',
  'POST',positive,'reviewer')).status,409);
 const [retired]=await db.query<any[]>('SELECT event_type FROM inv_key_retirements WHERE key_id=?',
  [oldKey]);
 assert.equal(retired.length,1);
 assert.equal(retired[0].event_type,'ROTATION_RETIRED');
 assert.equal(((await call(sourceTemplate(oldKey))).status),409);
 const newReady=await call(sourceTemplate(newKey));
 assert.equal(newReady.status,200,JSON.stringify(newReady));
 assert.equal(newReady.data.trustAnchorEstablished,false);
});
test('emergency revocation effective immediately, refuses reuse and cannot enable trust/stock',async()=>{
 const revoked=await call('/api/key-lifecycle/keys/'+emergencyKey+'/revoke',
  'POST',{reason:'Suspected compromise of self-registered candidate, block now',
   evidenceRef:'SECURITY-INCIDENT-KEY-2026'});
 assert.equal(revoked.status,201,JSON.stringify(revoked));
 assert.equal(revoked.data.irreversible,true);
 assert.equal(((await call(sourceTemplate(emergencyKey))).status),409);
 assert.equal((await call('/api/key-lifecycle/challenges','POST',{keyId:emergencyKey})).status,409);
 assert.equal((await call('/api/key-lifecycle/keys/'+emergencyKey+'/revoke',
  'POST',{reason:'Repeated emergency revoke attempt should conflict',
   evidenceRef:'SECURITY-INCIDENT-KEY-2026'})).status,409);
 await assert.rejects(db.execute(`UPDATE inv_key_retirements SET event_type='TRUSTED'
  WHERE key_id=?`,[emergencyKey]));
 const [gates]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,picked_quantity,
  posted_quantity FROM inv_stock_position_gates`);
 assert.ok(gates.length>=2);
 assert.ok(gates.every(x=>Object.values(x).every(v=>Number(v)===0)));
 assert.equal((await call('/api/key-lifecycle/trust-external','POST',{})).status,404);
 assert.equal((await call('/api/key-lifecycle/post-grn','POST',{})).status,404);
});
