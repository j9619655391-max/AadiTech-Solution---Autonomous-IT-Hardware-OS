import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/stockFoundation/ownerRouter';
import reviewRouter from '../server/stockFoundation/reviewRouter';
import {claimDigest,heldGrnSnapshot} from '../server/evidenceChain/validation';
import {checkHeldSource,checkClaim,checkQuarantine,makePack} from '../server/evidenceChain/integrity';
import {dispatchManifest,sha} from '../server/dispatch/validation';
import {validateInbound,canonicalIntakeHash} from '../server/intake/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Stock foundation integration allowed only on disposable CI MySQL');
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
test('create full 1AC/1AD/1AE/1AF synthetic HELD source in disposable MySQL',async()=>{
 for(const [id,token,role,password] of [[owner,ownerToken,'OWNER',ownerPass],
  [reviewer,reviewerToken,'REVIEWER',reviewerPass]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
   [id,'stock-'+id+'@example.invalid','Stock Foundation CI',await hashPassword(password),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 main=await withHeldSource(await fixture('STOCK_MAIN'));
 second=await withHeldSource(await fixture('STOCK_SECOND'));
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/stock-foundation/review',reviewRouter);
 app.use('/api/stock-foundation',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('role, CSRF, step-up and strict payload defend release and reservation paths',async()=>{
 const body={heldGrnId:main.heldGrnId};
 assert.equal((await call('/api/stock-foundation/held-grn','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/stock-foundation/held-grn','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/stock-foundation/review/release-intents','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/stock-foundation/release-intents','POST',body)).status,403);
 assert.equal((await call('/api/stock-foundation/release-intents','POST',body,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/stock-foundation/release-intents','POST',body,'reviewer')).status,403);
 const [u,v]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass}),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(u.status,200);assert.equal(v.status,200);
 ownerStep=String(u.data.stepUpToken);reviewerStep=String(v.data.stepUpToken);
 assert.equal((await call('/api/stock-foundation/release-intents','POST',
  {...body,postStock:true})).status,400);
 const eligible=await call('/api/stock-foundation/held-grn');
 assert.equal(eligible.status,200);
 assert.equal(eligible.data.stockPostingEnabled,false);
 assert.ok(eligible.data.items.some((x:any)=>x.heldGrnId===main.heldGrnId));
});
let releaseId='',secondReleaseId='';
test('tampered 1AF GRN held SHA is denied, then snapshot-bound release intent is prepared exactly once',async()=>{
 const [prev]=await db.query<any[]>('SELECT snapshot_sha256 FROM inv_grn_held_records WHERE id=?',
  [main.heldGrnId]);
 await db.execute('UPDATE inv_grn_held_records SET snapshot_sha256=? WHERE id=?',
  ['a'.repeat(64),main.heldGrnId]);
 assert.equal((await call('/api/stock-foundation/release-intents','POST',
  {heldGrnId:main.heldGrnId})).status,409);
 await db.execute('UPDATE inv_grn_held_records SET snapshot_sha256=? WHERE id=?',
  [prev[0].snapshot_sha256,main.heldGrnId]);
 const pair=await Promise.all([
  call('/api/stock-foundation/release-intents','POST',{heldGrnId:main.heldGrnId}),
  call('/api/stock-foundation/release-intents','POST',{heldGrnId:main.heldGrnId})
 ]);
 assert.ok(pair.some(x=>x.status===201),JSON.stringify(pair));
 assert.ok(pair.every(x=>[200,201,409].includes(x.status)),JSON.stringify(pair));
 const replay=await call('/api/stock-foundation/release-intents','POST',
  {heldGrnId:main.heldGrnId});
 assert.equal(replay.status,200,JSON.stringify(replay));
 const created=pair.find(x=>x.status===201)!;
 assert.equal(replay.data.id,created.data.id);
 releaseId=replay.data.id;
 const [lines]=await db.query<any[]>('SELECT * FROM inv_stock_release_intent_lines WHERE release_intent_id=?',
  [releaseId]);
 assert.equal(lines.length,2);
 const [positions]=await db.query<any[]>(`SELECT available_quantity,reserved_quantity,
  picked_quantity,posted_quantity FROM inv_stock_position_gates`);
 assert.equal(positions.length,2);
 assert.ok(positions.every(r=>[r.available_quantity,r.reserved_quantity,
  r.picked_quantity,r.posted_quantity].every(v=>Number(v)===0)));
 const other=await call('/api/stock-foundation/release-intents','POST',
  {heldGrnId:second.heldGrnId});
 assert.equal(other.status,201);secondReleaseId=other.data.id;
});
test('MySQL hard-zero CHECK rejects all direct positive, negative, reserved or picked stock mutations',async()=>{
 const [site]=await db.query<any[]>('SELECT site_id,product_id FROM inv_stock_position_gates LIMIT 1');
 assert.equal(site.length,1);
 for(const [col,value] of [['available_quantity',1],['reserved_quantity',1],
  ['picked_quantity',1],['posted_quantity',1],['available_quantity',-1]] as const){
  await assert.rejects(db.execute(`UPDATE inv_stock_position_gates SET ${col}=?
    WHERE site_id=? AND product_id=?`,
    [value,site[0].site_id,site[0].product_id]));
 }
 const listed=await call('/api/stock-foundation/positions');
 assert.equal(listed.status,200);
 assert.equal(listed.data.postingAllowed,false);
 assert.ok(listed.data.items.every((p:any)=>Number(p.available)===0&&Number(p.reserved)===0));
});
test('reviewer refuses tampered serial identity, denies self-review and can only approve HELD release',async()=>{
 const path='/api/stock-foundation/review/release-intents/'+releaseId+'/decide';
 const body={decision:'REVIEWED_HELD',reason:'Independently inspected full internally observed serial and lot register',
  evidenceRef:'REVIEW-RELEASE-2026',sourceInspected:true};
 assert.equal((await call(path,'POST',body,'owner')).status,403);
 assert.equal((await call(path,'POST',{...body,sourceInspected:false},'reviewer')).status,400);
 assert.equal((await call(path,'POST',body,'reviewer',{stepUp:false})).status,403);
 const [before]=await db.query<any[]>(`SELECT id,serials_json FROM inv_stock_release_intent_lines
  WHERE release_intent_id=? AND tracking_mode='SERIAL'`,[releaseId]);
 assert.equal(before.length,1);
 await db.execute('UPDATE inv_stock_release_intent_lines SET serials_json=? WHERE id=?',
  [JSON.stringify(['FORGED-SERIAL-2026','FORGED-SERIAL-2027']),before[0].id]);
 assert.equal((await call(path,'POST',body,'reviewer')).status,409);
 await db.execute('UPDATE inv_stock_release_intent_lines SET serials_json=? WHERE id=?',
  [JSON.stringify(before[0].serials_json),before[0].id]);
 const review=await call(path,'POST',body,'reviewer');
 assert.equal(review.status,201);assert.equal(review.data.status,'REVIEWED_HELD');
 assert.equal(review.data.postingState,'DISABLED');assert.equal(review.data.stockPosted,0);
 assert.equal((await call(path,'POST',body,'reviewer')).status,409);
 const [rows]=await db.query<any[]>(`SELECT state,posting_state,snapshot_json
  FROM inv_stock_release_holds WHERE release_intent_id=?`,[releaseId]);
 assert.equal(rows.length,1);assert.equal(rows[0].state,'HELD');
 assert.equal(rows[0].posting_state,'DISABLED');
 assert.equal(rows[0].snapshot_json.stockPosted,false);
 const other=await call('/api/stock-foundation/review/release-intents/'+secondReleaseId+'/decide',
  'POST',{...body,decision:'REJECTED_INTERNAL',sourceInspected:false},'reviewer');
 assert.equal(other.status,201);
 const [otherHold]=await db.query<any[]>(`SELECT COUNT(*) AS n
  FROM inv_stock_release_holds WHERE release_intent_id=?`,[secondReleaseId]);
 assert.equal(Number(otherHold[0].n),0);
});
test('nonallocating planning is immutable, quantity-capped, no-negative and concurrent replay safe',async()=>{
 const body={releaseIntentId:releaseId,productId:main.productId,
  quantity:2,planningRef:'CUSTOMER-PLANNING-REF-2026'};
 assert.equal((await call('/api/stock-foundation/reservation-plans','POST',
  {...body,allocateNow:true})).status,400);
 assert.equal((await call('/api/stock-foundation/reservation-plans','POST',
  {...body,quantity:3})).status,409);
 const responses=await Promise.all([
  call('/api/stock-foundation/reservation-plans','POST',body),
  call('/api/stock-foundation/reservation-plans','POST',body)]);
 assert.ok(responses.some(x=>x.status===201),JSON.stringify(responses));
 assert.ok(responses.every(x=>[200,201,409].includes(x.status)),JSON.stringify(responses));
 const replayPlan=await call('/api/stock-foundation/reservation-plans','POST',body);
 assert.equal(replayPlan.status,200,JSON.stringify(replayPlan));
 assert.equal(replayPlan.data.id,responses.find(x=>x.status===201)!.data.id);
 assert.equal(replayPlan.data.allocatedQuantity,0);
 assert.equal((await call('/api/stock-foundation/reservation-plans','POST',
  {...body,quantity:1})).status,409);
 assert.equal((await call('/api/stock-foundation/reservation-plans','POST',
  {...body,releaseIntentId:secondReleaseId})).status,409);
 const attempt=await call('/api/stock-foundation/allocation-attempt','POST',body);
 assert.equal(attempt.status,409);
 const [stored]=await db.query<any[]>(`SELECT requested_quantity,state,reservation_state
  FROM inv_reservation_planning_intents WHERE release_intent_id=? AND product_id=?`,
  [releaseId,main.productId]);
 assert.equal(stored.length,1);assert.equal(Number(stored[0].requested_quantity),2);
 assert.equal(stored[0].state,'HELD');assert.equal(stored[0].reservation_state,'DISABLED');
 assert.equal((await call('/api/stock-foundation/stock-post','POST',body)).status,404);
 assert.equal((await call('/api/stock-foundation/movements','POST',body)).status,404);
 const after=await call('/api/stock-foundation/positions');
 assert.equal(after.status,200);assert.equal(after.data.postedStock,0);
 assert.equal(after.data.allocatedQuantity,0);assert.equal(after.data.availableToSell,null);
});
