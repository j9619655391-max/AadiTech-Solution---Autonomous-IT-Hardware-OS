import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/evidenceChain/ownerRouter';
import reviewRouter from '../server/evidenceChain/reviewRouter';
import {dispatchManifest,sha} from '../server/dispatch/validation';
import {validateInbound,canonicalIntakeHash} from '../server/intake/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Evidence-chain integration allowed only on disposable CI MySQL');
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

test('create independent synthetic owner/reviewer, held source and witnessed quarantine in disposable MySQL',async()=>{
 for(const [id,token,role,password] of [[owner,ownerToken,'OWNER',ownerPass],
  [reviewer,reviewerToken,'REVIEWER',reviewerPass]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
   [id,'ec-'+id+'@example.invalid','Evidence Chain CI',await hashPassword(password),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 a=await fixture('MAIN');b=await fixture('SECOND');c=await fixture('THIRD');
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/evidence-chain/review',reviewRouter);
 app.use('/api/evidence-chain',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('all claim and GRN mutations require role, CSRF and fresh step-up',async()=>{
 assert.equal((await call('/api/evidence-chain/eligible','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/evidence-chain/eligible','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/evidence-chain/review/claims','GET',undefined,'owner')).status,403);
 assert.equal((await call('/api/evidence-chain/claims','POST',claimBody(a))).status,403);
 assert.equal((await call('/api/evidence-chain/claims','POST',claimBody(a),'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/evidence-chain/claims','POST',claimBody(a),'reviewer')).status,403);
 const [u,v]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass}),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(u.status,200);assert.equal(v.status,200);
 ownerStep=String(u.data.stepUpToken);reviewerStep=String(v.data.stepUpToken);
 const list=await call('/api/evidence-chain/eligible');
 assert.equal(list.status,200);assert.equal(list.data.externalPoIssued,false);
 assert.equal(list.data.stockPostingEnabled,false);
 assert.ok(list.data.items.some((x:any)=>x.preparationId===a.preparationId));
});
test('claim source integrity, duplicate request replay, and tampering refused without external verification',async()=>{
 assert.equal((await call('/api/evidence-chain/claims','POST',
  {...claimBody(a),supplierAuthenticated:true})).status,400);
 assert.equal((await call('/api/evidence-chain/claims','POST',
  {...claimBody(a),documentSha256:'BAD'})).status,400);
 const [before]=await db.query<any[]>('SELECT snapshot_sha256 FROM proc_dispatch_outbox_holds WHERE id=?',[a.outboxId]);
 await db.execute('UPDATE proc_dispatch_outbox_holds SET snapshot_sha256=? WHERE id=?',
  ['a'.repeat(64),a.outboxId]);
 assert.equal((await call('/api/evidence-chain/claims','POST',claimBody(a))).status,409);
 await db.execute('UPDATE proc_dispatch_outbox_holds SET snapshot_sha256=? WHERE id=?',
  [before[0].snapshot_sha256,a.outboxId]);
 const created=await call('/api/evidence-chain/claims','POST',claimBody(a));
 assert.equal(created.status,201);
 assert.equal(created.data.status,'AWAITING_INTERNAL_REVIEW');
 assert.equal(created.data.supplierAuthenticated,false);
 assert.equal(created.data.supplierAcknowledged,false);
 a.claimId=created.data.id;
 const replay=await call('/api/evidence-chain/claims','POST',claimBody(a));
 assert.equal(replay.status,200);assert.equal(replay.data.replayed,true);
 assert.equal(replay.data.id,a.claimId);
 assert.equal((await call('/api/evidence-chain/claims','POST',
  {...claimBody(a),evidenceRef:'ALTERED-EVIDENCE-2026'})).status,409);
 assert.equal((await call('/api/evidence-chain/grn-packs','POST',
  {claimId:a.claimId,observationId:a.observationId})).status,409);
});
test('independent claim review captures untrusted document attestation; never supplier verified',async()=>{
 assert.equal((await call('/api/evidence-chain/review/claims/'+a.claimId+'/decide','POST',
  attest,'owner')).status,403);
 assert.equal((await call('/api/evidence-chain/review/claims/'+a.claimId+'/decide','POST',
  {...attest,documentInspected:false},'reviewer')).status,400);
 assert.equal((await call('/api/evidence-chain/review/claims/'+a.claimId+'/decide','POST',
  attest,'reviewer',{stepUp:false})).status,403);
 const accepted=await call('/api/evidence-chain/review/claims/'+a.claimId+'/decide','POST',attest,'reviewer');
 assert.equal(accepted.status,201);assert.equal(accepted.data.realSupplierVerified,false);
 assert.equal(accepted.data.status,'ATTESTED_INTERNAL');
 assert.equal((await call('/api/evidence-chain/review/claims/'+a.claimId+'/decide','POST',
  attest,'reviewer')).status,409);
 const [decisions]=await db.query<any[]>('SELECT reviewer_id,decision FROM proc_ack_claim_decisions WHERE claim_id=?',[a.claimId]);
 assert.equal(decisions.length,1);assert.equal(decisions[0].reviewer_id,reviewer);
});
test('grn pack refuses mismatched held source, serial discrepancies, missing custody and changed payload',async()=>{
 assert.equal((await call('/api/evidence-chain/grn-packs','POST',
  {claimId:a.claimId,observationId:b.observationId})).status,409);
 const [cEvents]=await db.query<any[]>('SELECT id FROM inv_quarantine_custody_events WHERE observation_id=? LIMIT 1',[a.observationId]);
 await db.execute('UPDATE inv_quarantine_custody_events SET quantity=quantity+1 WHERE id=?',[cEvents[0].id]);
 assert.equal((await call('/api/evidence-chain/grn-packs','POST',
  {claimId:a.claimId,observationId:a.observationId})).status,409);
 await db.execute('UPDATE inv_quarantine_custody_events SET quantity=quantity-1 WHERE id=?',[cEvents[0].id]);
 const [serials]=await db.query<any[]>('SELECT id,serial_number FROM inv_quarantine_serials WHERE observation_id=? LIMIT 1',[a.observationId]);
 await db.execute('UPDATE inv_quarantine_serials SET serial_number=? WHERE id=?',
  ['TAMPER-SERIAL-2026',serials[0].id]);
 assert.equal((await call('/api/evidence-chain/grn-packs','POST',
  {claimId:a.claimId,observationId:a.observationId})).status,409);
 await db.execute('UPDATE inv_quarantine_serials SET serial_number=? WHERE id=?',
  [serials[0].serial_number,serials[0].id]);
 const body={claimId:a.claimId,observationId:a.observationId};
 const created=await call('/api/evidence-chain/grn-packs','POST',body);
 assert.equal(created.status,201);
 assert.equal(created.data.status,'AWAITING_INTERNAL_REVIEW');
 assert.equal(created.data.officialGrnCreated,false);
 assert.equal(created.data.stockPosted,false);
 assert.equal(created.data.quantityTotal,5);
 const replay=await call('/api/evidence-chain/grn-packs','POST',body);
 assert.equal(replay.status,200);assert.equal(replay.data.replayed,true);
 assert.equal(replay.data.id,created.data.id);
 a.claimId=created.data.id;
});
test('independent GRN review detects stored pack mutation, only creates HELD/DISABLED record',async()=>{
 assert.equal((await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  holdDecision,'owner')).status,403);
 assert.equal((await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  {...holdDecision,custodyInspected:false},'reviewer')).status,400);
 assert.equal((await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  holdDecision,'reviewer',{csrf:false})).status,403);
 const [rows]=await db.query<any[]>('SELECT pack_json FROM inv_grn_reconciliation_packs WHERE id=?',[a.claimId]);
 await db.execute('UPDATE inv_grn_reconciliation_packs SET pack_json=? WHERE id=?',
  [JSON.stringify({...rows[0].pack_json,officialGrnCreated:true}),a.claimId]);
 assert.equal((await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  holdDecision,'reviewer')).status,409);
 await db.execute('UPDATE inv_grn_reconciliation_packs SET pack_json=? WHERE id=?',
  [JSON.stringify(rows[0].pack_json),a.claimId]);
 const approved=await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  holdDecision,'reviewer');
 assert.equal(approved.status,201);assert.equal(approved.data.status,'HELD_INTERNAL');
 assert.equal(approved.data.stockPostingState,'DISABLED');
 assert.equal(approved.data.officialGrnCreated,false);
 assert.equal(approved.data.availableToSell,null);
 assert.equal((await call('/api/evidence-chain/review/grn-packs/'+a.claimId+'/decide','POST',
  holdDecision,'reviewer')).status,409);
 const [held]=await db.query<any[]>('SELECT status,stock_posting_state,snapshot_json FROM inv_grn_held_records WHERE pack_id=?',
  [a.claimId]);
 assert.equal(held.length,1);assert.equal(held[0].status,'HELD');
 assert.equal(held[0].stock_posting_state,'DISABLED');
 assert.equal(held[0].snapshot_json.officialGrnCreated,false);
 const ready=await call('/api/evidence-chain/readiness');
 assert.equal(ready.status,200);assert.equal(ready.data.productionGrnReady,false);
 assert.equal(ready.data.availableToSell,null);
 assert.equal((await call('/api/evidence-chain/receipts','POST',{})).status,404);
 assert.equal((await call('/api/evidence-chain/stock-post','POST',{})).status,404);
});
test('disputed supplier claim and rejected GRN pack never create posted/HELD stock entries',async()=>{
 const dispute=await call('/api/evidence-chain/claims','POST',claimBody(b));
 assert.equal(dispute.status,201);
 const rejectedClaim=await call('/api/evidence-chain/review/claims/'+dispute.data.id+'/decide','POST',
  {...attest,decision:'DISPUTED_INTERNAL',documentInspected:false},'reviewer');
 assert.equal(rejectedClaim.status,201);
 assert.equal((await call('/api/evidence-chain/grn-packs','POST',
  {claimId:dispute.data.id,observationId:b.observationId})).status,409);
 const heldClaim=await call('/api/evidence-chain/claims','POST',claimBody(c));
 assert.equal(heldClaim.status,201);
 assert.equal((await call('/api/evidence-chain/review/claims/'+heldClaim.data.id+'/decide','POST',
  attest,'reviewer')).status,201);
 const pack=await call('/api/evidence-chain/grn-packs','POST',
  {claimId:heldClaim.data.id,observationId:c.observationId});
 assert.equal(pack.status,201);
 const rejectedPack=await call('/api/evidence-chain/review/grn-packs/'+pack.data.id+'/decide','POST',
  {...holdDecision,decision:'REJECTED_INTERNAL',custodyInspected:false},'reviewer');
 assert.equal(rejectedPack.status,201);assert.equal(rejectedPack.data.heldRecordCreated,false);
 const [holdRows]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inv_grn_held_records WHERE pack_id=?',
  [pack.data.id]);
 assert.equal(Number(holdRows[0].n),0);
 const [opening]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inventory_opening_counts WHERE product_id=?',[a.productId]);
 assert.equal(Number(opening[0].n),0);
});
