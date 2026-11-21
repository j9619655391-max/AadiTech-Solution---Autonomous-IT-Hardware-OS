import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/intake/ownerRouter';
import reviewRouter from '../server/intake/reviewRouter';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Phase 1AD MySQL suite permitted on disposable CI only');
const db=getPool();
if(!db)throw Error('Disposable CI MySQL required');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),
 reviewerToken=newSecret(),csrf=newSecret();
const ownerPass='CI-intake-owner-password-2026',reviewerPass='CI-intake-reviewer-password-2026';
let base='',ownerStep='',reviewerStep='',siteId='',supplierId='',productId='',productLotId='';
let holdId='',observedId='';
let close:undefined|(()=>Promise<void>);
after(async()=>{if(close)await close();await db.end();});

async function call(path:string,method='GET',body?:unknown,as:'owner'|'reviewer'|'anon'='owner',
 options:{csrf?:boolean;stepUp?:boolean;key?:string}={}){
 const headers:Record<string,string>={};
 if(as!=='anon')headers.cookie='aaditech_session='+(as==='owner'?ownerToken:reviewerToken);
 if(body!==undefined)headers['content-type']='application/json';
 if(method!=='GET'&&options.csrf!==false)headers['x-csrf-token']=csrf;
 if(options.stepUp!==false){
  const token=as==='owner'?ownerStep:reviewerStep;
  if(token)headers['x-step-up-token']=token;
 }
 if(options.key)headers['idempotency-key']=options.key;
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();
 let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON route response'};}}
 return {status:response.status,data};
}
async function seedHeld(lines:Array<{productId:string;sku:string;name:string;quantity:number;cost:string}>,
 corrupted=false){
 const id=randomUUID(),decisionId=randomUUID(),hId=randomUUID();
 const lineSnapshots=lines.map(line=>({
  productId:line.productId,sku:line.sku,name:line.name,quantity:line.quantity,
  quotedUnitCost:line.cost,
  lineSubtotal:(Number(line.cost)*line.quantity).toFixed(2)
 }));
 const subtotal=lineSnapshots.reduce((sum,x)=>sum+Number(x.lineSubtotal),0).toFixed(2);
 await db.execute(`INSERT INTO proc_requests
  (id,supplier_id,site_id,created_by,quote_evidence_ref,subtotal,status)
  VALUES (?,?,?,?,?,?,'APPROVED_INTERNAL')`,
  [id,supplierId,siteId,owner,'TEST-SUPPLIER-QUOTE-01',subtotal]);
 for(let i=0;i<lineSnapshots.length;i++){
  const line=lineSnapshots[i];
  await db.execute(`INSERT INTO proc_request_items
   (id,request_id,position,product_id,sku_snapshot,name_snapshot,quantity,quoted_unit_cost,line_subtotal)
   VALUES (?,?,?,?,?,?,?,?,?)`,
   [randomUUID(),id,i+1,line.productId,line.sku,line.name,line.quantity,
    line.quotedUnitCost,line.lineSubtotal]);
 }
 await db.execute(`INSERT INTO proc_review_decisions
  (id,request_id,reviewer_id,decision,reason,evidence_attested)
  VALUES (?,?,?,'APPROVED_INTERNAL',?,1)`,
  [decisionId,id,reviewer,'Internal synthetic evidence approved']);
 const snapshot={format:'aaditech-internal-po-hold-v1',requestId:id,
  supplierId,supplierCode:'CI_INT_STG',supplierName:'Synthetic internal supplier',
  siteId,supplierQuoteEvidenceRef:'TEST-SUPPLIER-QUOTE-01',subtotal,
  reviewId:decisionId,lines:lineSnapshots};
 const sha=createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');
 await db.execute(`INSERT INTO proc_po_holds
  (id,request_id,decision_id,prepared_by,snapshot_sha256,snapshot_json)
  VALUES(?,?,?,?,?,?)`,
  [hId,id,decisionId,owner,corrupted?'a'.repeat(64):sha,JSON.stringify(snapshot)]);
 return hId;
}
const serialLine=()=>({productId,quantity:2,trackingMode:'SERIAL' as const,
 lotCode:null,serialNumbers:['TEST-SER-20261111A','TEST-SER-20261111B']});
const lotLine=()=>({productId:productLotId,quantity:3,trackingMode:'LOT' as const,
 lotCode:'LOT-20261111-01',serialNumbers:[]});
function observation(hold=holdId,items:unknown[]=[serialLine(),lotLine()]){
 return {holdId:hold,deliveryEvidenceRef:'SYNTH-DELIVERY-2026-01',
  physicalCountRef:'SYNTH-PHYSICAL-2026-01',items};
}
test('build independent MySQL users, SKU/site/supplier and held internal PO fixture',async()=>{
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [owner,'intake-owner-'+owner+'@example.invalid','Intake CI Owner',await hashPassword(ownerPass),'OWNER']);
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [reviewer,'intake-review-'+reviewer+'@example.invalid','Intake CI Reviewer',await hashPassword(reviewerPass),'REVIEWER']);
 for(const [id,token] of [[owner,ownerToken],[reviewer,reviewerToken]]){
  await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
   [hashToken(token),id,csrf]);
 }
 productId=randomUUID();productLotId=randomUUID();siteId=randomUUID();supplierId=randomUUID();
 for(const [id,sku,name] of [[productId,'INT-SER-'+productId,'Observed Serialized Server'],
  [productLotId,'INT-LOT-'+productLotId,'Observed Lot Accessory']]){
  await db.execute(`INSERT INTO crm_products
   (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,hsn)
   VALUES(?,?,? ,?,'SERVER',?,'30.00','50.00','30.00','8471')`,
   [id,sku,'Synthetic',name,'CI inventory sample']);
 }
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [siteId,'Q'+owner.replace(/-/g,'').slice(0,20).toUpperCase(),'CI Quarantine Room',owner]);
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,status,evidence_ref,created_by,reviewed_by)
  VALUES (?,?,?,'REVIEWED_INTERNAL',?,?,?)`,
  [supplierId,'CI_INT_STG','Synthetic internal supplier','CI-ID-TEST-001',owner,reviewer]);
 holdId=await seedHeld([
  {productId,sku:'INT-SER-'+productId,name:'Synthetic Observed Serialized Server',quantity:2,cost:'70.00'},
  {productId:productLotId,sku:'INT-LOT-'+productLotId,name:'Synthetic Observed Lot Accessory',quantity:3,cost:'40.00'}
 ]);
 const app=express();app.use(express.json({limit:'256kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/intake/review',reviewRouter);
 app.use('/api/intake',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('owner and independent reviewer are segregated with CSRF and step-up',async()=>{
 assert.equal((await call('/api/intake/eligible','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/intake/eligible','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/intake/review/observations','GET',undefined,'owner')).status,403);
 const body=observation();
 assert.equal((await call('/api/intake/observations','POST',body,'owner',{key:randomUUID()})).status,403);
 assert.equal((await call('/api/intake/observations','POST',body,'owner',{key:randomUUID(),csrf:false})).status,403);
 assert.equal((await call('/api/intake/observations','POST',body,'reviewer',{key:randomUUID()})).status,403);
 const [o,r]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass},'owner'),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')]);
 assert.equal(o.status,200);assert.equal(r.status,200);
 ownerStep=String(o.data.stepUpToken);reviewerStep=String(r.data.stepUpToken);
 const eligible=await call('/api/intake/eligible');
 assert.equal(eligible.status,200);
 assert.ok(eligible.data.items.some((x:any)=>x.holdId===holdId));
 assert.equal(eligible.data.externalPoIssued,false);
});
test('held checksum, exact quantities, serial/lot cardinality and idempotency enforced before observation',async()=>{
 const body=observation();
 assert.equal((await call('/api/intake/observations','POST',body)).status,400);
 assert.equal((await call('/api/intake/observations','POST',{...body,items:[{...serialLine(),quantity:3},
  lotLine()]},'owner',{key:randomUUID()})).status,400);
 assert.equal((await call('/api/intake/observations','POST',{...body,items:[{...serialLine(),quantity:1,
  serialNumbers:['TEST-SER-20261111A']},lotLine()]},'owner',{key:randomUUID()})).status,409);
 assert.equal((await call('/api/intake/observations','POST',{...body,items:[serialLine()]},
  'owner',{key:randomUUID()})).status,409);
 assert.equal((await call('/api/intake/observations','POST',{...body,items:[serialLine(),{
  ...lotLine(),quantity:4}]},'owner',{key:randomUUID()})).status,409);
 const badHold=await seedHeld([{productId,sku:'INT-SER-'+productId,
  name:'Synthetic Observed Serialized Server',quantity:2,cost:'70.00'}],true);
 assert.equal((await call('/api/intake/observations','POST',
  observation(badHold,[serialLine()]),'owner',{key:randomUUID()})).status,409);
 const key=randomUUID();
 const created=await call('/api/intake/observations','POST',body,'owner',{key});
 assert.equal(created.status,201);
 assert.equal(created.data.status,'AWAITING_WITNESS');
 assert.equal(created.data.receiptAccepted,false);
 assert.equal(created.data.availableToSell,null);
 observedId=created.data.id;
 const replay=await call('/api/intake/observations','POST',body,'owner',{key});
 assert.equal(replay.status,200);assert.equal(replay.data.id,observedId);
 assert.equal(replay.data.replayed,true);
 assert.equal((await call('/api/intake/observations','POST',{...body,
  physicalCountRef:'CHANGED-EVIDENCE-2026'},'owner',{key})).status,409);
 assert.equal((await call('/api/intake/observations','POST',body,'owner',{key:randomUUID()})).status,409);
 const [custody]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inv_quarantine_custody_events WHERE observation_id=?',[observedId]);
 assert.equal(Number(custody[0].n),0);
});
test('reviewer independently witnesses serialized/lot counts, records custody evidence without availability',async()=>{
 const queue=await call('/api/intake/review/observations','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.ok(queue.data.items.some((x:any)=>x.id===observedId));
 const detail=await call('/api/intake/review/observations/'+observedId,'GET',undefined,'reviewer');
 assert.equal(detail.status,200);
 assert.equal(detail.data.items.length,2);
 assert.equal(detail.data.availableToSell,null);
 const witness={outcome:'ACCEPT_QUARANTINE',reason:'All serial and lot units independently inspected in quarantine',
  inspectionEvidenceRef:'QA-CHECK-20261111-01',physicallyInspected:true};
 assert.equal((await call('/api/intake/review/observations/'+observedId+'/witness','POST',witness,'owner')).status,403);
 assert.equal((await call('/api/intake/review/observations/'+observedId+'/witness','POST',witness,'reviewer',{stepUp:false})).status,403);
 assert.equal((await call('/api/intake/review/observations/'+observedId+'/witness','POST',witness,'reviewer',{csrf:false})).status,403);
 assert.equal((await call('/api/intake/review/observations/'+observedId+'/witness','POST',
  {...witness,physicallyInspected:false},'reviewer')).status,400);
 const result=await call('/api/intake/review/observations/'+observedId+'/witness','POST',witness,'reviewer');
 assert.equal(result.status,201);assert.equal(result.data.status,'QUARANTINED_INTERNAL');
 assert.equal(result.data.externalReceiptVerified,false);assert.equal(result.data.availableToSell,null);
 assert.equal(result.data.quarantineCustodyEventsRecorded,true);
 assert.equal((await call('/api/intake/review/observations/'+observedId+'/witness','POST',witness,'reviewer')).status,409);
 const [events]=await db.query<any[]>('SELECT product_id,quantity FROM inv_quarantine_custody_events WHERE observation_id=?',[observedId]);
 assert.equal(events.length,2);assert.equal(events.reduce((s:any,x:any)=>s+Number(x.quantity),0),5);
 const [serials]=await db.query<any[]>('SELECT serial_number FROM inv_quarantine_serials WHERE observation_id=?',[observedId]);
 assert.equal(serials.length,2);
 const summary=await call('/api/intake/quarantine-summary');
 assert.equal(summary.status,200);
 assert.equal(summary.data.internalLedgerConsistent,true);
 assert.equal(summary.data.availableToSell,null);
 assert.equal(summary.data.reservedQuantity,null);
 assert.equal(summary.data.financialValue,null);
 const [opening]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inventory_opening_counts WHERE product_id=?',[productId]);
 assert.equal(Number(opening[0].n),0);
});
test('duplicate serial on different observation is refused atomically; rejection never posts custody',async()=>{
 const duplicateHold=await seedHeld([{productId,sku:'INT-SER-'+productId,
  name:'Synthetic Observed Serialized Server',quantity:2,cost:'70.00'}]);
 const same=await call('/api/intake/observations','POST',
  observation(duplicateHold,[serialLine()]),'owner',{key:randomUUID()});
 assert.equal(same.status,201);
 const witness={outcome:'ACCEPT_QUARANTINE',reason:'Duplicate serialized units must be refused',
  inspectionEvidenceRef:'QA-CHECK-DUP-2026-01',physicallyInspected:true};
 const attempt=await call('/api/intake/review/observations/'+same.data.id+'/witness',
  'POST',witness,'reviewer');
 assert.equal(attempt.status,409);
 const [pending]=await db.query<any[]>('SELECT status FROM inv_inbound_observations WHERE id=?',[same.data.id]);
 assert.equal(pending[0].status,'AWAITING_WITNESS');
 const [events]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inv_quarantine_custody_events WHERE observation_id=?',[same.data.id]);
 assert.equal(Number(events[0].n),0);
 const rejected=await call('/api/intake/review/observations/'+same.data.id+'/witness','POST',
  {outcome:'REJECT_INTERNAL',reason:'Duplicate serial conflicts with previously quarantined custody',
   inspectionEvidenceRef:'QA-REJECT-DUP-2026',physicallyInspected:false},'reviewer');
 assert.equal(rejected.status,201);assert.equal(rejected.data.status,'REJECTED_INTERNAL');
 assert.equal(rejected.data.quarantineCustodyEventsRecorded,false);
 const [decision]=await db.query<any[]>('SELECT outcome FROM inv_inbound_decisions WHERE observation_id=?',[same.data.id]);
 assert.equal(decision.length,1);assert.equal(decision[0].outcome,'REJECT_INTERNAL');
 const unavailable=await call('/api/intake/receipts','POST',{id:observedId});
 assert.equal(unavailable.status,404);
 const issue=await call('/api/intake/reservations','POST',{id:observedId});
 assert.equal(issue.status,404);
});
