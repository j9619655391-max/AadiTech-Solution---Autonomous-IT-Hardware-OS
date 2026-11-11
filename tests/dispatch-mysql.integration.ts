import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/dispatch/ownerRouter';
import reviewRouter from '../server/dispatch/reviewRouter';
import {sha} from '../server/dispatch/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Phase 1AE MySQL suite strictly disposable CI only');
const db=getPool();if(!db)throw Error('Disposable CI MySQL unavailable');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),reviewerToken=newSecret(),csrf=newSecret();
const ownerPassword='CI-dispatch-owner-pass-2026',reviewerPassword='CI-dispatch-reviewer-pass-2026';
let base='',ownerStep='',reviewerStep='',productId='',siteId='',supplierId='',holdId='',destinationId='',preparationId='';
let close:(()=>Promise<void>)|undefined;
after(async()=>{if(close)await close();await db.end();});
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
 const response=await fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON route response'};}}
 return {status:response.status,data};
}
async function syntheticHold(tampered=false):Promise<string>{
 const requestId=randomUUID(),decisionId=randomUUID(),id=randomUUID();
 await db.execute(`INSERT INTO proc_requests
  (id,supplier_id,site_id,created_by,quote_evidence_ref,subtotal,status)
  VALUES(?,?,?,?,?,?,'APPROVED_INTERNAL')`,
  [requestId,supplierId,siteId,owner,'TEST-SUPPLIER-QUOTE-2026','210.00']);
 const line={productId,sku:'CI-PO-'+productId,name:'CI Laptop Model',quantity:2,
  quotedUnitCost:'105.00',lineSubtotal:'210.00'};
 await db.execute(`INSERT INTO proc_request_items
  (id,request_id,position,product_id,sku_snapshot,name_snapshot,quantity,quoted_unit_cost,line_subtotal)
  VALUES(?,?,?,?,?,?,?,?,?)`,
  [randomUUID(),requestId,1,line.productId,line.sku,line.name,line.quantity,
   line.quotedUnitCost,line.lineSubtotal]);
 await db.execute(`INSERT INTO proc_review_decisions
  (id,request_id,reviewer_id,decision,reason,evidence_attested)
  VALUES(?,?,?,'APPROVED_INTERNAL',?,1)`,
  [decisionId,requestId,reviewer,'CI synthetic independent reviewer evidence']);
 const snapshot={format:'aaditech-internal-po-hold-v1',requestId,
  supplierId,supplierCode:'CI_SUP_AE',supplierName:'Synthetic CI Supplier',siteId,
  supplierQuoteEvidenceRef:'TEST-SUPPLIER-QUOTE-2026',
  subtotal:'210.00',reviewId:decisionId,lines:[line]};
 await db.execute(`INSERT INTO proc_po_holds
  (id,request_id,decision_id,prepared_by,snapshot_sha256,snapshot_json)
  VALUES (?,?,?,?,?,?)`,
  [id,requestId,decisionId,owner,tampered?'a'.repeat(64):sha(JSON.stringify(snapshot)),
   JSON.stringify(snapshot)]);
 return id;
}
test('create disposable actor identity, supplier master and immutable HELD order',async()=>{
 for(const [id,token,role,pass] of [[owner,ownerToken,'OWNER',ownerPassword],
  [reviewer,reviewerToken,'REVIEWER',reviewerPassword]]){
  await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES(?,?,?,?,?)',
   [id,'ci-dispatch-'+id+'@example.invalid','CI supplier dispatch actor',await hashPassword(pass),role]);
  await db.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES(?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),id,csrf]);
 }
 productId=randomUUID();siteId=randomUUID();supplierId=randomUUID();
 await db.execute(`INSERT INTO crm_products
  (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,hsn)
  VALUES (?,?,?,?,?,?,?,?,?,?)`,
  [productId,'CI-PO-'+productId,'CI','Laptop Model','LAPTOP','Synthetic only','105.00','125.00','105.00','8471']);
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [siteId,'D'+owner.replace(/-/g,'').slice(0,16).toUpperCase(),'CI unshipped site',owner]);
 await db.execute(`INSERT INTO proc_suppliers
  (id,code,legal_name,status,evidence_ref,created_by,reviewed_by)
  VALUES(?,?,?,'REVIEWED_INTERNAL',?,?,?)`,
  [supplierId,'CI_SUP_AE','Synthetic CI Supplier','IDENTITY-CI-2026',owner,reviewer]);
 holdId=await syntheticHold();
 const app=express();app.use(express.json({limit:'128kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/po-dispatch/review',reviewRouter);
 app.use('/api/po-dispatch',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('roles, CSRF and step-up guard destination capture and review',async()=>{
 assert.equal((await call('/api/po-dispatch/destinations','GET',undefined,'anon')).status,401);
 assert.equal((await call('/api/po-dispatch/destinations','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/po-dispatch/review/destinations','GET',undefined,'owner')).status,403);
 const input={supplierId,email:'ops@example.invalid',evidenceRef:'SUPPLIER-EMAIL-REF-2026'};
 assert.equal((await call('/api/po-dispatch/destinations','POST',input)).status,403);
 assert.equal((await call('/api/po-dispatch/destinations','POST',input,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/po-dispatch/destinations','POST',input,'reviewer')).status,403);
 const [a,b]=await Promise.all([call('/api/auth/step-up','POST',{currentPassword:ownerPassword},'owner'),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPassword},'reviewer')]);
 assert.equal(a.status,200);assert.equal(b.status,200);
 ownerStep=String(a.data.stepUpToken);reviewerStep=String(b.data.stepUpToken);
 assert.match(ownerStep,/^[A-Za-z0-9_-]{43}$/);assert.match(reviewerStep,/^[A-Za-z0-9_-]{43}$/);
 const added=await call('/api/po-dispatch/destinations','POST',input);
 assert.equal(added.status,201);destinationId=added.data.id;
 assert.equal(added.data.status,'PENDING_INTERNAL');
 assert.equal(added.data.externalVerification,false);
 assert.equal((await call('/api/po-dispatch/destinations','POST',input)).status,409);
 assert.equal((await call('/api/po-dispatch/review/destinations/'+destinationId+'/decide','POST',
  {decision:'REVIEWED_INTERNAL',evidenceRef:'REVIEW-EMAIL-REF-2026',
   reason:'Inspected internal supplier account evidence',identityAttested:true},'owner')).status,403);
});
test('reviewer independently attests destination; review is immutable and not external validation',async()=>{
 const body={decision:'REVIEWED_INTERNAL',evidenceRef:'REVIEW-EMAIL-REF-2026',
  reason:'Supplier destination proof inspected in internal records',identityAttested:true};
 assert.equal((await call('/api/po-dispatch/review/destinations/'+destinationId+'/decide','POST',
  {...body,identityAttested:false},'reviewer')).status,400);
 assert.equal((await call('/api/po-dispatch/review/destinations/'+destinationId+'/decide','POST',
  body,'reviewer',{stepUp:false})).status,403);
 const created=await call('/api/po-dispatch/review/destinations/'+destinationId+'/decide','POST',
  body,'reviewer');
 assert.equal(created.status,201);
 assert.equal(created.data.status,'REVIEWED_INTERNAL');
 assert.equal(created.data.externallyVerified,false);
 assert.equal((await call('/api/po-dispatch/review/destinations/'+destinationId+'/decide','POST',
  body,'reviewer')).status,409);
});
test('owner creates one checksum-bound internal PO dispatch request and identical retries are safe',async()=>{
 const body={holdId,destinationId,authorizationEvidenceRef:'PO-DISPATCH-AUTH-2026'};
 assert.equal((await call('/api/po-dispatch/requests','POST',{...body,sendNow:true})).status,400);
 assert.equal((await call('/api/po-dispatch/requests','POST',body,'reviewer')).status,403);
 const corrupt=await syntheticHold(true);
 assert.equal((await call('/api/po-dispatch/requests','POST',{...body,holdId:corrupt})).status,409);
 const created=await call('/api/po-dispatch/requests','POST',body);
 assert.equal(created.status,201);assert.equal(created.data.status,'PENDING_INTERNAL');
 assert.equal(created.data.externalPoIssued,false);
 preparationId=created.data.id;
 assert.match(created.data.manifestSha256,/^[0-9a-f]{64}$/);
 const replay=await call('/api/po-dispatch/requests','POST',body);
 assert.equal(replay.status,200);assert.equal(replay.data.id,preparationId);
 assert.equal(replay.data.replayed,true);
 assert.equal((await call('/api/po-dispatch/requests','POST',
  {...body,authorizationEvidenceRef:'CHANGED-EVIDENCE-2026'})).status,409);
 const [rows]=await db.query<any[]>('SELECT manifest_json,manifest_sha256 FROM proc_dispatch_preparations WHERE id=?',
  [preparationId]);
 assert.equal(rows.length,1);assert.equal(rows[0].manifest_json.dispatchState,'DISABLED');
 assert.equal(rows[0].manifest_json.email,'ops@example.invalid');
 assert.equal(rows[0].manifest_json.externalOrderIssued,false);
});
test('independent approval inserts one immutable DISABLED outbox hold; no actual supplier order',async()=>{
 const detail=await call('/api/po-dispatch/review/requests/'+preparationId,'GET',undefined,'reviewer');
 assert.equal(detail.status,200);
 assert.equal(detail.data.manifest.externalOrderIssued,false);
 const body={decision:'APPROVED_INTERNAL',reason:'Confirmed destination evidence and matching held purchase manifest',
  evidenceRef:'INDEPENDENT-PO-REVIEW-2026',destinationAttested:true};
 assert.equal((await call('/api/po-dispatch/review/requests/'+preparationId+'/decide','POST',body,'owner')).status,403);
 assert.equal((await call('/api/po-dispatch/review/requests/'+preparationId+'/decide','POST',
  {...body,destinationAttested:false},'reviewer')).status,400);
 assert.equal((await call('/api/po-dispatch/review/requests/'+preparationId+'/decide','POST',
  body,'reviewer',{csrf:false})).status,403);
 const decision=await call('/api/po-dispatch/review/requests/'+preparationId+'/decide','POST',body,'reviewer');
 assert.equal(decision.status,201);
 assert.equal(decision.data.outboxState,'HELD');
 assert.equal(decision.data.dispatchState,'DISABLED');
 assert.equal(decision.data.externalPoIssued,false);
 assert.equal(decision.data.supplierAcknowledged,false);
 assert.equal((await call('/api/po-dispatch/review/requests/'+preparationId+'/decide','POST',body,'reviewer')).status,409);
 const [rows]=await db.query<any[]>('SELECT state,dispatch_state,snapshot_json,snapshot_sha256 FROM proc_dispatch_outbox_holds WHERE preparation_id=?',[preparationId]);
 assert.equal(rows.length,1);assert.equal(rows[0].state,'HELD');
 assert.equal(rows[0].dispatch_state,'DISABLED');
 assert.equal(rows[0].snapshot_json.externalPoIssued,false);
 const snap=rows[0].snapshot_json;
 assert.equal(rows[0].snapshot_sha256,sha(JSON.stringify({
  format:snap.format,preparationId:snap.preparationId,
  manifestSha256:snap.manifestSha256,decisionId:snap.decisionId,
  dispatchState:snap.dispatchState,externalPoIssued:snap.externalPoIssued
 })));
 const [events]=await db.query<any[]>('SELECT event_type FROM proc_dispatch_audit WHERE entity_id=?',[preparationId]);
 assert.ok(events.some((x:any)=>x.event_type==='PREPARATION_APPROVED_HELD'));
 assert.equal((await call('/api/po-dispatch/send','POST',{preparationId})).status,404);
 assert.equal((await call('/api/po-dispatch/acknowledgments','POST',{preparationId})).status,404);
});
test('observed inbound held PO cannot become outbound; rejection never populates outbox',async()=>{
 const observedHold=await syntheticHold();
 await db.execute(`INSERT INTO inv_inbound_observations
  (id,hold_id,request_id,site_id,recorded_by,delivery_evidence_ref,physical_count_ref,payload_sha256)
  SELECT ?,h.id,h.request_id,r.site_id,?,
   'CI-SYNTH-DELIVERY-REF','CI-SYNTH-COUNT-REF',?
   FROM proc_po_holds h JOIN proc_requests r ON r.id=h.request_id WHERE h.id=?`,
  [randomUUID(),owner,'a'.repeat(64),observedHold]);
 assert.equal((await call('/api/po-dispatch/requests','POST',
  {holdId:observedHold,destinationId,authorizationEvidenceRef:'PO-DISP-AUTH-2026'})).status,409);
 const deniedHold=await syntheticHold();
 const made=await call('/api/po-dispatch/requests','POST',
  {holdId:deniedHold,destinationId,authorizationEvidenceRef:'DENIED-ORDER-EVIDENCE'});
 assert.equal(made.status,201);
 const rejected=await call('/api/po-dispatch/review/requests/'+made.data.id+'/decide','POST',
  {decision:'REJECTED_INTERNAL',reason:'Internal authorization evidence insufficient for supplier order',
   evidenceRef:'REJECTION-REF-2026',destinationAttested:false},'reviewer');
 assert.equal(rejected.status,201);assert.equal(rejected.data.outboxState,null);
 const [outbox]=await db.query<any[]>('SELECT COUNT(*) AS n FROM proc_dispatch_outbox_holds WHERE preparation_id=?',[made.data.id]);
 assert.equal(Number(outbox[0].n),0);
 const [external]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inv_quarantine_custody_events WHERE product_id=?',[productId]);
 assert.equal(Number(external[0].n),0);
});
