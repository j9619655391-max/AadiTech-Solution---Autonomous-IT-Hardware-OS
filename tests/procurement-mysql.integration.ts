import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken,newSecret} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import ownerRouter from '../server/procurement/ownerRouter';
import reviewRouter from '../server/procurement/reviewRouter';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Procurement integration only permitted on disposable aaditech_ci');
const db=getPool();
if(!db)throw Error('Disposable MySQL unavailable');
const owner=randomUUID(),reviewer=randomUUID(),ownerToken=newSecret(),
 reviewerToken=newSecret(),csrf=newSecret();
const ownerPass='CI-procurement-owner-strong-2026',reviewerPass='CI-procurement-reviewer-strong-2026';
let base='',ownerStep='',reviewerStep='',siteId='',productId='',supplierId='',requestId='';
let close:undefined|(()=>Promise<void>);
after(async()=>{if(close)await close();await db.end();});

async function call(path:string,method='GET',body?:unknown,as:'owner'|'reviewer'|'anonymous'='owner',
 options:{csrf?:boolean;stepUp?:boolean;idempotencyKey?:string}={}){
 const headers:Record<string,string>={};
 if(as!=='anonymous')headers.cookie='aaditech_session='+(as==='owner'?ownerToken:reviewerToken);
 if(body!==undefined)headers['content-type']='application/json';
 if(options.csrf!==false&&method!=='GET')headers['x-csrf-token']=csrf;
 if(options.stepUp!==false){
  const token=as==='owner'?ownerStep:reviewerStep;
  if(token)headers['x-step-up-token']=token;
 }
 if(options.idempotencyKey)headers['idempotency-key']=options.idempotencyKey;
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();
 let data:Record<string,any>={};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Invalid non-JSON response'};}}
 return {status:response.status,data};
}
test('establish disposable real MySQL identities and supplier/catalog/site fixtures',async()=>{
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [owner,'proc-owner-'+owner+'@example.invalid','CI Procurement Owner',await hashPassword(ownerPass),'OWNER']);
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [reviewer,'proc-review-'+reviewer+'@example.invalid','Independent CI Reviewer',
   await hashPassword(reviewerPass),'REVIEWER']);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(ownerToken),owner,csrf]);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(reviewerToken),reviewer,csrf]);
 productId=randomUUID();siteId=randomUUID();
 await db.execute(`INSERT INTO crm_products(id,sku,brand,model,category,specs,
  unitCost,sellingPrice,minPrice,hsn) VALUES(?,?,?,?,?,?,?,?,?,?)`,
  [productId,'PROC-'+productId,'CI','Server','SERVER','Synthetic procurement product',
   '100.00','120.00','100.00','8471']);
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [siteId,'P'+owner.replace(/-/g,'').slice(0,15).toUpperCase(),'Isolated stock site',owner]);
 const app=express();app.use(express.json({limit:'32kb'}));
 app.use('/api/auth',authRouter);
 app.use('/api/procurement/review',reviewRouter);
 app.use('/api/procurement',ownerRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('authentication, role separation and CSRF/step-up gates protect supplier and reviewer operations',async()=>{
 assert.equal((await call('/api/procurement/suppliers','GET',undefined,'anonymous')).status,401);
 assert.equal((await call('/api/procurement/suppliers','GET',undefined,'reviewer')).status,403);
 assert.equal((await call('/api/procurement/review/suppliers','GET',undefined,'owner')).status,403);
 const input={code:'SUP_'+owner.replace(/-/g,'').slice(0,10).toUpperCase(),
  legalName:'Synthetic Vendor',taxId:null};
 assert.equal((await call('/api/procurement/suppliers','POST',input)).status,403);
 assert.equal((await call('/api/procurement/suppliers','POST',input,'owner',{csrf:false})).status,403);
 assert.equal((await call('/api/procurement/suppliers','POST',input,'reviewer')).status,403);
 const [o,r]=await Promise.all([
  call('/api/auth/step-up','POST',{currentPassword:ownerPass},'owner'),
  call('/api/auth/step-up','POST',{currentPassword:reviewerPass},'reviewer')
 ]);
 assert.equal(o.status,200);assert.equal(r.status,200);
 ownerStep=String(o.data.stepUpToken);reviewerStep=String(r.data.stepUpToken);
 assert.match(ownerStep,/^[A-Za-z0-9_-]{43}$/);
 assert.match(reviewerStep,/^[A-Za-z0-9_-]{43}$/);
 const created=await call('/api/procurement/suppliers','POST',input);
 assert.equal(created.status,201);supplierId=created.data.id;
 assert.equal(created.data.status,'UNVERIFIED');
 assert.equal(created.data.externalVerification,false);
 assert.equal((await call('/api/procurement/suppliers','POST',input)).status,409);
});
test('independent reviewer attests supplier evidence; owner cannot self attest',async()=>{
 const query=await call('/api/procurement/review/suppliers','GET',undefined,'reviewer');
 assert.equal(query.status,200);
 assert.ok(query.data.items.some((x:any)=>x.id===supplierId));
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'owner')).status,403);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer',{stepUp:false})).status,403);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:false},'reviewer')).status,400);
 const reviewed=await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer');
 assert.equal(reviewed.status,201);
 assert.equal(reviewed.data.status,'REVIEWED_INTERNAL');
 assert.equal(reviewed.data.externalVerification,false);
 assert.equal((await call('/api/procurement/review/suppliers/'+supplierId+'/attest','POST',
  {evidenceRef:'CHECK-IDENTITY-2026',attestIdentified:true},'reviewer')).status,409);
});
test('owner persists bounded quote-evidence purchase request exactly once, no PO or stock',async()=>{
 const invalid={supplierId,siteId,quoteEvidenceRef:'SUP-QUOTE-2026-001',
  items:[{productId,quantity:2,quotedUnitCost:'199.20'}]};
 assert.equal((await call('/api/procurement/requests','POST',invalid)).status,400);
 assert.equal((await call('/api/procurement/requests','POST',invalid,'owner',{stepUp:false,idempotencyKey:randomUUID()})).status,403);
 assert.equal((await call('/api/procurement/requests','POST',{...invalid,items:[
  {productId:randomUUID(),quantity:1,quotedUnitCost:'100.00'}]},
  'owner',{idempotencyKey:randomUUID()})).status,400);
 const key=randomUUID();
 const created=await call('/api/procurement/requests','POST',invalid,'owner',{idempotencyKey:key});
 assert.equal(created.status,201);
 assert.equal(created.data.status,'PENDING');
 assert.equal(created.data.subtotal,'398.40');
 assert.equal(created.data.dispatchEnabled,false);
 requestId=created.data.id;
 const replay=await call('/api/procurement/requests','POST',invalid,'owner',{idempotencyKey:key});
 assert.equal(replay.status,200);assert.equal(replay.data.replayed,true);
 assert.equal(replay.data.id,requestId);
 assert.equal((await call('/api/procurement/requests','POST',{...invalid,
  quoteEvidenceRef:'SUP-QUOTE-2026-002'},'owner',{idempotencyKey:key})).status,409);
 const owned=await call('/api/procurement/requests/'+requestId);
 assert.equal(owned.status,200);
 assert.equal(owned.data.items.length,1);
 assert.equal(owned.data.items[0].quotedUnitCost,'199.20');
 assert.equal(owned.data.externalPurchaseOrderIssued,false);
 const holds=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(holds.status,409);
});
test('independent review attests quote, rejects repeat and creates no external order',async()=>{
 const queue=await call('/api/procurement/review/requests','GET',undefined,'reviewer');
 assert.equal(queue.status,200);
 assert.ok(queue.data.items.some((x:any)=>x.id===requestId));
 const detail=await call('/api/procurement/review/requests/'+requestId,'GET',undefined,'reviewer');
 assert.equal(detail.status,200);assert.equal(detail.data.items[0].lineSubtotal,'398.40');
 const body={decision:'APPROVED_INTERNAL',reason:'Supplier quote evidence inspected and internally accepted',
  evidenceAttested:true};
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'owner')).status,403);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',
  {...body,evidenceAttested:false},'reviewer')).status,400);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',
  body,'reviewer',{csrf:false})).status,403);
 const decided=await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'reviewer');
 assert.equal(decided.status,201);assert.equal(decided.data.decision,'APPROVED_INTERNAL');
 assert.equal(decided.data.externalPurchaseOrderIssued,false);
 assert.equal((await call('/api/procurement/review/requests/'+requestId+'/decide','POST',body,'reviewer')).status,409);
});
test('internal PO hold is immutable, idempotent, hash-backed and dispatch DISABLED',async()=>{
 const missing=await call('/api/procurement/requests/'+requestId+'/hold','POST',
  {recipient:'outside@example.invalid'});
 assert.equal(missing.status,400);
 const held=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(held.status,201);
 assert.equal(held.data.status,'HELD');assert.equal(held.data.dispatchState,'DISABLED');
 assert.equal(held.data.stockPosted,false);
 assert.equal(held.data.externalPurchaseOrderIssued,false);
 assert.match(held.data.sha256,/^[0-9a-f]{64}$/);
 const repeated=await call('/api/procurement/requests/'+requestId+'/hold','POST',{});
 assert.equal(repeated.status,200);
 assert.equal(repeated.data.replayed,true);
 assert.equal(repeated.data.sha256,held.data.sha256);
 const [rows]=await db.query<any[]>('SELECT status,dispatch_state,snapshot_sha256,snapshot_json FROM proc_po_holds WHERE request_id=?',[requestId]);
 assert.equal(rows.length,1);assert.equal(rows[0].status,'HELD');
 assert.equal(rows[0].dispatch_state,'DISABLED');
 assert.equal(rows[0].snapshot_sha256,held.data.sha256);
 assert.equal(rows[0].snapshot_json.lines[0].quotedUnitCost,'199.20');
 const [opening]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inventory_opening_counts WHERE product_id=?',[productId]);
 assert.equal(Number(opening[0].n),0);
 const unsupported=await call('/api/procurement/receipts','POST',
  {requestId,siteId,quantity:2,serials:['TEST-SERIAL']});
 assert.equal(unsupported.status,404);
});
test('rejection fails closed; does not permit PO hold or stock movement',async()=>{
 const body={supplierId,siteId,quoteEvidenceRef:'SUP-QUOTE-2026-REJ',
  items:[{productId,quantity:1,quotedUnitCost:'10.00'}]};
 const request=await call('/api/procurement/requests','POST',body,'owner',
  {idempotencyKey:randomUUID()});
 assert.equal(request.status,201);
 const rejection=await call('/api/procurement/review/requests/'+request.data.id+'/decide',
  'POST',{decision:'REJECTED_INTERNAL',reason:'Supplier conditions and payment terms do not satisfy review',
   evidenceAttested:false},'reviewer');
 assert.equal(rejection.status,201);
 assert.equal((await call('/api/procurement/requests/'+request.data.id+'/hold','POST',{})).status,409);
 const [audit]=await db.query<any[]>('SELECT entity_type,action FROM proc_audit_events WHERE entity_id=?',
  [request.data.id]);
 assert.ok(audit.some((x:any)=>x.action==='SUBMITTED_FOR_INDEPENDENT_REVIEW'));
});
