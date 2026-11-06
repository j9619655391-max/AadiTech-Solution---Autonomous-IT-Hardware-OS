import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import { getPool } from '../server/db';
import { hashToken } from '../server/auth/crypto';
import crmRouter from '../server/crm/router';
import quoteDraftRouter from '../server/quotes/router';
import quoteReviewRouter from '../server/quotes/reviewRouter';

if (process.env.CRM_TEST_DB !== '1') throw new Error('CRM integration test must run on disposable test DB only (CRM_TEST_DB=1)');
if (process.env.DB_NAME !== 'aaditech_ci') throw new Error('Refusing integration tests outside aaditech_ci database');
const db=getPool();
if (!db) throw new Error('Integration test MySQL pool unavailable');
after(async()=>{await db.end();});
const actor=randomUUID(), token='a'.repeat(43), csrf='b'.repeat(43);
let base='';
let closeServer:()=>Promise<void>;
const cookie='aaditech_session='+token;

test('setup isolated owner session',async()=>{
  await db.execute("INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)",[actor,'ci-owner@example.invalid','CI Owner','test-only','OWNER']);
  await db.execute("INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))",[hashToken(token),actor,csrf]);
  const app=express();app.use(express.json());app.use('/api/crm',crmRouter);app.use('/api/quotes/drafts',quoteDraftRouter);app.use('/api/quotes/reviews',quoteReviewRouter);
  const server=app.listen(0,'127.0.0.1');
  await new Promise<void>(resolve=>server.once('listening',resolve));
  const addr=server.address();
  assert.ok(addr && typeof addr!=='string');
  base='http://127.0.0.1:'+addr.port;
  closeServer=()=>new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
});
after(async()=>{if(closeServer)await closeServer();});

async function call(route:string, method='GET', body?:unknown, authorized=true, includeCsrf=true, extraHeaders:Record<string,string>={}) {
  const headers:Record<string,string>={...extraHeaders};
  if(authorized)headers.cookie=cookie;
  if(body!==undefined)headers['content-type']='application/json';
  if(method==='POST' && route==='/api/quotes/drafts' && !('idempotency-key' in headers)) headers['idempotency-key']=randomUUID();
  if(includeCsrf&& !['GET','HEAD'].includes(method))headers['x-csrf-token']=csrf;
  const response=await fetch(base+route,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const raw=await response.text();
  return {status:response.status,data:raw?JSON.parse(raw):null};
}

test('anonymous access and missing CSRF are blocked by server',async()=>{
  assert.equal((await call('/api/crm/leads','GET',undefined,false)).status,401);
  assert.equal((await call('/api/crm/leads','POST',{name:'X'},true,false)).status,403);
});

test('customer creation, update/version conflict, soft deletion and immutable audit',async()=>{
  const payload={name:'Example Customer',contactPerson:'Buyer',email:'buyer@example.invalid',phone:'1234567890',city:'Mumbai',state:'Maharashtra'};
  const created=await call('/api/crm/customers','POST',payload);
  assert.equal(created.status,201);const id=created.data.id;assert.equal(created.data.version,1);
  const get=await call('/api/crm/customers/'+id);assert.equal(get.data.name,payload.name);
  const updated=await call('/api/crm/customers/'+id,'PATCH',{expectedVersion:1,city:'Pune'});
  assert.equal(updated.status,200);assert.equal(updated.data.version,2);
  assert.equal((await call('/api/crm/customers/'+id,'PATCH',{expectedVersion:1,city:'Delhi'})).status,409);
  assert.equal((await call('/api/crm/customers?limit=10&page=1')).data.total,1);
  assert.equal((await call('/api/crm/customers/'+id,'DELETE',undefined,true,true,{'if-match':'1'})).status,409);
  assert.equal((await call('/api/crm/customers/'+id,'DELETE',undefined,true,true,{'if-match':'2'})).status,204);
  assert.equal((await call('/api/crm/customers/'+id)).status,404);
  const [audit]=await db.execute<any[]>('SELECT operation FROM crm_audit_events WHERE entity_id=? ORDER BY created_at',[id]);
  assert.equal(audit.length,3);
  assert.deepEqual(audit.map((x:any)=>x.operation).sort(),['CREATE','DELETE','UPDATE']);
});

test('lead and product records persist; product SKU enforced unique',async()=>{
  const lead=await call('/api/crm/leads','POST',{name:'Buyer',company:'Example',email:'lead@example.invalid',phone:'1234567890',source:'EMAIL',requirement:'Servers',estimatedBudget:'250000.00'});
  assert.equal(lead.status,201);
  assert.equal((await call('/api/crm/leads/'+lead.data.id)).data.estimatedBudget,'250000.00');
  const product={sku:'TEST-SRV-001',brand:'Dell',model:'Example',category:'SERVER',specs:'Test',unitCost:'20000.00',minPrice:'21000.00',sellingPrice:'23000.00',hsn:'8471'};
  const created=await call('/api/crm/products','POST',product);assert.equal(created.status,201);
  assert.equal(created.data.unitCost,'20000.00');
  assert.equal((await call('/api/crm/products','POST',product)).status,409);
  assert.equal((await call('/api/crm/products','POST',{...product,sku:'X',stockBhiwandi:100})).status,400);
  assert.equal((await call('/api/crm/products','POST',{...product,sku:'Y',unitCost:20000})).status,400);
});


test('authenticated quote drafts snapshot verified product prices and do not send anything',async()=>{
  const customer=await call('/api/crm/customers','POST',{
    name:'Quote Test Customer',contactPerson:'Buyer',email:'quote-buyer@example.invalid',
    phone:'9999999999',city:'Mumbai',state:'Maharashtra'
  });
  assert.equal(customer.status,201);
  const product=await call('/api/crm/products','POST',{
    sku:'QUOTE-TEST-1',brand:'Dell',model:'Quote Test Server',category:'SERVER',
    specs:'Verified test specification',unitCost:'1000.00',minPrice:'1200.00',
    sellingPrice:'1500.00',gstRate:'18.00',hsn:'8471'
  });
  assert.equal(product.status,201);
  const body={customerId:customer.data.id,items:[{productId:product.data.id,quantity:2}]};
  assert.equal((await call('/api/quotes/drafts','POST',body,false)).status,401);
  assert.equal((await call('/api/quotes/drafts','POST',body,true,false)).status,403);
  assert.equal((await call('/api/quotes/drafts','POST',{...body,totalEstimate:'0.01'})).status,400);
  assert.equal((await call('/api/quotes/drafts','POST',{...body,items:[{...body.items[0],unitPrice:'0.01'}]})).status,400);
  const key=randomUUID();
  const created=await call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':key});
  assert.equal(created.status,201);
  assert.equal(created.data.draftNumber,'ADQ-'+created.data.id);
  const replay=await call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':key});
  assert.equal(replay.status,200);
  assert.equal(replay.data.replayed,true);
  assert.equal(replay.data.id,created.data.id);
  assert.equal((await call('/api/quotes/drafts','POST',
    {...body,items:[{...body.items[0],quantity:3}]},true,true,{'idempotency-key':key})).status,409);
  assert.equal(created.data.status,'DRAFT');
  assert.equal(created.data.subtotal,'3000.00');
  assert.equal(created.data.taxEstimate,'540.00');
  assert.equal(created.data.totalEstimate,'3540.00');
  const detail=await call('/api/quotes/drafts/'+created.data.id);
  assert.equal(detail.status,200);
  assert.equal(detail.data.items.length,1);
  assert.equal(detail.data.items[0].unit_price,'1500.00');
  assert.equal((await call('/api/quotes/drafts')).data.items.length,1);
  // Snapshot remains intact even after catalog price changes.
  const updated=await call('/api/crm/products/'+product.data.id,'PATCH',
    {expectedVersion:1,sellingPrice:'1900.00'});
  assert.equal(updated.status,200);
  const frozen=await call('/api/quotes/drafts/'+created.data.id);
  assert.equal(frozen.data.items[0].unit_price,'1500.00');
  const replayAfterCatalogChange=await call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':key});
  assert.equal(replayAfterCatalogChange.status,200);
  assert.equal(replayAfterCatalogChange.data.totalEstimate,'3540.00');
  const [dbRows]=await db.query<any[]>('SELECT status,total_estimate FROM sales_quote_drafts WHERE id=?',[created.data.id]);
  assert.equal(dbRows[0].status,'DRAFT');
  assert.equal(dbRows[0].total_estimate,'3540.00');
  assert.equal((await call('/api/quotes/drafts','POST',{...body,customerId:'00000000-0000-0000-0000-000000000000'})).status,400);
  assert.equal((await call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':'bad'})).status,400);
  const [keys]=await db.query<any[]>('SELECT COUNT(*) AS n FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,key]);
  assert.equal(Number(keys[0].n),1);
  // Concurrent identical POST requests must serialize on MySQL's unique key.
  const concurrentKey=randomUUID();
  const [first,second]=await Promise.all([
    call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':concurrentKey}),
    call('/api/quotes/drafts','POST',body,true,true,{'idempotency-key':concurrentKey})
  ]);
  assert.deepEqual([first.status,second.status].sort(),[200,201]);
  assert.equal(first.data.id,second.data.id);
  const [concurrentRows]=await db.query<any[]>(
    'SELECT COUNT(*) AS n FROM sales_quote_drafts WHERE id=?',[first.data.id]);
  assert.equal(Number(concurrentRows[0].n),1);
});

test('draft revisions preserve original snapshots, enforce version and margin guardrail',async()=>{
  const customer=await call('/api/crm/customers','POST',{
    name:'Revision Customer',contactPerson:'Owner',email:'revision@example.invalid',
    phone:'1234567890',city:'Mumbai',state:'Maharashtra'
  });
  assert.equal(customer.status,201);
  const product=await call('/api/crm/products','POST',{
    sku:'REV-SKU-1',brand:'Dell',model:'Revision Test',category:'SERVER',
    specs:'Test',unitCost:'900.00',minPrice:'1000.00',sellingPrice:'1000.00',gstRate:'18.00',hsn:'8471'
  });
  assert.equal(product.status,201);
  const draft=await call('/api/quotes/drafts','POST',{
    customerId:customer.data.id,items:[{productId:product.data.id,quantity:1}]
  });
  assert.equal(draft.status,201);
  const route='/api/quotes/drafts/'+draft.data.id+'/revisions';
  assert.equal((await call(route,'GET',undefined,false)).status,401);
  assert.equal((await call(route)).data.revisions.length,0);
  const body={expectedRevision:0,reason:'Customer requested two servers',items:[{productId:product.data.id,quantity:2}]};
  assert.equal((await call(route,'POST',body,true,false)).status,403);
  const first=await call(route,'POST',body);
  assert.equal(first.status,201);
  assert.equal(first.data.revision,1);
  assert.equal(first.data.subtotal,'2000.00');
  assert.equal(first.data.totalEstimate,'2360.00');
  assert.equal(first.data.grossMarginBps,1000);
  assert.equal(first.data.reviewStatus,'MARGIN_REVIEW_REQUIRED');
  assert.equal((await call(route,'POST',body)).status,409);
  assert.equal((await call(route,'POST',{...body,expectedRevision:1,
    items:[{productId:randomUUID(),quantity:2}]})).status,400);
  const second=await call(route,'POST',{...body,expectedRevision:1,reason:'Customer confirmed three units',
    items:[{productId:product.data.id,quantity:3}]});
  assert.equal(second.status,201);
  assert.equal(second.data.revision,2);
  const history=await call(route);
  assert.equal(history.status,200);
  assert.equal(history.data.revisions.length,2);
  assert.equal(history.data.revisions[0].line_snapshot[0].quantity,2);
  assert.equal(history.data.revisions[1].line_snapshot[0].quantity,3);
  const original=await call('/api/quotes/drafts/'+draft.data.id);
  assert.equal(original.data.items[0].quantity,1);
  const [dbHistory]=await db.query<any[]>('SELECT revision_number,review_status FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number',[draft.data.id]);
  assert.deepEqual(dbHistory.map((x:any)=>x.revision_number),[1,2]);
});

test('owner reviews exact latest draft revision with enforced margin override and immutable audit',async()=>{
  const customer=await call('/api/crm/customers','POST',{
    name:'Review Test Customer',contactPerson:'Buyer',email:'review@example.invalid',
    phone:'9876543210',city:'Mumbai',state:'Maharashtra'});
  assert.equal(customer.status,201);
  const product=await call('/api/crm/products','POST',{
    sku:'REVIEW-TEST-1',brand:'Dell',model:'Test Approval',category:'SERVER',specs:'Test',
    unitCost:'950.00',sellingPrice:'1000.00',minPrice:'980.00',gstRate:'18.00',hsn:'8471'});
  assert.equal(product.status,201);
  const draft=await call('/api/quotes/drafts','POST',{
    customerId:customer.data.id,items:[{productId:product.data.id,quantity:1}]});
  assert.equal(draft.status,201);
  const path='/api/quotes/reviews/'+draft.data.id;
  assert.equal((await call(path,'GET',undefined,false)).status,401);
  assert.equal((await call(path,'POST',{expectedRevision:0,decision:'REJECTED_INTERNAL',reason:'Not commercially acceptable',overrideRequested:false},true,false)).status,403);
  const review={expectedRevision:0,decision:'APPROVED_INTERNAL',reason:'Approved by owner',overrideRequested:false};
  assert.equal((await call(path,'POST',review)).status,400);
  assert.equal((await call(path,'POST',{...review,overrideRequested:true})).status,400);
  const approved=await call(path,'POST',{...review,reason:'Owner accepted discounted margin after detailed commercial review',overrideRequested:true});
  assert.equal(approved.status,201);
  assert.equal(approved.data.reviewStatus,'APPROVED_INTERNAL');
  assert.equal(approved.data.grossMarginBps,500);
  assert.equal((await call(path,'POST',{...review,reason:'Try again',overrideRequested:true})).status,409);
  const initial=await call(path);
  assert.equal(initial.status,200);
  assert.equal(initial.data.currentRevision,0);
  assert.equal(initial.data.effectiveDecision.decision,'APPROVED_INTERNAL');
  const revision=await call('/api/quotes/drafts/'+draft.data.id+'/revisions','POST',{
    expectedRevision:0,reason:'Customer changed quantity',items:[{productId:product.data.id,quantity:2}]});
  assert.equal(revision.status,201);
  const stale=await call(path);
  assert.equal(stale.data.currentRevision,1);
  assert.equal(stale.data.effectiveDecision,null);
  assert.equal(stale.data.history.length,1);
  assert.equal((await call(path,'POST',{expectedRevision:0,decision:'REJECTED_INTERNAL',reason:'Old version',overrideRequested:false})).status,409);
  const rejected=await call(path,'POST',{
    expectedRevision:1,decision:'REJECTED_INTERNAL',reason:'Check vendor quote again',overrideRequested:false});
  assert.equal(rejected.status,201);
  const decisions=await call(path);
  assert.equal(decisions.data.history.length,2);
  assert.equal(decisions.data.effectiveDecision.decision,'REJECTED_INTERNAL');
  const [databaseRows]=await db.query<any[]>('SELECT decision,revision_number FROM sales_quote_review_decisions WHERE quote_id=? ORDER BY revision_number',[draft.data.id]);
  assert.deepEqual(databaseRows.map((x:any)=>x.decision),['APPROVED_INTERNAL','REJECTED_INTERNAL']);
});
