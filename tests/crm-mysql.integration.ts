import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import { getPool } from '../server/db';
import { hashToken } from '../server/auth/crypto';
import crmRouter from '../server/crm/router';
import quoteDraftRouter from '../server/quotes/router';

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
  const app=express();app.use(express.json());app.use('/api/crm',crmRouter);app.use('/api/quotes/drafts',quoteDraftRouter);
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
  const created=await call('/api/quotes/drafts','POST',body);
  assert.equal(created.status,201);
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
  const [dbRows]=await db.query<any[]>('SELECT status,total_estimate FROM sales_quote_drafts WHERE id=?',[created.data.id]);
  assert.equal(dbRows[0].status,'DRAFT');
  assert.equal(dbRows[0].total_estimate,'3540.00');
  assert.equal((await call('/api/quotes/drafts','POST',{...body,customerId:'00000000-0000-0000-0000-000000000000'})).status,400);
});
