import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import { getPool } from '../server/db';
import { hashPassword, hashToken } from '../server/auth/crypto';
import crmRouter from '../server/crm/router';
import quoteDraftRouter from '../server/quotes/router';
import quoteReviewRouter from '../server/quotes/reviewRouter';
import quoteReleaseHoldRouter from '../server/quotes/releaseHoldRouter';
import securityAdminRouter from '../server/security/adminRouter';
import authRouter from '../server/auth/router';
import mfaRouter from '../server/auth/mfaRouter';
import {totpAt} from '../server/auth/totp';

if (process.env.CRM_TEST_DB !== '1') throw new Error('CRM integration test must run on disposable test DB only (CRM_TEST_DB=1)');
if (process.env.DB_NAME !== 'aaditech_ci') throw new Error('Refusing integration tests outside aaditech_ci database');
const db=getPool();
if (!db) throw new Error('Integration test MySQL pool unavailable');
after(async()=>{await db.end();});
const actor=randomUUID(), token='a'.repeat(43), csrf='b'.repeat(43);
const ownerPassword='CI-owner-strong-password-2026';
let stepUpToken='';
let base='';
let closeServer:()=>Promise<void>;
const cookie='aaditech_session='+token;
const reviewerId=randomUUID(),reviewerToken='r'.repeat(43),reviewerCookie='aaditech_session='+reviewerToken;

test('setup isolated owner session',async()=>{
  await db.execute("INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)",
    [actor,'ci-owner@example.invalid','CI Owner',await hashPassword(ownerPassword),'OWNER']);
  await db.execute("INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))",[hashToken(token),actor,csrf]);
  await db.execute("INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)",
    [reviewerId,'ci-reviewer@example.invalid','Independent CI Reviewer','test-only','REVIEWER']);
  await db.execute("INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))",
    [hashToken(reviewerToken),reviewerId,csrf]);
  const app=express();app.use(express.json());app.use('/api/auth',authRouter);app.use('/api/auth/mfa',mfaRouter);app.use('/api/security',securityAdminRouter);app.use('/api/crm',crmRouter);app.use('/api/quotes/drafts',quoteDraftRouter);app.use('/api/quotes/reviews',quoteReviewRouter);app.use('/api/quotes/release-preparations',quoteReleaseHoldRouter);
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
  if(authorized)headers.cookie=headers.cookie??(route.startsWith('/api/quotes/reviews')?reviewerCookie:cookie);
  if(body!==undefined)headers['content-type']='application/json';
  if(method==='POST' && route==='/api/quotes/drafts' && !('idempotency-key' in headers)) headers['idempotency-key']=randomUUID();
  if(includeCsrf&& !['GET','HEAD'].includes(method)&&!('x-csrf-token' in headers))headers['x-csrf-token']=csrf;
  if(stepUpToken && !('x-step-up-token' in headers) && ((route.startsWith('/api/security/reviewers/')&&method!=='GET') || route==='/api/auth/revoke-my-sessions'))
    headers['x-step-up-token']=stepUpToken;
  const response=await fetch(base+route,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const raw=await response.text();
  return {status:response.status,data:raw?JSON.parse(raw):null,setCookie:response.headers.get('set-cookie')};
}

test('roles are independent: reviewer cannot mutate CRM or draft, owner cannot sign review decisions',async()=>{
  const reviewSession=await call('/api/quotes/reviews/queue','GET',undefined,true,true,{cookie:reviewerCookie});
  assert.equal(reviewSession.status,200);
  assert.equal((await call('/api/crm/customers','GET',undefined,true,true,{cookie:reviewerCookie})).status,403);
  assert.equal((await call('/api/quotes/drafts','GET',undefined,true,true,{cookie:reviewerCookie})).status,403);
  assert.equal((await call('/api/quotes/reviews/queue','GET',undefined,true,true,{cookie})).status,403);
  const [drafts]=await db.query<any[]>('SELECT id FROM sales_quote_drafts ORDER BY created_at LIMIT 1');
  if(drafts.length){
    const attempt=await call('/api/quotes/reviews/'+drafts[0].id,'POST',{
      expectedRevision:0,decision:'REJECTED_INTERNAL',reason:'Owner bypass attempt',overrideRequested:false
    },true,true,{cookie});
    assert.equal(attempt.status,403);
  }
});

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
  const reviewQueue=await call('/api/quotes/reviews/queue');
  assert.equal(reviewQueue.status,200);
  const brief=await call('/api/quotes/reviews/'+draft.data.id+'/brief');
  assert.equal(brief.status,200);
  assert.equal(brief.data.drafterId,actor);
  assert.equal('email' in brief.data,false);
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

test('release-preparation outbox stays disabled, replays safely and stales after revision',async()=>{
  const customer=await call('/api/crm/customers','POST',{
    name:'Held Release Customer',contactPerson:'Owner',email:'heldrelease@example.invalid',
    phone:'9988776655',city:'Mumbai',state:'Maharashtra'});
  assert.equal(customer.status,201);
  const product=await call('/api/crm/products','POST',{
    sku:'HOLD-RELEASE-1',brand:'HP',model:'Hold Only',category:'SERVER',
    specs:'Internal test',unitCost:'600.00',minPrice:'900.00',
    sellingPrice:'1000.00',gstRate:'18.00',hsn:'8471'});
  assert.equal(product.status,201);
  const draft=await call('/api/quotes/drafts','POST',
    {customerId:customer.data.id,items:[{productId:product.data.id,quantity:1}]});
  assert.equal(draft.status,201);
  const path='/api/quotes/release-preparations/'+draft.data.id;
  assert.equal((await call(path,'GET',undefined,false)).status,401);
  assert.equal((await call(path,'POST',{expectedRevision:0},true,false)).status,403);
  assert.equal((await call(path,'POST',{expectedRevision:0,recipient:'buyer@example.invalid'})).status,400);
  assert.equal((await call(path,'POST',{expectedRevision:0})).status,409);
  const approved=await call('/api/quotes/reviews/'+draft.data.id,'POST',{
    expectedRevision:0,decision:'APPROVED_INTERNAL',reason:'Owner reviewed internal commercial record',
    overrideRequested:false});
  assert.equal(approved.status,201);
  const first=await call(path,'POST',{expectedRevision:0});
  assert.equal(first.status,201);
  assert.equal(first.data.status,'HELD');
  assert.equal(first.data.dispatchState,'DISABLED');
  assert.equal(first.data.replayed,false);
  const retry=await call(path,'POST',{expectedRevision:0});
  assert.equal(retry.status,200);
  assert.equal(retry.data.id,first.data.id);
  assert.equal(retry.data.replayed,true);
  const [holds]=await db.query<any[]>(
    'SELECT p.status,o.dispatch_state,o.event_type FROM sales_quote_release_preparations p JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id WHERE p.quote_id=?',[draft.data.id]);
  assert.equal(holds.length,1);
  assert.equal(holds[0].status,'HELD');
  assert.equal(holds[0].dispatch_state,'DISABLED');
  assert.equal(holds[0].event_type,'QUOTE_RELEASE_PREPARATION_HELD');
  const newRevision=await call('/api/quotes/drafts/'+draft.data.id+'/revisions','POST',{
    expectedRevision:0,reason:'Quantity changed after internal review',
    items:[{productId:product.data.id,quantity:2}]});
  assert.equal(newRevision.status,201);
  assert.equal((await call(path,'POST',{expectedRevision:0})).status,409);
  const refreshed=await call(path);
  assert.equal(refreshed.status,200);
  assert.equal(refreshed.data.currentRevision,1);
  assert.equal(refreshed.data.preparations[0].stale,true);
  assert.equal((await call(path,'POST',{expectedRevision:1})).status,409);
  assert.equal((await call('/api/quotes/reviews/'+draft.data.id,'POST',{
    expectedRevision:1,decision:'REJECTED_INTERNAL',
    reason:'Do not prepare this version',overrideRequested:false})).status,201);
  assert.equal((await call(path,'POST',{expectedRevision:1})).status,409);
});

test('step-up requires correct password and creates session-bound short-lived token',async()=>{
  assert.equal((await call('/api/auth/step-up','POST',{currentPassword:ownerPassword},true,false)).status,403);
  assert.equal((await call('/api/auth/step-up','POST',{currentPassword:'wrong-password'})).status,401);
  const verified=await call('/api/auth/step-up','POST',{currentPassword:ownerPassword});
  assert.equal(verified.status,200);
  assert.equal(verified.data.expiresInSeconds,300);
  assert.match(verified.data.stepUpToken,/^[A-Za-z0-9_-]{43}$/);
  stepUpToken=verified.data.stepUpToken;
  const [rows]=await db.execute<any[]>('SELECT step_up_token_hash FROM auth_step_up_sessions WHERE session_token_hash=?',[hashToken(token)]);
  assert.equal(rows[0].step_up_token_hash,hashToken(stepUpToken));
});

test('privileged MFA policy rejects password-only sessions, retains journal and fails closed on invalid configuration',async()=>{
  const previous=process.env.MFA_REQUIRE_PRIVILEGED;
  try{
    process.env.MFA_REQUIRE_PRIVILEGED='true';
    const blocked=await call('/api/security/reviewers/'+reviewerId+'/revoke-sessions','POST',{},true,true);
    assert.equal(blocked.status,403);
    assert.match(blocked.data.error,/MFA-verified session/);
    const policyDeniedReview=await call('/api/quotes/reviews/'+randomUUID(),'POST',{
      expectedRevision:0,decision:'REJECTED_INTERNAL',reason:'Policy denial probe',overrideRequested:false
    });
    assert.equal(policyDeniedReview.status,403);
    const [events]=await db.execute<any[]>(
      'SELECT event_type FROM auth_security_events WHERE target_user_id IN (?,?) AND event_type=?',
      [actor,reviewerId,'MFA_POLICY_DENIED']);
    assert.ok(events.length>=2);
    process.env.MFA_REQUIRE_PRIVILEGED='invalid';
    assert.equal((await call('/api/security/reviewers/'+reviewerId+'/revoke-sessions','POST',{})).status,503);
  }finally{
    if(previous===undefined)delete process.env.MFA_REQUIRE_PRIVILEGED;
    else process.env.MFA_REQUIRE_PRIVILEGED=previous;
  }
});

test('owner-only read-only security summary returns event counts without secrets',async()=>{
  assert.equal((await call('/api/security/alerts','GET',undefined,false)).status,401);
  assert.equal((await call('/api/security/alerts','GET',undefined,true,true,{cookie:reviewerCookie})).status,403);
  const response=await call('/api/security/alerts');
  assert.equal(response.status,200);
  assert.equal(response.data.windowHours,24);
  assert.equal(response.data.deliveryEnabled,false);
  assert.ok(Array.isArray(response.data.counts));
  assert.ok(response.data.counts.every((v:any)=>
    typeof v.eventType==='string' && Number.isSafeInteger(v.count) && v.count>=0));
});

test('owner-only reviewer administration revokes sessions and appends immutable security events',async()=>{
  const baseRoute='/api/security/reviewers/'+reviewerId;
  assert.equal((await call(baseRoute+'/status','PATCH',{status:'DISABLED'},true,true,{'x-step-up-token':'invalid'})).status,403);
  assert.equal((await call('/api/security/reviewers','GET',undefined,true,true,{cookie:reviewerCookie})).status,403);
  assert.equal((await call('/api/security/reviewers','GET',undefined,false)).status,401);
  const listed=await call('/api/security/reviewers');
  assert.equal(listed.status,200);
  const target=listed.data.items.find((item:any)=>item.id===reviewerId);
  assert.equal(target.status,'ACTIVE');
  assert.equal('password_hash' in target,false);
  assert.equal('csrf_token' in target,false);
  assert.equal((await call(baseRoute+'/status','PATCH',{status:'DISABLED'},true,false)).status,403);
  assert.equal((await call(baseRoute+'/status','PATCH',{status:'OWNER'})).status,400);
  assert.equal((await call(baseRoute+'/status','PATCH',{status:'DISABLED',role:'OWNER'})).status,400);
  assert.equal((await call('/api/security/reviewers/'+actor+'/status','PATCH',{status:'DISABLED'})).status,404);
  const disabled=await call(baseRoute+'/status','PATCH',{status:'DISABLED'});
  assert.equal(disabled.status,200);
  assert.equal(disabled.data.status,'DISABLED');
  assert.ok(disabled.data.revokedSessions>=1);
  assert.equal((await call('/api/quotes/reviews/queue','GET',undefined,true,true,{cookie:reviewerCookie})).status,401);
  assert.equal((await call('/api/auth/me','GET',undefined,true,true,{cookie:reviewerCookie})).status,401);
  assert.equal((await call(baseRoute+'/status','PATCH',{status:'DISABLED'})).status,409);
  const enabled=await call(baseRoute+'/status','PATCH',{status:'ACTIVE'});
  assert.equal(enabled.status,200);
  assert.equal(enabled.data.status,'ACTIVE');
  assert.equal((await call('/api/auth/me','GET',undefined,true,true,{cookie:reviewerCookie})).status,401);
  const secondToken='z'.repeat(43);
  await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))',
    [hashToken(secondToken),reviewerId,csrf]);
  assert.equal((await call('/api/auth/me','GET',undefined,true,true,{cookie:'aaditech_session='+secondToken})).status,200);
  const revoked=await call(baseRoute+'/revoke-sessions','POST',{});
  assert.equal(revoked.status,200);
  assert.equal(revoked.data.revokedSessions,1);
  assert.equal((await call('/api/auth/me','GET',undefined,true,true,{cookie:'aaditech_session='+secondToken})).status,401);
  const logs=await call('/api/security/events?limit=10');
  assert.equal(logs.status,200);
  assert.deepEqual(logs.data.items.filter((ev:any)=>ev.target_user_id===reviewerId).slice(0,3).map((ev:any)=>ev.event_type),
    ['SESSIONS_REVOKED','REVIEWER_ENABLED','REVIEWER_DISABLED']);
  assert.equal((await call('/api/security/events?limit=1000')).status,400);
});

test('authenticated self-revocation invalidates current owner session and is recorded',async()=>{
  assert.equal((await call('/api/auth/revoke-my-sessions','POST',{},true,false)).status,403);
  assert.equal((await call('/api/auth/revoke-my-sessions','POST',{},true,true,{'x-step-up-token':'bad'})).status,403);
  const response=await call('/api/auth/revoke-my-sessions','POST',{});
  assert.equal(response.status,200);
  assert.equal(response.data.signInRequired,true);
  assert.ok(response.data.revokedSessions>=1);
  assert.equal((await call('/api/auth/me')).status,401);
  assert.equal((await call('/api/crm/customers')).status,401);
  const [events]=await db.execute<any[]>('SELECT event_type,revoked_session_count FROM auth_security_events WHERE target_user_id=? ORDER BY created_at DESC',[actor]);
  assert.ok(events.some((item:any)=>item.event_type==='OWN_SESSIONS_REVOKED'));
});

test('database-backed rate limiter survives request bursts and stores hashed identifiers',async()=>{
  const email='absent-ci-user@example.invalid';
  for(let n=0;n<6;n++){
    const outcome=await call('/api/auth/login','POST',{email,password:'invalid-password'},false);
    assert.equal(outcome.status,401);
  }
  assert.equal((await call('/api/auth/login','POST',{email,password:'invalid-password'},false)).status,429);
  const [rows]=await db.execute<any[]>('SELECT key_hash,attempt_count FROM auth_login_rate_buckets ORDER BY attempt_count DESC');
  assert.ok(rows.some((x:any)=>Number(x.attempt_count)>=7));
  assert.ok(rows.every((x:any)=>!String(x.key_hash).includes('absent-ci-user')));
  const [stepups]=await db.execute<any[]>('SELECT * FROM auth_step_up_sessions WHERE session_token_hash=?',[hashToken(token)]);
  assert.equal(stepups.length,0);
});


test('MFA enrollment revokes old sessions; password login needs challenge; recovery codes are one-use',async()=>{
  const id=randomUUID();
  const email='mfa-ci-'+id.slice(0,8)+'@example.invalid';
  const password='MFA-Integration-Test-Password-2026';
  const sessionToken='m'.repeat(43),sessionCookie='aaditech_session='+sessionToken;
  await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
    [id,email,'MFA CI Owner',await hashPassword(password),'OWNER']);
  await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 8 HOUR))',
    [hashToken(sessionToken),id,csrf]);
  const extra={cookie:sessionCookie};
  assert.equal((await call('/api/auth/mfa/status','GET',undefined,true,true,extra)).data.enabled,false);
  assert.equal((await call('/api/auth/mfa/enroll/start','POST',{},true,true,extra)).status,403);
  const fresh=await call('/api/auth/step-up','POST',{currentPassword:password},true,true,extra);
  assert.equal(fresh.status,200);
  const stepHeaders={cookie:sessionCookie,'x-step-up-token':fresh.data.stepUpToken};
  const start=await call('/api/auth/mfa/enroll/start','POST',{},true,true,stepHeaders);
  assert.equal(start.status,200);
  assert.match(start.data.otpauthUri,/^otpauth:\/\/totp\//);
  const secret=start.data.secret;
  const firstCode=totpAt(secret,Math.floor(Date.now()/30000));
  assert.equal((await call('/api/auth/mfa/enroll/activate','POST',{code:'abcdef'},true,true,stepHeaders)).status,400);
  assert.equal((await call('/api/auth/mfa/enroll/activate','POST',{code:'000000'},true,true,stepHeaders)).status,401);
  const activated=await call('/api/auth/mfa/enroll/activate','POST',{code:firstCode},true,true,stepHeaders);
  assert.equal(activated.status,200);
  assert.equal(activated.data.enabled,true);
  assert.equal(activated.data.signInRequired,true);
  assert.equal(activated.data.recoveryCodes.length,8);
  assert.equal((await call('/api/auth/me','GET',undefined,true,true,extra)).status,401);
  const [storage]=await db.execute<any[]>('SELECT secret_encrypted,enabled_at,last_counter FROM auth_totp_credentials WHERE user_id=?',[id]);
  assert.ok(storage[0].enabled_at);
  assert.ok(!String(storage[0].secret_encrypted).includes(secret));
  const noCookieLogin=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(noCookieLogin.status,202);
  assert.equal(noCookieLogin.data.mfaRequired,true);
  assert.ok(!noCookieLogin.data.csrfToken);
  assert.ok(!noCookieLogin.data.user);
  const [noSession]=await db.execute<any[]>('SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?',[id]);
  assert.equal(Number(noSession[0].n),0);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:noCookieLogin.data.challengeToken,code:'999'
  },false)).status,400);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:noCookieLogin.data.challengeToken,code:firstCode
  },false)).status,401);
  const usedCode=activated.data.recoveryCodes[0];
  const second=await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:noCookieLogin.data.challengeToken,code:usedCode
  },false);
  assert.equal(second.status,200);
  assert.equal(second.data.user.id,id);
  assert.ok(second.data.csrfToken);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:noCookieLogin.data.challengeToken,code:usedCode
  },false)).status,401);
  const again=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(again.status,202);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:again.data.challengeToken,code:usedCode
  },false)).status,401);
  // An unused recovery code can recover once more.
  const another=await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:again.data.challengeToken,code:activated.data.recoveryCodes[1]
  },false);
  assert.equal(another.status,200);
  const [used]=await db.execute<any[]>('SELECT COUNT(*) AS n FROM auth_totp_recovery_codes WHERE user_id=? AND used_at IS NOT NULL',[id]);
  assert.equal(Number(used[0].n),2);
  const nextChallenge=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(nextChallenge.status,202);
  // Current-step +1 is within the allowable TOTP drift window and is newer
  // than the code already used at enrollment.
  const freshTotp=totpAt(secret,Math.floor(Date.now()/30000)+1);
  const signed=await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:nextChallenge.data.challengeToken,code:freshTotp
  },false);
  assert.equal(signed.status,200);
  assert.equal(signed.data.user.id,id);
  const verifiedCookie=signed.setCookie?.split(';')[0];
  assert.ok(verifiedCookie?.startsWith('aaditech_session='));
  const oldPolicy=process.env.MFA_REQUIRE_PRIVILEGED;
  try{
    process.env.MFA_REQUIRE_PRIVILEGED='true';
    // A session created after the real TOTP challenge may reach the
    // owner-only action; 404 is the expected unknown-draft result.
    const accepted=await call('/api/quotes/release-preparations/'+randomUUID(),'POST',
      {expectedRevision:0},true,false,
      {cookie:verifiedCookie,'x-csrf-token':signed.data.csrfToken});
    assert.equal(accepted.status,404);
  }finally{
    if(oldPolicy===undefined)delete process.env.MFA_REQUIRE_PRIVILEGED;
    else process.env.MFA_REQUIRE_PRIVILEGED=oldPolicy;
  }
  const [verifiedSessions]=await db.execute<any[]>('SELECT mfa_verified_at FROM auth_sessions WHERE user_id=?',[id]);
  assert.ok(verifiedSessions.some((row:any)=>row.mfa_verified_at));
  const [mfaEvents]=await db.execute<any[]>('SELECT event_type FROM auth_security_events WHERE target_user_id=?',[id]);
  const names=mfaEvents.map((row:any)=>row.event_type);
  assert.ok(names.includes('MFA_ENROLLED'));
  assert.ok(names.includes('MFA_LOGIN_SUCCEEDED'));
  assert.ok(names.includes('MFA_LOGIN_FAILED'));
  assert.ok(names.includes('MFA_RECOVERY_USED'));
  const reusedChallenge=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(reusedChallenge.status,202);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:reusedChallenge.data.challengeToken,code:freshTotp
  },false)).status,401);
  // A fixed challenge allows five wrong guesses, then permanently denies.
  const wrong='FFFFFFFFFFFFFFFFFFFF';
  for(let n=0;n<5;n++)assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:reusedChallenge.data.challengeToken,code:wrong
  },false)).status,401);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:reusedChallenge.data.challengeToken,code:activated.data.recoveryCodes[2]
  },false)).status,401);
});

test('recovery rotation requires verified second factor and invalidates every old code',async()=>{
  const id=randomUUID(),email='rotation-'+id.slice(0,8)+'@example.invalid';
  const password='Strong-Rotation-Password-2026';
  const tokenValue='q'.repeat(43),loginCookie='aaditech_session='+tokenValue;
  await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
    [id,email,'Recovery Rotation CI',await hashPassword(password),'OWNER']);
  await db.execute('INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 8 HOUR))',
    [hashToken(tokenValue),id,csrf]);
  const oldSession={cookie:loginCookie};
  const oldStep=await call('/api/auth/step-up','POST',{currentPassword:password},true,true,oldSession);
  assert.equal(oldStep.status,200);
  const enrollHeaders={cookie:loginCookie,'x-step-up-token':oldStep.data.stepUpToken};
  const started=await call('/api/auth/mfa/enroll/start','POST',{},true,true,enrollHeaders);
  assert.equal(started.status,200);
  const activated=await call('/api/auth/mfa/enroll/activate','POST',{
    code:totpAt(started.data.secret,Math.floor(Date.now()/30000))
  },true,true,enrollHeaders);
  assert.equal(activated.status,200);
  const olderCodes=activated.data.recoveryCodes as string[];
  const challenge=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(challenge.status,202);
  const finished=await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:challenge.data.challengeToken,code:olderCodes[0]
  },false);
  assert.equal(finished.status,200);
  const verifiedCookie=finished.setCookie?.split(';')[0];
  assert.ok(verifiedCookie?.startsWith('aaditech_session='));
  const verifiedHeaders={cookie:verifiedCookie,'x-csrf-token':finished.data.csrfToken};
  assert.equal((await call('/api/auth/mfa/recovery/rotate','POST',{code:'000000'},true,true,verifiedHeaders)).status,403);
  const verifyPasswordAgain=await call('/api/auth/step-up','POST',{currentPassword:password},true,true,verifiedHeaders);
  assert.equal(verifyPasswordAgain.status,200);
  const authorized={...verifiedHeaders,'x-step-up-token':verifyPasswordAgain.data.stepUpToken};
  const fresh=totpAt(started.data.secret,Math.floor(Date.now()/30000)+1);
  const rotated=await call('/api/auth/mfa/recovery/rotate','POST',{code:fresh},true,true,authorized);
  assert.equal(rotated.status,200);
  assert.equal(rotated.data.recoveryCodes.length,8);
  assert.ok(!rotated.data.recoveryCodes.some((v:string)=>olderCodes.includes(v)));
  assert.equal((await call('/api/auth/mfa/recovery/rotate','POST',{code:fresh},true,true,authorized)).status,401);
  const [existing]=await db.execute<any[]>(
    'SELECT code_hash FROM auth_totp_recovery_codes WHERE user_id=?',[id]);
  assert.equal(existing.length,8);
  assert.ok(!existing.some((row:any)=>row.code_hash===hashToken(id+':'+olderCodes[1])));
  const secondChallenge=await call('/api/auth/login','POST',{email,password},false);
  assert.equal(secondChallenge.status,202);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:secondChallenge.data.challengeToken,code:olderCodes[1]
  },false)).status,401);
  assert.equal((await call('/api/auth/mfa/challenge/verify','POST',{
    challengeToken:secondChallenge.data.challengeToken,code:rotated.data.recoveryCodes[0]
  },false)).status,200);
  const [events]=await db.execute<any[]>(
    'SELECT COUNT(*) AS n FROM auth_security_events WHERE target_user_id=? AND event_type=?',
    [id,'MFA_RECOVERY_ROTATED']);
  assert.equal(Number(events[0].n),1);
});
