import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {getPool} from '../server/db';
import {hashPassword,hashToken} from '../server/auth/crypto';
import authRouter from '../server/auth/router';
import inventoryRouter from '../server/inventory/router';

if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Inventory integration tests refuse non-disposable MySQL');
const db=getPool();
if(!db)throw Error('MySQL disposable inventory test requires DB pool');
const actor=randomUUID(),reviewer=randomUUID(),otherOwner=randomUUID(),
 token=randomUUID().replace(/-/g,'')+'a'.repeat(11);
const csrf='c'.repeat(43),pass='CI-inventory-password-unique';
const ownerCookie='aaditech_session='+token;
const reviewerToken='r'.repeat(43),reviewerCookie='aaditech_session='+reviewerToken,
 otherToken='o'.repeat(43),otherOwnerCookie='aaditech_session='+otherToken;
let foreignSiteId='',foreignCountId='';
let base='',stepUp='',siteId='',productId='';
let close:()=>Promise<void>|undefined;
after(async()=>{if(close)await close();await db.end();});

async function call(path:string,method='GET',body?:unknown,options:{
 cookie?:string;csrf?:boolean;stepUp?:boolean;idempotencyKey?:string;
}={}){
 const headers:Record<string,string>={cookie:options.cookie??ownerCookie};
 if(body!==undefined)headers['content-type']='application/json';
 if(options.csrf!==false&&method!=='GET')headers['x-csrf-token']=csrf;
 if(options.stepUp!==false&&stepUp)headers['x-step-up-token']=stepUp;
 if(options.idempotencyKey)headers['idempotency-key']=options.idempotencyKey;
 const response=await fetch(base+path,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();
 let data:Record<string,any>= {};
 if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON response',contentType:response.headers.get('content-type')};}}
 return {status:response.status,data};
}
test('isolated stock setup uses existing server auth and product master',async()=>{
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [actor,'stock-owner-'+actor+'@example.invalid','Stock test owner',await hashPassword(pass),'OWNER']);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(token),actor,csrf]);
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [reviewer,'stock-review-'+reviewer+'@example.invalid','Stock test reviewer','test-only','REVIEWER']);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(reviewerToken),reviewer,csrf]);
 await db.execute('INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)',
  [otherOwner,'stock-other-'+otherOwner+'@example.invalid','Other CI stock owner','test-only','OWNER']);
 await db.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))',
  [hashToken(otherToken),otherOwner,csrf]);
 foreignSiteId=randomUUID();foreignCountId=randomUUID();
 const foreignCode='CI_OTHER_'+otherOwner.replace(/-/g,'').slice(0,12).toUpperCase();
 await db.execute('INSERT INTO inventory_sites(id,code,name,created_by) VALUES (?,?,?,?)',
  [foreignSiteId,foreignCode,'Other owner private site',otherOwner]);
 productId=randomUUID();
 await db.execute(`INSERT INTO crm_products
  (id,sku,brand,model,category,specs,unitCost,sellingPrice,minPrice,hsn)
  VALUES (?,?,?,?,?,?,?,?,?,?)`,
  [productId,'CI-INV-'+productId,'Test','Count-only laptop','LAPTOP','Synthetic test item',
   '100.00','120.00','100.00','8471']);
 await db.execute('INSERT INTO inventory_opening_counts(id,product_id,site_id,quantity,evidence_ref,attested_by) VALUES (?,?,?,?,?,?)',
  [foreignCountId,productId,foreignSiteId,23,'OTHER-PRIVATE-COUNT-REF',otherOwner]);
 const app=express();app.use(express.json());app.use('/api/auth',authRouter);
 app.use('/api/inventory',inventoryRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown API endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});
test('anonymous, reviewer and missing-CSRF stock writes are rejected',async()=>{
 const anon=await call('/api/inventory/sites','GET',undefined,{cookie:'invalid=1'});
 assert.equal(anon.status,401);
 const reviewerRead=await call('/api/inventory/sites','GET',undefined,{cookie:reviewerCookie});
 assert.equal(reviewerRead.status,403);
 const body={code:'CI_'+actor.replace(/-/g,'').slice(0,18).toUpperCase(),name:'Synthetic site'};
 assert.equal((await call('/api/inventory/sites','POST',body,{csrf:false})).status,403);
 assert.equal((await call('/api/inventory/sites','POST',body,{cookie:reviewerCookie})).status,403);
 assert.equal((await call('/api/inventory/sites','POST',body)).status,403);
});
test('current password step-up required to create explicitly named site',async()=>{
 const verified=await call('/api/auth/step-up','POST',{currentPassword:pass});
 assert.equal(verified.status,200);
 stepUp=String(verified.data.stepUpToken);
 assert.match(stepUp,/^[A-Za-z0-9_-]{43}$/);
 const code='CI_'+actor.replace(/-/g,'').slice(0,18).toUpperCase();
 const site=await call('/api/inventory/sites','POST',{code,name:'Synthetic count site'});
 assert.equal(site.status,201);siteId=site.data.id;
 assert.equal((await call('/api/inventory/sites','POST',{code,name:'Synthetic count site'})).status,409);
 const list=await call('/api/inventory/sites');
 assert.equal(list.status,200);
 assert.ok(list.data.items.some((x:any)=>x.id===siteId));
});
test('count requires exact schema, evidence reference and idempotency key',async()=>{
 const body={productId,siteId,quantity:7,evidenceRef:'TEST-COUNT-0001'};
 assert.equal((await call('/api/inventory/opening-counts','POST',body)).status,400);
 assert.equal((await call('/api/inventory/opening-counts','POST',{...body,quantity:-5},{idempotencyKey:randomUUID()})).status,400);
 assert.equal((await call('/api/inventory/opening-counts','POST',{...body,availableToSell:7},{idempotencyKey:randomUUID()})).status,400);
 assert.equal((await call('/api/inventory/opening-counts','POST',{...body,productId:randomUUID()},{idempotencyKey:randomUUID()})).status,400);
 const key=randomUUID();
 const created=await call('/api/inventory/opening-counts','POST',body,{idempotencyKey:key});
 assert.equal(created.status,201);
 assert.equal(created.data.status,'OPENING_COUNT_ONLY');
 assert.equal(created.data.availableToSell,null);
 assert.equal(created.data.reservations,null);
 const replay=await call('/api/inventory/opening-counts','POST',body,{idempotencyKey:key});
 assert.equal(replay.status,200);
 assert.equal(replay.data.id,created.data.id);
 assert.equal(replay.data.replayed,true);
 assert.equal((await call('/api/inventory/opening-counts','POST',{...body,quantity:9},{idempotencyKey:key})).status,409);
 assert.equal((await call('/api/inventory/opening-counts','POST',body,{idempotencyKey:randomUUID()})).status,409);
 const listed=await call('/api/inventory/opening-counts?page=1&limit=50');
 assert.equal(listed.status,200);
 const mine=listed.data.items.filter((row:any)=>row.productId===productId&&row.siteId===siteId);
 assert.equal(mine.length,1);
 assert.equal(mine[0].quantity,7);
 assert.equal(listed.data.availableToSell,null);
 const [rows]=await db.query<any[]>('SELECT COUNT(*) AS n FROM inventory_opening_counts WHERE product_id=? AND site_id=?',
  [productId,siteId]);
 assert.equal(Number(rows[0].n),1);
 const unsupported=await call('/api/inventory/opening-counts','DELETE',body);
 assert.equal(unsupported.status,404);
 assert.equal(unsupported.data.error,'Unknown API endpoint');
});


test('1EJ actor-scoped site list prevents OWNER-to-OWNER warehouse IDOR',async()=>{
 const own=await call('/api/inventory/sites');
 assert.equal(own.status,200);
 assert.equal(own.data.items.some((s:any)=>s.id===foreignSiteId),false);
 const foreign=await call('/api/inventory/sites','GET',undefined,
  {cookie:otherOwnerCookie});
 assert.equal(foreign.status,200);
 assert.equal(foreign.data.items.some((s:any)=>s.id===foreignSiteId),true);
 assert.equal(foreign.data.items.some((s:any)=>s.id===siteId),false);
 assert.match(own.data.authority,/OWNER_ATTESTED_SITE_ONLY/);
});
test('1EJ opening counts and total do not disclose another OWNER counts',async()=>{
 const mine=await call('/api/inventory/opening-counts?page=1&limit=50');
 assert.equal(mine.status,200);
 assert.equal(mine.data.items.some((c:any)=>c.id===foreignCountId),false);
 assert.equal(mine.data.items.some((c:any)=>c.siteId===foreignSiteId),false);
 assert.equal(mine.data.items.some((c:any)=>c.siteId===siteId),true);
 const outsider=await call('/api/inventory/opening-counts?page=1&limit=50',
  'GET',undefined,{cookie:otherOwnerCookie});
 assert.equal(outsider.status,200);
 assert.equal(outsider.data.items.some((c:any)=>c.id===foreignCountId),true);
 assert.equal(outsider.data.items.some((c:any)=>c.siteId===siteId),false);
 assert.equal(mine.data.total,mine.data.items.length);
 assert.equal(outsider.data.total,outsider.data.items.length);
 assert.equal(mine.data.availableToSell,null);
 assert.equal(outsider.data.availableToSell,null);
 assert.equal(mine.data.reservations,null);
 assert.equal(outsider.data.reservations,null);
});
test('1EJ privileged write and idempotency cannot target another OWNER site',async()=>{
 const body={productId,siteId:foreignSiteId,quantity:4,
  evidenceRef:'CI-FOREIGN-BOLA-ATTEMPT'};
 const key=randomUUID();
 const denied=await call('/api/inventory/opening-counts','POST',body,
  {idempotencyKey:key});
 assert.equal(denied.status,400);
 assert.match(denied.data.error,/Active product and registered site/);
 // The rejected MySQL transaction must not reserve the failed idempotency key.
 const [keys]=await db.query<any[]>(
  'SELECT COUNT(*) AS n FROM inventory_opening_requests WHERE actor_id=? AND request_key=?',
  [actor,key]);
 assert.equal(Number(keys[0].n),0);
 const [foreign]=await db.query<any[]>(
  'SELECT quantity,attested_by FROM inventory_opening_counts WHERE id=?',
  [foreignCountId]);
 assert.equal(foreign.length,1);
 assert.equal(Number(foreign[0].quantity),23);
 assert.equal(foreign[0].attested_by,otherOwner);
 const otherBody={productId,siteId,quantity:4,
  evidenceRef:'CI-REVERSE-FOREIGN-BOLA'};
 const deniedReverse=await call('/api/inventory/opening-counts','POST',
  otherBody,{cookie:otherOwnerCookie,idempotencyKey:randomUUID()});
 // The other owner has no password step-up; refuse before either actor scope or stock mutation.
 assert.equal(deniedReverse.status,403);
});
test('1EJ cross-owner count read rejects unprivileged and anonymous sessions',async()=>{
 for(const cookie of [reviewerCookie,'bad=1']){
  const result=await call('/api/inventory/opening-counts',
   'GET',undefined,{cookie});
  assert.equal(result.status,cookie===reviewerCookie?403:401);
 }
});
