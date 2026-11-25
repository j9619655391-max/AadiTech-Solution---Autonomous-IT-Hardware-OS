import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import express from 'express';
import mysql from 'mysql2/promise';
import {getPool,getDatabaseConfig} from '../server/db';
import {hashToken} from '../server/auth/crypto';
import {MySQLCRMRepository,CRMOwnerInactiveError,lockActiveCrmOwner} from '../server/crm/repository';
import {validate} from '../server/crm/validation';
import quoteRouter from '../server/quotes/router';

// This fixture is never allowed to connect to authorized staging or production.
if(process.env.CRM_TEST_DB!=='1'||process.env.NODE_ENV!=='test'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FK quote OWNER race fixture requires disposable aaditech_ci only');
const db=getPool();
if(!db)throw Error('1FK disposable MySQL pool unavailable');
after(async()=>{await db.end();});

async function createOwner(){
 const id=randomUUID(),secret=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 await db!.execute(
  "INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-NOT-VALID-PASSWORD','OWNER')",
  [id,'fk-owner-'+id+'@example.invalid','FK synthetic owner']);
 await db!.execute(
  'INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))',
  [hashToken(secret),id,csrf]);
 return {id,secret,csrf};
}
async function count(sql:string,params:unknown[]){
 const [rows]=await db!.query<any[]>(sql,params);
 return Number(rows[0].n);
}
test('1FK M04 actual HTTP draft create, replay and revision stay committed only while OWNER active',async()=>{
 const actor=await createOwner(),repository=new MySQLCRMRepository(db!);
 const customer=await repository.create('customers',validate('customers',{
  name:'FK quoted customer',contactPerson:'CI buyer',email:'buyer-fk@example.invalid',
  phone:'0000000000',city:'Mumbai',state:'Maharashtra'}),actor.id) as {id:string};
 const product=await repository.create('products',validate('products',{
  sku:'FK-'+randomUUID(),brand:'Example',model:'Quote guard fixture',
  category:'SERVER',specs:'Synthetic only',unitCost:'100.00',sellingPrice:'120.00',
  minPrice:'110.00',gstRate:'18.00',hsn:'8471'}),actor.id) as {id:string};
 const app=express();
 app.use(express.json());
 app.use('/api/quotes/drafts',quoteRouter);
 const server=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>server.once('listening',resolve));
 const address=server.address();
 assert.ok(address&&typeof address!=='string');
 const base='http://127.0.0.1:'+address.port;
 const request=async(path:string,body:object,key?:string)=>{
  const headers:Record<string,string>={
   'content-type':'application/json','cookie':'aaditech_session='+actor.secret,
   'x-csrf-token':actor.csrf
  };
  if(key)headers['idempotency-key']=key;
  const response=await fetch(base+path,{method:'POST',headers,body:JSON.stringify(body)});
  return {status:response.status,data:await response.json() as any};
 };
 const draftInput={customerId:customer.id,items:[{productId:product.id,quantity:2}]};
 const key=randomUUID();
 try{
  const created=await request('/api/quotes/drafts',draftInput,key);
  assert.equal(created.status,201);
  assert.equal(created.data.replayed,false);
  const draftId=String(created.data.id);
  const replay=await request('/api/quotes/drafts',draftInput,key);
  assert.equal(replay.status,200);
  assert.equal(replay.data.replayed,true);
  assert.equal(replay.data.id,draftId);
  const revisionInput={
   expectedRevision:0,reason:'CI-only bounded internal revision',
   items:[{productId:product.id,quantity:2}]
  };
  const revision=await request('/api/quotes/drafts/'+draftId+'/revisions',revisionInput);
  assert.equal(revision.status,201);
  assert.equal(revision.data.revision,1);
  assert.equal(await count('SELECT COUNT(*) AS n FROM sales_quote_draft_revisions WHERE quote_id=?',[draftId]),1);
  await db!.execute("UPDATE auth_users SET status='DISABLED' WHERE id=?",[actor.id]);
  const deniedNew=await request('/api/quotes/drafts',draftInput,randomUUID());
  assert.ok([401,403].includes(deniedNew.status));
  const deniedReplay=await request('/api/quotes/drafts',draftInput,key);
  assert.ok([401,403].includes(deniedReplay.status));
  const deniedRevision=await request('/api/quotes/drafts/'+draftId+'/revisions',
   {...revisionInput,expectedRevision:1});
  assert.ok([401,403].includes(deniedRevision.status));
  assert.equal(await count('SELECT COUNT(*) AS n FROM sales_quote_drafts WHERE created_by=?',[actor.id]),1);
  assert.equal(await count('SELECT COUNT(*) AS n FROM sales_quote_create_requests WHERE actor_id=?',[actor.id]),1);
  assert.equal(await count('SELECT COUNT(*) AS n FROM sales_quote_draft_revisions WHERE quote_id=?',[draftId]),1);
 }finally{
  await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
 }
});

test('1FK InnoDB row lock serializes demotion ahead of quote OWNER authorization',async()=>{
 const actor=await createOwner();
 const blocker=await db!.getConnection();
 const candidate=mysql.createPool({...getDatabaseConfig(),connectionLimit:1});
 let open=false;
 try{
  const worker=await candidate.getConnection();
  try{
   await worker.query('SET SESSION innodb_lock_wait_timeout=1');
   await blocker.beginTransaction();open=true;
   const [changed]=await blocker.execute<any>(
    "UPDATE auth_users SET role='REVIEWER' WHERE id=? AND role='OWNER'",[actor.id]);
   assert.equal(changed.affectedRows,1);
   await worker.beginTransaction();
   await assert.rejects(
    lockActiveCrmOwner(worker,actor.id),
    (e:unknown)=>Boolean(e&&typeof e==='object'&&'code' in e&&e.code==='ER_LOCK_WAIT_TIMEOUT'),
    'quote guard must not bypass an in-flight OWNER demotion lock');
   await worker.rollback();
   await blocker.commit();open=false;
   await worker.beginTransaction();
   await assert.rejects(lockActiveCrmOwner(worker,actor.id),
    (e:unknown)=>e instanceof CRMOwnerInactiveError);
   await worker.rollback();
  }finally{worker.release();}
 }finally{
  if(open)await blocker.rollback().catch(()=>{});
  blocker.release();await candidate.end();
 }
});

test('1FK every quote draft write transaction locks OWNER before writes or idempotency replay',()=>{
 const source=readFileSync('server/quotes/router.ts','utf8');
 assert.match(source,/CRMOwnerInactiveError/);
 assert.match(source,/res\.status\(403\)\.json\(\{error:'Active OWNER account required'\}\)/);
 const writeLocks=[...source.matchAll(/await lockActiveCrmOwner\((?:connection|conn),res\.locals\.auth\.userId\)/g)];
 assert.equal(writeLocks.length,2,'both draft creation/replay and revision writes require a transaction guard');
 const create=source.slice(source.indexOf("router.post('/',"),source.indexOf("router.get('/:id/revisions'"));
 assert.ok(create.indexOf('await connection.beginTransaction()')<create.indexOf('await lockActiveCrmOwner('));
 assert.ok(create.indexOf('await lockActiveCrmOwner(')<create.indexOf('INSERT IGNORE INTO sales_quote_create_requests'));
 const revise=source.slice(source.indexOf("router.post('/:id/revisions'"));
 assert.ok(revise.indexOf('await conn.beginTransaction()')<revise.indexOf('await lockActiveCrmOwner('));
 assert.ok(revise.indexOf('await lockActiveCrmOwner(')<revise.indexOf('SELECT id FROM sales_quote_drafts'));
});
