import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import express from 'express';
import mysql from 'mysql2/promise';
import {getPool,getDatabaseConfig} from '../server/db';
import {hashToken} from '../server/auth/crypto';
import serviceDeskRouter from '../server/serviceDesk/router';
import {MySQLCRMRepository,CRMOwnerInactiveError,lockActiveCrmOwner} from '../server/crm/repository';
import {validate} from '../server/crm/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.NODE_ENV!=='test'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FN integration test REFUSED outside disposable CI MySQL');
const db=getPool();if(!db)throw Error('1FN isolated MySQL unavailable');
after(async()=>{if(close)await close();await db.end();});
type Actor={id:string;token:string;csrf:string;cookie:string};
let owner:Actor,other:Actor,reviewer:Actor,ownerCustomer='',otherCustomer='',ticketId='',base='';
let close:(()=>Promise<void>)|undefined;
const repository=new MySQLCRMRepository(db);
async function makeActor(role:'OWNER'|'REVIEWER'):Promise<Actor>{
 const id=randomUUID(),token=randomBytes(32).toString('base64url'),
  csrf=randomBytes(32).toString('base64url');
 await db!.execute("INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,?,?)",
  [id,'ci-fn-'+id+'@example.invalid','FN isolated '+role,'ci-only-hash',role]);
 await db!.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
  VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,[hashToken(token),id,csrf]);
 return {id,token,csrf,cookie:'aaditech_session='+token};
}
async function makeCustomer(actor:Actor,name:string){
 const data=validate('customers',{
  name,contactPerson:'CI test operator',email:'ci-customer-'+randomUUID()+'@example.invalid',
  phone:'0000000000',city:'Mumbai',state:'Maharashtra'
 });
 return (await repository.create('customers',data,actor.id) as {id:string}).id;
}
async function request(route:string,method='GET',body?:unknown,as:'owner'|'other'|'reviewer'|'anon'='owner'){
 const actor=as==='owner'?owner:as==='other'?other:as==='reviewer'?reviewer:null;
 const headers:Record<string,string>={};
 if(actor)headers.cookie=actor.cookie;
 if(body!==undefined)headers['content-type']='application/json';
 if(actor&&!['GET','HEAD'].includes(method))headers['x-csrf-token']=actor.csrf;
 const response=await fetch(base+'/api/service-desk/internal-tickets'+route,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();let data:any={};
 try{data=raw?JSON.parse(raw):{};}catch{data={error:'Non-JSON response'};}
 return {status:response.status,data,cache:response.headers.get('cache-control')};
}
const payload=(customerId:string)=>({
 customerId,guideId:'wifi-no-internet',subject:'CI Wi-Fi disconnect after login',
 description:'CI internal observation, no verified customer request',
 priority:'NORMAL',acknowledgeUnverifiedConsent:true
});
async function count(table:'service_tickets_internal'|'service_ticket_audit_internal',where:string,params:unknown[]){
 const [rows]=await db!.query<any[]>(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`,params);
 return Number(rows[0].n);
}

test('1FN isolated owner, independent other owner/reviewer and CRM provenance fixture',async()=>{
 owner=await makeActor('OWNER');
 other=await makeActor('OWNER');
 reviewer=await makeActor('REVIEWER');
 ownerCustomer=await makeCustomer(owner,'FN CI customer scoped to owner');
 otherCustomer=await makeCustomer(other,'FN CI different-owner customer');
 const app=express();app.use(express.json());
 app.use('/api/service-desk/internal-tickets',serviceDeskRouter);
 app.use('/api',(_req,res)=>res.status(404).json({error:'Unknown endpoint'}));
 const listener=app.listen(0,'127.0.0.1');
 await new Promise<void>(resolve=>listener.once('listening',resolve));
 const address=listener.address();assert.ok(address&&typeof address!=='string');
 base='http://127.0.0.1:'+address.port;
 close=()=>new Promise<void>((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
});

test('1FN owner-only GET and create fail closed on no consent, foreign CRM and missing audit',async()=>{
 const list=await request('/');
 assert.equal(list.status,200);assert.equal(list.cache,'no-store');
 assert.deepEqual(list.data.items,[]);
 assert.equal(list.data.externalDispatchEnabled,false);
 assert.equal((await request('/','GET',undefined,'anon')).status,401);
 assert.equal((await request('/','GET',undefined,'reviewer')).status,403);
 assert.equal((await request('/','POST',payload(ownerCustomer),'reviewer')).status,403);
 assert.equal((await request('/','POST',{...payload(ownerCustomer),acknowledgeUnverifiedConsent:false})).status,400);
 assert.equal((await request('/','POST',{...payload(ownerCustomer),priority:'CRITICAL'})).status,400);
 assert.equal((await request('/','POST',payload(otherCustomer))).status,404);
 const noAuditId=randomUUID();
 await db!.execute(`INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state)
  VALUES (?,?,?,?,?,?,?)`,[noAuditId,'CI forged legacy','N/A','ci-forged-'+noAuditId+'@example.invalid','000','CI','CI']);
 assert.equal((await request('/','POST',payload(noAuditId))).status,404);
 assert.equal(await count('service_tickets_internal','owner_user_id=?',[owner.id]),0);
});

test('1FN internal ticket creation is atomic with audit, owner scoped, and cannot dispatch',async()=>{
 const created=await request('/','POST',payload(ownerCustomer));
 assert.equal(created.status,201);
 assert.equal(created.data.ticket.status,'OPEN_INTERNAL');
 assert.equal(created.data.ticket.version,1);
 assert.equal(created.data.ticket.customerConsentState,'UNVERIFIED');
 assert.equal(created.data.ticket.externalDispatchState,'DISABLED');
 assert.equal(created.data.externalDispatchEnabled,false);
 ticketId=String(created.data.ticket.id);
 assert.match(ticketId,/^[a-f0-9-]{36}$/);
 const list=await request('/');
 assert.equal(list.status,200);
 assert.equal(list.data.items.length,1);
 assert.equal(list.data.items[0].id,ticketId);
 const detail=await request('/'+ticketId);
 assert.equal(detail.status,200);
 assert.equal(detail.data.history.length,1);
 assert.equal(detail.data.historyLimit,100);
 assert.equal(detail.data.historyHasMore,false);
 assert.equal(detail.data.history[0].operation,'CREATE');
 assert.equal(detail.data.history[0].versionAfter,1);
 assert.equal((await request('/'+ticketId,'GET',undefined,'other')).status,404);
 assert.equal((await request('/'+ticketId,'GET',undefined,'reviewer')).status,403);
 assert.equal((await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:'Foreign owner attempt'
 },'other')).status,404);
 const otherCreated=await request('/','POST',payload(otherCustomer),'other');
 assert.equal(otherCreated.status,201);
 const ownerList=await request('/');
 assert.equal(ownerList.data.items.length,1);
 assert.equal(ownerList.data.items[0].id,ticketId);
 assert.equal(await count('service_tickets_internal','owner_user_id=?',[owner.id]),1);
});

test('1FN transition permissions, stale versions and held terminal state preserve audit chronology',async()=>{
 const wrong=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:1,nextStatus:'RESOLVED_HELD',note:'Skip triage attempt'});
 assert.equal(wrong.status,400);
 const triage=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:'Operator-only triage'});
 assert.equal(triage.status,200);assert.equal(triage.data.version,2);
 const stale=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:1,nextStatus:'WAITING_INTERNAL',note:'Stale'});
 assert.equal(stale.status,409);
 const waiting=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:2,nextStatus:'WAITING_INTERNAL',note:'Waiting for internal facts'});
 assert.equal(waiting.status,200);assert.equal(waiting.data.version,3);
 const returned=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:3,nextStatus:'TRIAGED_INTERNAL',note:'Internal facts collected'});
 assert.equal(returned.status,200);assert.equal(returned.data.version,4);
 const held=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:4,nextStatus:'RESOLVED_HELD',note:'Needs actual customer verification'});
 assert.equal(held.status,200);assert.equal(held.data.version,5);
 assert.equal((await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:5,nextStatus:'CLOSED',note:'Unapproved external closure'})).status,400);
 assert.equal((await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:5,nextStatus:'TRIAGED_INTERNAL',note:'Held state cannot reopen'})).status,400);
 const detail=await request('/'+ticketId);
 assert.equal(detail.status,200);
 assert.equal(detail.data.ticket.status,'RESOLVED_HELD');
 assert.equal(detail.data.ticket.customerConsentState,'UNVERIFIED');
 assert.equal(detail.data.ticket.externalDispatchState,'DISABLED');
 assert.deepEqual(detail.data.history.map((x:{versionAfter:number})=>x.versionAfter),[1,2,3,4,5]);
 assert.equal(detail.data.historyLimit,100);
 assert.equal(detail.data.historyHasMore,false);
 assert.equal(await count('service_ticket_audit_internal','ticket_id=?',[ticketId]),5);
});

test('1FN disabled OWNER cannot create or mutate, and no rows are appended',async()=>{
 const before=await count('service_ticket_audit_internal','ticket_id=?',[ticketId]);
 await db!.execute("UPDATE auth_users SET status='DISABLED' WHERE id=?",[owner.id]);
 const deniedCreate=await request('/','POST',payload(ownerCustomer));
 assert.ok([401,403].includes(deniedCreate.status));
 const deniedPatch=await request('/'+ticketId+'/status','PATCH',{
  expectedVersion:5,nextStatus:'TRIAGED_INTERNAL',note:'Inactive owner'});
 assert.ok([401,403].includes(deniedPatch.status));
 assert.equal(await count('service_ticket_audit_internal','ticket_id=?',[ticketId]),before);
 assert.equal(await count('service_tickets_internal','owner_user_id=?',[owner.id]),1);
});

test('1FN real MySQL OWNER lock rejects mutation behind concurrent role demotion',async()=>{
 const actor=await makeActor('OWNER');
 const blocker=await db!.getConnection(),pool=mysql.createPool({...getDatabaseConfig(),connectionLimit:1});
 let started=false;
 try{
  const worker=await pool.getConnection();
  try{
   await worker.query('SET SESSION innodb_lock_wait_timeout=1');
   await blocker.beginTransaction();started=true;
   const [changed]=await blocker.execute<any>("UPDATE auth_users SET role='REVIEWER' WHERE id=?",[actor.id]);
   assert.equal(changed.affectedRows,1);
   await worker.beginTransaction();
   await assert.rejects(lockActiveCrmOwner(worker,actor.id),
    (e:any)=>e?.code==='ER_LOCK_WAIT_TIMEOUT');
   await worker.rollback();
   await blocker.commit();started=false;
   await worker.beginTransaction();
   await assert.rejects(lockActiveCrmOwner(worker,actor.id),
    (e:any)=>e instanceof CRMOwnerInactiveError);
   await worker.rollback();
  }finally{worker.release();}
 }finally{
  if(started)await blocker.rollback().catch(()=>{});
  blocker.release();await pool.end();
 }
});
