import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import express from 'express';
import mysql from 'mysql2/promise';
import {getPool,getDatabaseConfig} from '../server/db';
import {hashToken} from '../server/auth/crypto';
import serviceDeskRouter,{readInternalTicketSnapshot} from '../server/serviceDesk/router';
import {MySQLCRMRepository,CRMOwnerInactiveError,lockActiveCrmOwner} from '../server/crm/repository';
import {validate} from '../server/crm/validation';

if(process.env.CRM_TEST_DB!=='1'||process.env.NODE_ENV!=='test'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FN integration test REFUSED outside disposable CI MySQL');
const db=getPool();if(!db)throw Error('1FN isolated MySQL unavailable');
after(async()=>{if(close)await close();await db.end();});
type Actor={id:string;token:string;csrf:string;cookie:string};
let owner:Actor,other:Actor,reviewer:Actor,ownerCustomer='',otherCustomer='',ticketId='',base='';
let pagedTicketId='';
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

test('1FQ real MySQL authenticated keyset audit walks past 100 events without BOLA or overlap',async()=>{
 // Generate 103 genuine internal application versions on a separate
 // disposable CI ticket owned by the OTHER test actor, not the primary ticket.
 const created=await request('/','POST',payload(otherCustomer),'other');
 assert.equal(created.status,201);
 const id=String(created.data.ticket.id);
 pagedTicketId=id;
 for(let version=2;version<=103;version++){
  const nextStatus=version%2===0?'TRIAGED_INTERNAL':'WAITING_INTERNAL';
  const changed=await request('/'+id+'/status','PATCH',{
   expectedVersion:version-1,nextStatus,note:'CI-only verified audit pagination '+version
  },'other');
  assert.equal(changed.status,200,'transition '+version+' must commit its audit entry');
  assert.equal(changed.data.version,version);
 }
 const first=await request('/'+id,'GET',undefined,'other');
 assert.equal(first.status,200);
 assert.equal(first.data.history.length,100);
 assert.equal(first.data.historyLimit,100);
 assert.equal(first.data.historyHasMore,true);
 assert.equal(first.data.nextBeforeVersion,4);
 assert.deepEqual(first.data.history.map((e:{versionAfter:number})=>e.versionAfter),
  Array.from({length:100},(_,i)=>i+4));
 const older=await request('/'+id+'/history?beforeVersion=4','GET',undefined,'other');
 assert.equal(older.status,200);
 assert.equal(older.data.cache,undefined);
 assert.equal(older.cache,'no-store');
 assert.equal(older.data.mode,'INTERNAL_HELD');
 assert.equal(older.data.externalDispatchEnabled,false);
 assert.equal(older.data.ticketId,id);
 assert.equal(older.data.historyHasMore,false);
 assert.equal(older.data.nextBeforeVersion,null);
 assert.deepEqual(older.data.history.map((e:{versionAfter:number})=>e.versionAfter),[1,2,3]);
 assert.equal(older.data.history[0].operation,'CREATE');
 const oldest=await request('/'+id+'/history?beforeVersion=1','GET',undefined,'other');
 assert.equal(oldest.status,200);
 assert.deepEqual(oldest.data.history,[]);
 assert.equal(oldest.data.historyHasMore,false);
 assert.equal((await request('/'+id+'/history?beforeVersion=4')).status,404);
 assert.equal((await request('/'+id+'/history?beforeVersion=4','GET',undefined,'reviewer')).status,403);
 assert.equal((await request('/'+id+'/history?beforeVersion=4','GET',undefined,'anon')).status,401);
 for(const query of ['','?beforeVersion=0','?beforeVersion=01','?beforeVersion=4.0',
  '?beforeVersion=4&beforeVersion=3','?beforeVersion=4&limit=10000',
  '?beforeVersion%5Bgt%5D=4']){
  const invalid=await request('/'+id+'/history'+query,'GET',undefined,'other');
  assert.equal(invalid.status,400,'untrusted cursor was accepted: '+query);
 }
 assert.equal(await count('service_ticket_audit_internal','ticket_id=?',[id]),103);
});

test('1FS real MySQL owner-only unsigned 103-event audit fingerprint and cap',async()=>{
 assert.ok(pagedTicketId,'1FQ 103-event synthetic fixture must precede fingerprint validation');
 const path='/'+pagedTicketId+'/audit-fingerprint';
 const one=await request(path,'GET',undefined,'other');
 assert.equal(one.status,200);
 assert.equal(one.cache,'no-store');
 assert.equal(one.data.ticketId,pagedTicketId);
 assert.equal(one.data.eventCount,103);
 assert.equal(one.data.latestVersion,103);
 assert.equal(one.data.mode,'INTERNAL_HELD');
 assert.equal(one.data.externalDispatchEnabled,false);
 assert.equal(one.data.scope,'APPLICATION_UNATTESTED');
 assert.equal(one.data.signatureVerified,false);
 assert.equal(one.data.externalAnchorVerified,false);
 assert.equal(one.data.customerConsentVerified,false);
 assert.match(one.data.auditDigestSha256,/^[0-9a-f]{64}$/);
 assert.equal(one.data.format,'aaditech/internal-ticket-audit/sha256/v1');
 assert.equal(one.data.history,undefined);
 assert.ok(!JSON.stringify(one.data).includes('CI-only verified audit pagination 42'),
  'Fingerprint response must never return raw audit note content');
 const repeated=await request(path,'GET',undefined,'other');
 assert.equal(repeated.status,200);
 assert.equal(repeated.data.auditDigestSha256,one.data.auditDigestSha256);
 assert.equal((await request(path)).status,404,'foreign OWNER cannot fingerprint other ticket');
 assert.equal((await request(path,'GET',undefined,'reviewer')).status,403);
 assert.equal((await request(path,'GET',undefined,'anon')).status,401);
 for(const query of ['?limit=100000','?beforeVersion=2','?probe=1&probe=2']){
  assert.equal((await request(path+query,'GET',undefined,'other')).status,400,
   'Untrusted fingerprint query parameter accepted');
 }
 const [rows]=await db!.query<any[]>(
  'SELECT note FROM service_ticket_audit_internal WHERE ticket_id=? AND version_after=42',
  [pagedTicketId]);
 assert.equal(rows.length,1);
 try{
  await db!.execute(
   'UPDATE service_ticket_audit_internal SET note=? WHERE ticket_id=? AND version_after=42',
   ['CI-only deliberate data tamper, unsigned fingerprint',pagedTicketId]);
  const modified=await request(path,'GET',undefined,'other');
  assert.equal(modified.status,200,
   'A self-calculated hash is NOT an independent tamper attestation');
  assert.notEqual(modified.data.auditDigestSha256,one.data.auditDigestSha256);
 }finally{
  await db!.execute(
   'UPDATE service_ticket_audit_internal SET note=? WHERE ticket_id=? AND version_after=42',
   [rows[0].note,pagedTicketId]);
 }
 assert.equal((await request(path,'GET',undefined,'other')).data.auditDigestSha256,
  one.data.auditDigestSha256);
 try{
  await db!.execute('UPDATE service_tickets_internal SET version=1001 WHERE id=?',[pagedTicketId]);
  const over=await request(path,'GET',undefined,'other');
  assert.equal(over.status,409);
  assert.equal(over.data.mode,'INTERNAL_HELD');
  assert.equal(over.data.externalDispatchEnabled,false);
  assert.equal(over.data.auditDigestSha256,undefined);
 }finally{
  await db!.execute('UPDATE service_tickets_internal SET version=103 WHERE id=?',[pagedTicketId]);
 }
 assert.equal((await request(path,'GET',undefined,'other')).status,200);
 assert.equal(await count('service_ticket_audit_internal','ticket_id=?',[pagedTicketId]),103);
});

test('1FR real MySQL read-only snapshot rejects mixed ticket/audit versions and tampered events',async()=>{
 const created=await request('/','POST',payload(otherCustomer),'other');
 assert.equal(created.status,201);
 const id=String(created.data.ticket.id);
 // Commit a legitimate transition *between* two SELECTs in the same
 // read-only InnoDB snapshot; both queries must keep seeing version 1.
 const writer=await db!.getConnection();
 let begun=false;
 try{
  await readInternalTicketSnapshot(db!,async(snapshot)=>{
   const [before]=await snapshot.query<any[]>(
    'SELECT version,status FROM service_tickets_internal WHERE id=?',[id]);
   assert.equal(before[0].version,1);
   assert.equal(before[0].status,'OPEN_INTERNAL');
   await writer.beginTransaction();begun=true;
   await writer.execute(
    "UPDATE service_tickets_internal SET status='TRIAGED_INTERNAL',version=2 WHERE id=?",[id]);
   await writer.execute(`INSERT INTO service_ticket_audit_internal
    (id,ticket_id,actor_user_id,operation,from_status,to_status,note,version_after)
    VALUES (?,?,?,'STATUS_CHANGE','OPEN_INTERNAL','TRIAGED_INTERNAL',?,2)`,
    [randomUUID(),id,other.id,'1FR atomic external writer simulation in disposable CI']);
   await writer.commit();begun=false;
   const [after]=await snapshot.query<any[]>(
    'SELECT version,status FROM service_tickets_internal WHERE id=?',[id]);
   const [audit]=await snapshot.query<any[]>(
    'SELECT MAX(version_after) AS latest FROM service_ticket_audit_internal WHERE ticket_id=?',[id]);
   assert.equal(after[0].version,1,'snapshot cannot silently switch to the committed writer version');
   assert.equal(after[0].status,'OPEN_INTERNAL');
   assert.equal(Number(audit[0].latest),1,'snapshot audit must match first ticket read');
  });
 }finally{
  if(begun)await writer.rollback().catch(()=>{});
  writer.release();
 }
 const now=await request('/'+id,'GET',undefined,'other');
 assert.equal(now.status,200);
 assert.equal(now.data.ticket.version,2);
 assert.deepEqual(now.data.history.map((x:{versionAfter:number})=>x.versionAfter),[1,2]);
 // These are isolated disposable DB mutations, NOT production repair or
 // evidence verification. Restore every intentional corruption immediately.
 try{
  await db!.execute("UPDATE service_ticket_audit_internal SET to_status='WAITING_INTERNAL' WHERE ticket_id=? AND version_after=2",[id]);
  assert.equal((await request('/'+id,'GET',undefined,'other')).status,503);
  assert.equal((await request('/'+id+'/history?beforeVersion=3','GET',undefined,'other')).status,503);
 }finally{
  await db!.execute("UPDATE service_ticket_audit_internal SET to_status='TRIAGED_INTERNAL' WHERE ticket_id=? AND version_after=2",[id]);
 }
 try{
  await db!.execute('UPDATE service_tickets_internal SET version=3 WHERE id=?',[id]);
  assert.equal((await request('/'+id,'GET',undefined,'other')).status,503,
   'Missing latest audit must refuse rather than return incomplete history');
 }finally{
  await db!.execute('UPDATE service_tickets_internal SET version=2 WHERE id=?',[id]);
 }
 try{
  await db!.execute('UPDATE service_ticket_audit_internal SET version_after=7 WHERE ticket_id=? AND version_after=1',[id]);
  assert.equal((await request('/'+id,'GET',undefined,'other')).status,503,
   'Missing genesis entry must refuse');
 }finally{
  await db!.execute('UPDATE service_ticket_audit_internal SET version_after=1 WHERE ticket_id=? AND version_after=7',[id]);
 }
 assert.equal((await request('/'+id,'GET',undefined,'other')).status,200);
 assert.equal((await request('/'+id+'/history?beforeVersion=3','GET',undefined,'other')).status,200);
 assert.equal(await count('service_ticket_audit_internal','ticket_id=?',[id]),2);
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
