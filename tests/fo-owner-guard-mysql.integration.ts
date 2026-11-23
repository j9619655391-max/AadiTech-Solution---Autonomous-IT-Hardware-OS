import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import express from 'express';
import mysql from 'mysql2/promise';
import {getPool,getAuthPool,getDatabaseConfig} from '../server/db';
import {hashToken} from '../server/auth/crypto';
import {lockActiveCrmOwner,CRMOwnerInactiveError,MySQLCRMRepository} from '../server/crm/repository';
import crmRouter from '../server/crm/router';
import quoteRouter from '../server/quotes/router';
import ticketRouter from '../server/serviceDesk/router';
import {validate} from '../server/crm/validation';
import {checkStagingRuntimeDbPrivilegeIntegrity} from '../scripts/staging-preflight';

if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
 process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FO authority routine test must run ONLY on disposable CI MySQL');

test('1FO restricted runtime HTTP CRM/quote/service-desk uses exact DEFINER guard without auth table grants',async()=>{
 const cfg=getDatabaseConfig();
 const admin=mysql.createPool({...cfg,connectionLimit:3,waitForConnections:true});
 const suffix=randomBytes(7).toString('hex'),user='ci_fo_rt_'+suffix,
  password=randomBytes(32).toString('base64url'),account="'"+user+"'@'%'";
 const actor=randomUUID(),token=randomBytes(32).toString('base64url'),
  csrf=randomBytes(32).toString('base64url');
 let createdUser=false,createdRoutine=false,listener:ReturnType<express.Express['listen']>|undefined;
 let runtime:mysql.Pool|undefined,auth:mysql.Pool|undefined;
 const original={DB_USER:process.env.DB_USER,DB_PASSWORD:process.env.DB_PASSWORD,
  AUTH_DB_USER:process.env.AUTH_DB_USER,AUTH_DB_PASSWORD:process.env.AUTH_DB_PASSWORD,
  AUTH_OWNER_GUARD_MODE:process.env.AUTH_OWNER_GUARD_MODE};
 const restore=()=>{for(const [k,v] of Object.entries(original)){
  if(v===undefined)delete process.env[k];else process.env[k]=v;
 }};
 const invoke=async(base:string,path:string,method='GET',body?:unknown,extra:Record<string,string>={})=>{
  const headers:Record<string,string>={
   'cookie':'aaditech_session='+token,'x-csrf-token':csrf,...extra
  };
  if(body!==undefined)headers['content-type']='application/json';
  const r=await fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const raw=await r.text();let data:any={};
  if(raw){try{data=JSON.parse(raw);}catch{data={error:'Non-JSON'};}}
  return {status:r.status,data};
 };
 try{
  const [old]=await admin.query<any[]>(`SELECT COUNT(*) AS n FROM information_schema.ROUTINES
   WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='aaditech_guard_active_owner'`);
  assert.equal(Number(old[0].n),0,'fixture must not replace an existing, differently defined routine');
  const sql=readFileSync('database/authority/phase1fo_active_owner_guard.sql','utf8');
  await admin.query(sql);
  createdRoutine=true;
  await admin.query('CREATE USER '+account+' IDENTIFIED BY ?',[password]);
  createdUser=true;
  const grants=[
   ['SELECT, INSERT, UPDATE, DELETE','crm_customers'],
   ['SELECT, INSERT','crm_audit_events'],
   ['SELECT, INSERT, UPDATE','crm_products'],
   ['SELECT, INSERT, UPDATE','crm_leads'],
   ['SELECT, INSERT','sales_quote_drafts'],
   ['SELECT, INSERT','sales_quote_draft_items'],
   ['SELECT, INSERT, UPDATE','sales_quote_create_requests'],
   ['SELECT, INSERT','sales_quote_draft_revisions'],
   ['SELECT, INSERT, UPDATE','service_tickets_internal'],
   ['SELECT, INSERT','service_ticket_audit_internal']
  ];
  for(const [privileges,table] of grants){
   await admin.query('GRANT '+privileges+' ON '+BT+'aaditech_ci'+BT+'.'+BT+table+BT+' TO '+account);
  }
  await admin.query('GRANT EXECUTE ON PROCEDURE aaditech_ci.aaditech_guard_active_owner TO '+account);
  await admin.execute(
   "INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-INVALID-HASH','OWNER')",
   [actor,'fo-'+actor+'@example.invalid','FO synthetic owner']);
  await admin.execute(`INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at)
   VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR))`,
   [hashToken(token),actor,csrf]);
  // Runtime and AUTH pool must authenticate independently. getPool() has not
  // been initialized in this isolated test process before this point.
  process.env.DB_USER=user;
  process.env.DB_PASSWORD=password;
  process.env.AUTH_DB_USER=cfg.user;
  process.env.AUTH_DB_PASSWORD=cfg.password;
  process.env.AUTH_OWNER_GUARD_MODE='procedure';
  runtime=getPool()!;
  assert.ok(runtime);
  auth=getAuthPool()!;
  assert.ok(auth);
  const [principals]=await runtime.query<any[]>('SELECT CURRENT_USER() AS who,CURRENT_ROLE() AS activeRole');
  const [authWho]=await auth.query<any[]>('SELECT CURRENT_USER() AS who');
  assert.notEqual(principals[0].who,authWho[0].who);
  assert.equal(principals[0].activeRole,'NONE');
  await assert.rejects(runtime.query('SELECT id FROM auth_users LIMIT 1'),
   (e:any)=>e?.code==='ER_TABLEACCESS_DENIED_ERROR'||e?.code==='ER_DBACCESS_DENIED_ERROR');
  await assert.rejects(runtime.query('UPDATE auth_users SET status=status WHERE id=?',[actor]),
   (e:any)=>e?.code==='ER_TABLEACCESS_DENIED_ERROR'||e?.code==='ER_DBACCESS_DENIED_ERROR');
  const observed=await checkStagingRuntimeDbPrivilegeIntegrity(
   runtime,'aaditech_ci',{requireOwnerGuard:true});
  assert.equal(observed.dataGrantCount,grants.length);

  const app=express();
  app.use(express.json());
  app.use('/api/crm',crmRouter);
  app.use('/api/quotes/drafts',quoteRouter);
  app.use('/api/service-desk/internal-tickets',ticketRouter);
  listener=app.listen(0,'127.0.0.1');
  await new Promise<void>(resolve=>listener!.once('listening',resolve));
  const address=listener.address();
  assert.ok(address&&typeof address!=='string');
  const base='http://127.0.0.1:'+address.port;
  const customer=await invoke(base,'/api/crm/customers','POST',{
   name:'FO isolated synthetic customer',contactPerson:'CI contact',
   email:'fo-customer-'+randomUUID()+'@example.invalid',phone:'0000000000',
   city:'Mumbai',state:'Maharashtra'
  });
  assert.equal(customer.status,201,JSON.stringify(customer.data));
  const customerId=String(customer.data.id);
  const product=await invoke(base,'/api/crm/products','POST',{
   sku:'FO-'+randomUUID(),brand:'CI',model:'Test Server',category:'SERVER',
   specs:'Synthetic, no external inventory',unitCost:'100.00',
   sellingPrice:'200.00',minPrice:'150.00',gstRate:'18.00',hsn:'8471'
  });
  assert.equal(product.status,201,JSON.stringify(product.data));
  const quote=await invoke(base,'/api/quotes/drafts','POST',{
   customerId,items:[{productId:String(product.data.id),quantity:1}]
  },{'idempotency-key':randomUUID()});
  assert.equal(quote.status,201,JSON.stringify(quote.data));
  assert.equal(quote.data.replayed,false);
  const ticket=await invoke(base,'/api/service-desk/internal-tickets','POST',{
   customerId,guideId:'wifi-no-internet',subject:'CI offline network internal note',
   description:'CI-only internal troubleshooting simulation',priority:'NORMAL',
   acknowledgeUnverifiedConsent:true
  });
  assert.equal(ticket.status,201,JSON.stringify(ticket.data));
  assert.equal(ticket.data.ticket.customerConsentState,'UNVERIFIED');
  assert.equal(ticket.data.ticket.externalDispatchState,'DISABLED');
  const updated=await invoke(base,
   '/api/service-desk/internal-tickets/'+ticket.data.ticket.id+'/status','PATCH',{
    expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:'CI-only owner internal triage'
   });
  assert.equal(updated.status,200,JSON.stringify(updated.data));
  // The guard prevents stale middleware privileges: an in-flight role change
  // holds the same InnoDB auth_users row lock reached *through* the definer.
  const blocker=await admin.getConnection();
  let open=false;
  try{
   await blocker.beginTransaction();open=true;
   const [changed]=await blocker.execute<any>(
    "UPDATE auth_users SET status='DISABLED' WHERE id=?",[actor]);
   assert.equal(changed.affectedRows,1);
   const candidate=await runtime.getConnection();
   try{
    await candidate.query('SET SESSION innodb_lock_wait_timeout=1');
    await candidate.beginTransaction();
    await assert.rejects(lockActiveCrmOwner(candidate,actor),
     (e:any)=>e?.code==='ER_LOCK_WAIT_TIMEOUT');
    await candidate.rollback();
   }finally{candidate.release();}
   await blocker.commit();open=false;
  }finally{
   if(open)await blocker.rollback().catch(()=>{});
   blocker.release();
  }
  const conn=await runtime.getConnection();
  try{
   await conn.beginTransaction();
   await assert.rejects(lockActiveCrmOwner(conn,actor),
    (e:any)=>e instanceof CRMOwnerInactiveError);
   await conn.rollback();
  }finally{conn.release();}
  const rejected=await invoke(base,'/api/service-desk/internal-tickets','POST',{
   customerId,guideId:'pc-slow',subject:'Unauthorized second ticket',
   description:'Must be denied after account disable',priority:'LOW',
   acknowledgeUnverifiedConsent:true
  });
  assert.ok([401,403].includes(rejected.status));
  const [counts]=await admin.query<any[]>(
   'SELECT COUNT(*) AS n FROM service_tickets_internal WHERE owner_user_id=?',[actor]);
  assert.equal(Number(counts[0].n),1);
 }finally{
  if(listener)await new Promise<void>((resolve,reject)=>listener!.close(e=>e?reject(e):resolve()));
  if(runtime)await runtime.end();
  if(auth&&auth!==runtime)await auth.end();
  restore();
  if(createdUser)await admin.query('DROP USER '+account);
  if(createdRoutine)await admin.query('DROP PROCEDURE aaditech_ci.aaditech_guard_active_owner');
  await admin.end();
 }
});
