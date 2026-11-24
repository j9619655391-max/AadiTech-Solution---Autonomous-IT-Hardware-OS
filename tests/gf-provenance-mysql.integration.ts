import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {hashToken} from '../server/auth/crypto';
import {assessRuntimeGrantEnvelope} from '../scripts/phase1fb-runtime-db-privileges';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {gfMigrationTarget,checkInstalledGfIntegrity} from '../scripts/migrate-gf-provenance';

test('1GF disposable MySQL enforces unique origin and one-time same-owner quote binding',async()=>{
 gfMigrationTarget(process.env);
 const cfg=getDatabaseConfig(),admin=mysql.createPool({...cfg,connectionLimit:2});
 const user='ci_gf_'+randomBytes(7).toString('hex'),account="'"+user+"'@'%'",password=randomBytes(32).toString('base64url');
 const actor=randomUUID(),other=randomUUID(),customer=randomUUID(),q1=randomUUID(),q2=randomUUID(),foreign=randomUUID(),key=randomUUID();
 const hash='a'.repeat(64);
 let created=false,runtime:mysql.Pool|undefined;
 try{
  await checkInstalledGfIntegrity(admin);
  for(const id of [actor,other])await admin.execute("INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-INVALID-HASH','OWNER')",
   [id,'gf-'+id+'@example.invalid','GF synthetic owner']);
  await admin.execute("INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,'GF test','CI','gf@example.invalid','0000000000','Mumbai','Maharashtra')",[customer]);
  for(const [id,owner] of [[q1,actor],[q2,actor],[foreign,other]])await admin.execute(
   'INSERT INTO sales_quote_drafts(id,customer_id,created_by,subtotal,tax_estimate,total_estimate) VALUES (?,?,?,100,18,118)',[id,customer,owner]);
  await admin.query('CREATE USER '+account+' IDENTIFIED BY ?',[password]);created=true;
  await admin.query('GRANT SELECT, INSERT ON aaditech_ci.crm_audit_events TO '+account);
  await admin.query('GRANT SELECT, INSERT, UPDATE ON aaditech_ci.sales_quote_create_requests TO '+account);
  runtime=mysql.createPool({...cfg,user,password,connectionLimit:2});
  const origin=(owner:string,operation:string)=>runtime!.execute(
   'INSERT INTO crm_audit_events(id,actor_user_id,entity_type,entity_id,operation) VALUES (?,?,\'customers\',?,?)',
   [randomUUID(),owner,customer,operation]);
  const first=await Promise.allSettled([origin(actor,'CREATE'),origin(actor,'CREATE')]);
  assert.equal(first.filter(x=>x.status==='fulfilled').length,1);
  const failure=first.find(x=>x.status==='rejected') as PromiseRejectedResult;
  assert.equal(failure.reason?.code,'ER_DUP_ENTRY');
  await assert.rejects(origin(other,'CREATE'),(e:any)=>e?.code==='ER_DUP_ENTRY');
  await origin(actor,'UPDATE');await origin(actor,'UPDATE');
  const insert=(k:string,quote:string|null)=>runtime!.execute(
   'INSERT INTO sales_quote_create_requests(actor_id,request_key,request_hash,quote_id) VALUES (?,?,?,?)',[actor,k,hash,quote]);
  const bind=(k:string,quote:string|null)=>runtime!.execute(
   'UPDATE sales_quote_create_requests SET quote_id=? WHERE actor_id=? AND request_key=?',[quote,actor,k]);
  const denied=(e:any)=>e?.code==='ER_SIGNAL_EXCEPTION'&&e?.sqlState==='45000';
  await assert.rejects(insert(randomUUID(),q1),denied);
  await insert(key,null);
  await assert.rejects(bind(key,foreign),denied);
  await assert.rejects(runtime.execute('UPDATE sales_quote_create_requests SET request_hash=?,quote_id=? WHERE actor_id=? AND request_key=?',
   ['b'.repeat(64),q1,actor,key]),denied);
  // Two identical-snapshot quotes compete for the same unbound request.
  const race=await Promise.allSettled([bind(key,q1),bind(key,q2)]);
  assert.equal(race.filter(x=>x.status==='fulfilled').length,1);
  assert.equal((race.find(x=>x.status==='rejected') as PromiseRejectedResult).reason?.code,'ER_SIGNAL_EXCEPTION');
  const [rows]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,key]);
  const bound=rows[0].quote_id;assert.ok([q1,q2].includes(bound));
  await assert.rejects(bind(key,bound===q1?q2:q1),denied);
  await assert.rejects(bind(key,null),denied);
  const second=randomUUID();await insert(second,null);
  await assert.rejects(bind(second,bound),(e:any)=>e?.code==='ER_DUP_ENTRY');
  await bind(second,bound===q1?q2:q1);
 }finally{
  if(runtime)await runtime.end();
  if(created)await admin.query('DROP USER '+account);
  await admin.end();
 }
});

test('1GI isolated session-checked binding candidate denies direct UPDATE, wrong session and replay',async()=>{
 gfMigrationTarget(process.env);
 const cfg=getDatabaseConfig(),admin=mysql.createPool({...cfg,connectionLimit:3});
 const user='ci_gi_'+randomBytes(7).toString('hex'),account="'"+user+"'@'%'",password=randomBytes(32).toString('base64url');
 const actor=randomUUID(),other=randomUUID(),customer=randomUUID(),quote=randomUUID(),foreign=randomUUID(),key=randomUUID();
 const session=hashToken(randomBytes(32).toString('base64url')),
  otherSession=hashToken(randomBytes(32).toString('base64url')),
  expired=hashToken(randomBytes(32).toString('base64url')),
  noMfa=hashToken(randomBytes(32).toString('base64url'));
 const hash='c'.repeat(64);
 let created=false,routine=false,runtime:mysql.Pool|undefined;
 try{
  await checkInstalledGfIntegrity(admin);
  const [existing]=await admin.query<mysql.RowDataPacket[]>(
   "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME='aaditech_gi_bind_quote_candidate'");
  assert.equal(existing.length,0);
  await admin.query(readFileSync('database/authority/phase1gi_session_quote_bind_candidate.sql','utf8'));routine=true;
  for(const id of [actor,other])await admin.execute(
   "INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-INVALID-HASH','OWNER')",
   [id,'gi-'+id+'@example.invalid','GI synthetic owner']);
  for(const [token,id,expiry,mfa] of [[session,actor,1,true],[otherSession,other,1,true],[expired,actor,-1,true],[noMfa,actor,1,false]] as const)
   await admin.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at,mfa_verified_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? HOUR),'+(mfa?'UTC_TIMESTAMP(3)':'NULL')+')',
    [token,id,randomBytes(32).toString('base64url'),expiry]);
  await admin.execute("INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,'GI test','CI','gi@example.invalid','0000000000','Mumbai','Maharashtra')",[customer]);
  for(const [id,owner] of [[quote,actor],[foreign,other]])await admin.execute(
   'INSERT INTO sales_quote_drafts(id,customer_id,created_by,subtotal,tax_estimate,total_estimate) VALUES (?,?,?,100,18,118)',[id,customer,owner]);
  await admin.query('CREATE USER '+account+' IDENTIFIED BY ?',[password]);created=true;
  await admin.query('GRANT SELECT, INSERT ON aaditech_ci.sales_quote_create_requests TO '+account);
  await admin.query('GRANT EXECUTE ON PROCEDURE aaditech_ci.aaditech_gi_bind_quote_candidate TO '+account);
  runtime=mysql.createPool({...cfg,user,password,connectionLimit:2});
  const [grants]=await runtime.query<mysql.RowDataPacket[]>('SHOW GRANTS FOR CURRENT_USER()');
  const envelope=assessRuntimeGrantEnvelope(grants.map(row=>String(Object.values(row)[0])),'aaditech_ci');
  assert.equal(envelope.allowed,false,'experimental procedure must remain outside the staging grant envelope');
  await runtime.execute('INSERT INTO sales_quote_create_requests(actor_id,request_key,request_hash) VALUES (?,?,?)',[actor,key,hash]);
  const denied=(e:any)=>e?.code==='ER_SIGNAL_EXCEPTION'&&e?.sqlState==='45000';
  const sqlDenied=(e:any)=>['ER_TABLEACCESS_DENIED_ERROR','ER_COLUMNACCESS_DENIED_ERROR','ER_DBACCESS_DENIED_ERROR'].includes(e?.code);
  await assert.rejects(runtime.query('SELECT token_hash FROM auth_sessions LIMIT 0'),sqlDenied);
  await assert.rejects(runtime.query('UPDATE sales_quote_create_requests SET quote_id=? WHERE actor_id=? AND request_key=?',[quote,actor,key]),sqlDenied);
  const call=(conn:Pick<mysql.PoolConnection,'query'>,token:string,target=quote,digest=hash)=>
   conn.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,token,key,digest,target]);
  const conn=await runtime.getConnection();
  try{
   for(const token of ['0'.repeat(64),otherSession,expired,noMfa]){
    await conn.beginTransaction();
    try{await assert.rejects(call(conn,token),denied);}finally{await conn.rollback();}
   }
   await conn.beginTransaction();
   try{await assert.rejects(call(conn,session,quote,'d'.repeat(64)),denied);}finally{await conn.rollback();}
   await conn.beginTransaction();
   try{await assert.rejects(call(conn,session,foreign),denied);}finally{await conn.rollback();}
   // A rollback must also roll back the successful procedure mutation.
   await conn.beginTransaction();
   try{await call(conn,session);}finally{await conn.rollback();}
   const [before]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,key]);
   assert.equal(before[0].quote_id,null);
   await conn.beginTransaction();
   try{await call(conn,session);await conn.commit();}catch(e){await conn.rollback();throw e;}
   await conn.beginTransaction();
   try{await assert.rejects(call(conn,session),denied);}finally{await conn.rollback();}
   const [after]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,key]);
   assert.equal(after[0].quote_id,quote);
   // Fresh unbound request proves revoked session cannot authorize initial binding.
   const nextKey=randomUUID();
   await runtime.execute('INSERT INTO sales_quote_create_requests(actor_id,request_key,request_hash) VALUES (?,?,?)',[actor,nextKey,hash]);
   await admin.execute('DELETE FROM auth_sessions WHERE token_hash=?',[session]);
   await conn.beginTransaction();
   try{await assert.rejects(conn.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,session,nextKey,hash,quote]),denied);}
   finally{await conn.rollback();}
   const [unbound]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,nextKey]);
   assert.equal(unbound[0].quote_id,null);
  }finally{conn.release();}
 }finally{
  if(runtime)await runtime.end();
  if(created)await admin.query('DROP USER '+account);
  if(routine)await admin.query('DROP PROCEDURE aaditech_gi_bind_quote_candidate');
  await admin.end();
 }
});
