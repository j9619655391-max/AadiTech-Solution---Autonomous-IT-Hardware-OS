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
 const actor=randomUUID(),other=randomUUID(),customer=randomUUID(),quote=randomUUID(),foreign=randomUUID(),freshQuote=randomUUID(),key=randomUUID();
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
  for(const [id,owner] of [[quote,actor],[foreign,other],[freshQuote,actor]])await admin.execute(
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
  const authorityDenied=(e:any)=>denied(e)&&e?.sqlMessage==='GI_BIND_AUTHORITY_DENIED';
  const sqlDenied=(e:any)=>['ER_TABLEACCESS_DENIED_ERROR','ER_COLUMNACCESS_DENIED_ERROR','ER_DBACCESS_DENIED_ERROR'].includes(e?.code);
  await assert.rejects(runtime.query('SELECT token_hash FROM auth_sessions LIMIT 0'),sqlDenied);
  await assert.rejects(runtime.query('UPDATE sales_quote_create_requests SET quote_id=? WHERE actor_id=? AND request_key=?',[quote,actor,key]),sqlDenied);
  const call=(conn:Pick<mysql.PoolConnection,'query'>,token:string,target=quote,digest=hash)=>
   conn.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,token,key,digest,target]);
  const conn=await runtime.getConnection();
  try{
   for(const token of ['0'.repeat(64),otherSession,expired,noMfa]){
    await conn.beginTransaction();
    try{await assert.rejects(call(conn,token),authorityDenied);}finally{await conn.rollback();}
   }
   await conn.beginTransaction();
   try{await assert.rejects(call(conn,session,quote,'d'.repeat(64)),authorityDenied);}finally{await conn.rollback();}
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
   try{await assert.rejects(conn.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,session,nextKey,hash,freshQuote]),authorityDenied);}
   finally{await conn.rollback();}
   const [unbound]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,nextKey]);
   assert.equal(unbound[0].quote_id,null);
   // Fresh valid session and target still cannot bind after OWNER disable.
   const live=hashToken(randomBytes(32).toString('base64url'));
   await admin.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at,mfa_verified_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR),UTC_TIMESTAMP(3))',
    [live,actor,randomBytes(32).toString('base64url')]);
   await admin.execute("UPDATE auth_users SET status='DISABLED' WHERE id=?",[actor]);
   await conn.beginTransaction();
   try{await assert.rejects(conn.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,live,nextKey,hash,freshQuote]),authorityDenied);}
   finally{await conn.rollback();}
   const [stillUnbound]=await runtime.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,nextKey]);
   assert.equal(stillUnbound[0].quote_id,null);
  }finally{conn.release();}
 }finally{
  if(runtime)await runtime.end();
  if(created)await admin.query('DROP USER '+account);
  if(routine)await admin.query('DROP PROCEDURE aaditech_gi_bind_quote_candidate');
  await admin.end();
 }
});

test('1GJ separate issuer exact-intent candidate rejects substitution and atomically consumes once',async()=>{
 gfMigrationTarget(process.env);
 const cfg=getDatabaseConfig(),admin=mysql.createPool({...cfg,connectionLimit:3});
 const suffix=randomBytes(7).toString('hex'),rt='ci_gj_rt_'+suffix,iss='ci_gj_iss_'+suffix;
 const rtAccount="'"+rt+"'@'%'",issAccount="'"+iss+"'@'%'";
 const rtPassword=randomBytes(32).toString('base64url'),issPassword=randomBytes(32).toString('base64url');
 const actor=randomUUID(),customer=randomUUID(),quote=randomUUID(),alternate=randomUUID(),key=randomUUID();
 const session=hashToken(randomBytes(32).toString('base64url')),intent=hashToken(randomBytes(32).toString('base64url')),hash='e'.repeat(64);
 let runtime:mysql.Pool|undefined,issuer:mysql.Pool|undefined;
 let rtCreated=false,issCreated=false,giCreated=false,gjCreated=false,tableCreated=false;
 try{
  await checkInstalledGfIntegrity(admin);
  const [old]=await admin.query<mysql.RowDataPacket[]>(
   "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME IN ('aaditech_gi_bind_quote_candidate','aaditech_gj_bind_intent_candidate')");
  assert.equal(old.length,0);
  const [tables]=await admin.query<mysql.RowDataPacket[]>(
   "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='auth_gj_quote_intents_candidate'");
  assert.equal(tables.length,0);
  await admin.query(readFileSync('database/authority/phase1gi_session_quote_bind_candidate.sql','utf8'));giCreated=true;
  const statements=readFileSync('database/authority/phase1gj_quote_intent_candidate.sql','utf8').split(/^-- statement-break$/m);
  assert.equal(statements.length,2);
  await admin.query(statements[0]);tableCreated=true;
  await admin.query(statements[1]);gjCreated=true;
  await admin.execute("INSERT INTO auth_users(id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-INVALID-HASH','OWNER')",[actor,'gj-'+actor+'@example.invalid','GJ synthetic owner']);
  await admin.execute('INSERT INTO auth_sessions(token_hash,user_id,csrf_token,expires_at,mfa_verified_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 HOUR),UTC_TIMESTAMP(3))',[session,actor,randomBytes(32).toString('base64url')]);
  await admin.execute("INSERT INTO crm_customers(id,name,contactPerson,email,phone,city,state) VALUES (?,'GJ test','CI','gj@example.invalid','0000000000','Mumbai','Maharashtra')",[customer]);
  for(const id of [quote,alternate])await admin.execute('INSERT INTO sales_quote_drafts(id,customer_id,created_by,subtotal,tax_estimate,total_estimate) VALUES (?,?,?,100,18,118)',[id,customer,actor]);
  await admin.query('CREATE USER '+rtAccount+' IDENTIFIED BY ?',[rtPassword]);rtCreated=true;
  await admin.query('CREATE USER '+issAccount+' IDENTIFIED BY ?',[issPassword]);issCreated=true;
  await admin.query('GRANT SELECT, INSERT ON aaditech_ci.sales_quote_create_requests TO '+rtAccount);
  await admin.query('GRANT EXECUTE ON PROCEDURE aaditech_ci.aaditech_gj_bind_intent_candidate TO '+rtAccount);
  await admin.query('GRANT INSERT ON aaditech_ci.auth_gj_quote_intents_candidate TO '+issAccount);
  runtime=mysql.createPool({...cfg,user:rt,password:rtPassword,connectionLimit:3});
  issuer=mysql.createPool({...cfg,user:iss,password:issPassword,connectionLimit:1});
  const sqlDenied=(e:any)=>['ER_TABLEACCESS_DENIED_ERROR','ER_COLUMNACCESS_DENIED_ERROR','ER_DBACCESS_DENIED_ERROR','ER_PROCACCESS_DENIED_ERROR'].includes(e?.code);
  const intentDenied=(e:any)=>e?.code==='ER_SIGNAL_EXCEPTION'&&e?.sqlState==='45000'&&e?.sqlMessage==='GJ_INTENT_DENIED';
  const issueSql='INSERT INTO auth_gj_quote_intents_candidate(intent_hash,actor_id,session_hash,request_key,request_hash,quote_id,expires_at) VALUES (?,?,?,?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL ? MINUTE))';
  await assert.rejects(runtime.execute(issueSql,[intent,actor,session,key,hash,quote,2]),sqlDenied);
  await assert.rejects(runtime.query('SELECT intent_hash FROM auth_gj_quote_intents_candidate LIMIT 0'),sqlDenied);
  await assert.rejects(runtime.query('UPDATE auth_gj_quote_intents_candidate SET consumed_at=NULL WHERE 1=0'),sqlDenied);
  await assert.rejects(issuer.query('UPDATE sales_quote_create_requests SET quote_id=NULL WHERE 1=0'),sqlDenied);
  await assert.rejects(issuer.query('UPDATE auth_gj_quote_intents_candidate SET consumed_at=NULL WHERE 1=0'),sqlDenied);
  await assert.rejects(runtime.query('CALL aaditech_gi_bind_quote_candidate(?,?,?,?,?)',[actor,session,key,hash,quote]),sqlDenied);
  await runtime.execute('INSERT INTO sales_quote_create_requests(actor_id,request_key,request_hash) VALUES (?,?,?)',[actor,key,hash]);
  await issuer.execute(issueSql,[intent,actor,session,key,hash,quote,2]);
  const expired=hashToken(randomUUID()),overlong=hashToken(randomUUID());
  await issuer.execute(issueSql,[expired,actor,session,key,hash,quote,-1]);
  await issuer.execute(issueSql,[overlong,actor,session,key,hash,quote,10]);
  const call=(c:Pick<mysql.PoolConnection,'query'>,values:string[]= [actor,session,key,hash,quote,intent])=>c.query('CALL aaditech_gj_bind_intent_candidate(?,?,?,?,?,?)',values);
  const conn=await runtime.getConnection();
  const observe=async()=>{
   const [rows]=await admin.query<mysql.RowDataPacket[]>('SELECT consumed_at FROM auth_gj_quote_intents_candidate WHERE intent_hash=?',[intent]);
   const [requests]=await admin.query<mysql.RowDataPacket[]>('SELECT quote_id FROM sales_quote_create_requests WHERE actor_id=? AND request_key=?',[actor,key]);
   return {consumed:rows[0].consumed_at,bound:requests[0].quote_id};
  };
  try{
   for(const values of [[actor,session,key,hash,alternate,intent],[actor,session,key,'f'.repeat(64),quote,intent],
    [actor,session,randomUUID(),hash,quote,intent],[actor,'0'.repeat(64),key,hash,quote,intent],
    [randomUUID(),session,key,hash,quote,intent],[actor,session,key,hash,quote,expired],
    [actor,session,key,hash,quote,overlong],[actor,session,key,hash,quote,'0'.repeat(64)]]){
    await conn.beginTransaction();
    try{await assert.rejects(call(conn,values),intentDenied);await conn.commit();}catch(e){await conn.rollback();throw e;}
    assert.deepEqual(await observe(),{consumed:null,bound:null});
   }
   await conn.beginTransaction();
   try{await call(conn);}finally{await conn.rollback();}
   assert.deepEqual(await observe(),{consumed:null,bound:null});
   // Separate connections race for one issuer intent; only one commit wins.
   const race=async()=>{
    const c=await runtime!.getConnection();
    try{await c.beginTransaction();await call(c);await c.commit();}
    catch(e){await c.rollback();throw e;}finally{c.release();}
   };
   const outcomes=await Promise.allSettled([race(),race()]);
   assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
   assert.ok(intentDenied((outcomes.find(x=>x.status==='rejected') as PromiseRejectedResult).reason));
   const after=await observe();assert.equal(after.bound,quote);assert.ok(after.consumed);
  }finally{conn.release();}
 }finally{
  if(runtime)await runtime.end();if(issuer)await issuer.end();
  if(rtCreated)await admin.query('DROP USER '+rtAccount);
  if(issCreated)await admin.query('DROP USER '+issAccount);
  if(gjCreated)await admin.query('DROP PROCEDURE aaditech_gj_bind_intent_candidate');
  if(giCreated)await admin.query('DROP PROCEDURE aaditech_gi_bind_quote_candidate');
  if(tableCreated)await admin.query('DROP TABLE auth_gj_quote_intents_candidate');
  await admin.end();
 }
});
