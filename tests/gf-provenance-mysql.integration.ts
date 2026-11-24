import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
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
