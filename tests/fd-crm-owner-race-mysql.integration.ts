import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig,getPool} from '../server/db';
import {CRMOwnerInactiveError,MySQLCRMRepository} from '../server/crm/repository';
import {validate} from '../server/crm/validation';

// Disposable integration only: never acquire locks or change roles on staging/production.
if(process.env.CRM_TEST_DB!=='1'||process.env.NODE_ENV!=='test'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FD CRM race fixture refuses non-disposable database');
const db=getPool();
if(!db)throw Error('1FD disposable MySQL pool unavailable');
after(async()=>{await db.end();});
async function owner(){
 const id=randomUUID();
 await db.execute(
  "INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-NOT-VALID-PASSWORD','OWNER')",
  [id,'fd-owner-'+id+'@example.invalid','FD test owner']);
 return id;
}
function customer(name:string){
 return validate('customers',{name,contactPerson:'CI-only customer representative',
  email:'ci-fd@example.invalid',phone:'0000000000',city:'Mumbai',state:'Maharashtra'});
}
function inactive(error:unknown){
 return error instanceof CRMOwnerInactiveError;
}

test('1FD: write repository rejects disabled/demoted OWNER inside all three transactions, without audit or row changes',async()=>{
 const actor=await owner(),repo=new MySQLCRMRepository(db);
 const name='FD fixture '+randomUUID();
 const created=await repo.create('customers',customer(name),actor) as {id:string;version:number};
 assert.equal(created.version,1);
 const [initial]=await db.query<any[]>(
  "SELECT COUNT(*) AS n FROM crm_audit_events WHERE entity_type='customers' AND entity_id=?",[created.id]);
 assert.equal(Number(initial[0].n),1);
 for(const transition of ["status='DISABLED'","status='ACTIVE',role='REVIEWER'"]){
  await db.execute("UPDATE auth_users SET role='OWNER',status='ACTIVE' WHERE id=?",[actor]);
  await db.execute('UPDATE auth_users SET '+transition+' WHERE id=?',[actor]);
  await assert.rejects(repo.create('customers',customer('FD rejected '+randomUUID()),actor),inactive);
  await assert.rejects(repo.update('customers',created.id,1,{city:'Pune'},actor),inactive);
  await assert.rejects(repo.remove('customers',created.id,1,actor),inactive);
  const [rows]=await db.query<any[]>(
   'SELECT version,city,deleted_at FROM crm_customers WHERE id=?',[created.id]);
  assert.equal(rows[0].version,1);
  assert.equal(rows[0].city,'Mumbai');
  assert.equal(rows[0].deleted_at,null);
  const [audit]=await db.query<any[]>(
   "SELECT COUNT(*) AS n FROM crm_audit_events WHERE entity_type='customers' AND entity_id=?",[created.id]);
  assert.equal(Number(audit[0].n),1,'no UPDATE/DELETE audit or mutation after revocation');
 }
 await db.execute("UPDATE auth_users SET role='OWNER',status='ACTIVE' WHERE id=?",[actor]);
 const changed=await repo.update('customers',created.id,1,{city:'Pune'},actor) as {version:number};
 assert.equal(changed.version,2);
 assert.equal(await repo.remove('customers',created.id,2,actor),'deleted');
});

test('1FD: a concurrent disable holds auth_users lock and CRM CREATE cannot leapfrog it',async()=>{
 const actor=await owner();
 const blocker=await db.getConnection();
 const candidate=mysql.createPool({...getDatabaseConfig(),connectionLimit:1});
 const repo=new MySQLCRMRepository(candidate);
 const label='FD blocked '+randomUUID();
 let open=false;
 try{
  const worker=await candidate.getConnection();
  await worker.query('SET SESSION innodb_lock_wait_timeout=1');
  worker.release();
  await blocker.beginTransaction();open=true;
  const [changed]=await blocker.execute<any>(
   "UPDATE auth_users SET status='DISABLED' WHERE id=? AND role='OWNER'",[actor]);
  assert.equal(changed.affectedRows,1);
  await assert.rejects(repo.create('customers',customer(label),actor),
   (e:unknown)=>Boolean(e&&typeof e==='object'&&'code' in e&&e.code==='ER_LOCK_WAIT_TIMEOUT'),
   'write must wait on auth_users row lock instead of inserting under stale role');
  const [blocked]=await blocker.query<any[]>(
   "SELECT COUNT(*) AS n FROM crm_customers WHERE name=?",[label]);
  assert.equal(Number(blocked[0].n),0);
  await blocker.commit();open=false;
  await assert.rejects(repo.create('customers',customer(label),actor),inactive);
  const [remaining]=await db.query<any[]>(
   'SELECT COUNT(*) AS n FROM crm_customers WHERE name=?',[label]);
  assert.equal(Number(remaining[0].n),0);
 }finally{
  if(open)await blocker.rollback().catch(()=>{});
  blocker.release();
  await candidate.end();
 }
});
