import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {getPool} from '../server/db';

// This intentionally exercises two independent live InnoDB connections.
// Never point this test at staging, production or a non-disposable database.
if(process.env.CRM_TEST_DB!=='1'||process.env.DB_NAME!=='aaditech_ci'||
   process.env.NODE_ENV!=='test')
 throw Error('1FA concurrency tests require isolated aaditech_ci, CRM_TEST_DB=1 and NODE_ENV=test');
const db=getPool();
if(!db)throw Error('1FA disposable MySQL unavailable');
after(async()=>{await db.end();});
const lockTimeout=(error:unknown)=>Boolean(error&&typeof error==='object'&&
 'code' in error&&error.code==='ER_LOCK_WAIT_TIMEOUT');

async function seededReviewer(){
 const owner=randomUUID(),reviewer=randomUUID();
 await db.execute("INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-NOT-AN-AUTHENTICATOR','OWNER')",
  [owner,'fa-owner-'+owner+'@example.invalid','CI only transaction owner']);
 await db.execute("INSERT INTO auth_users (id,email,full_name,password_hash,role) VALUES (?,?,?,'CI-NOT-AN-AUTHENTICATOR','REVIEWER')",
  [reviewer,'fa-reviewer-'+reviewer+'@example.invalid','CI only transaction reviewer']);
 return {owner,reviewer};
}
async function assertQuarantined(reviewer:string,expectedRole:'OWNER'|'REVIEWER'){
 const [users]=await db.query<any[]>('SELECT role,status FROM auth_users WHERE id=?',[reviewer]);
 assert.equal(users.length,1);
 assert.equal(users[0].role,expectedRole);
 assert.equal(users[0].status,'ACTIVE');
 const [grants]=await db.query<any[]>(
  "SELECT COUNT(*) AS n FROM app_reviewer_scope_grants WHERE reviewer_user_id=? AND state='ACTIVE'",[reviewer]);
 assert.equal(Number(grants[0].n),0,'role change cannot leave an ACTIVE app-local grant');
 const [sessions]=await db.query<any[]>('SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?',[reviewer]);
 assert.equal(Number(sessions[0].n),0,'role change cannot leave a stale session');
}

test('1FA: concurrent direct-SQL demotion waits behind locked nomination, then revokes committed grant and session',async()=>{
 const {owner,reviewer}=await seededReviewer();
 const nominator=await db.getConnection(),demoter=await db.getConnection();
 let nominationOpen=false;
 try{
  await nominator.beginTransaction();nominationOpen=true;
  const [locked]=await nominator.query<any[]>(
   'SELECT role,status FROM auth_users WHERE id=? FOR UPDATE',[reviewer]);
  assert.equal(locked[0].role,'REVIEWER');
  await nominator.execute(
   "INSERT INTO app_reviewer_scope_grants (owner_user_id,reviewer_user_id,workflow_scope) VALUES (?,?,'QUOTES')",
   [owner,reviewer]);
  await nominator.execute(
   'INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))',
   [randomBytes(32).toString('hex'),reviewer,randomBytes(32).toString('base64url').slice(0,43)]);
  await demoter.query('SET SESSION innodb_lock_wait_timeout=1');
  await assert.rejects(
   demoter.execute("UPDATE auth_users SET role='OWNER' WHERE id=? AND role='REVIEWER'",[reviewer]),
   lockTimeout,'direct SQL role update must not leapfrog the reviewer row lock');
  await nominator.commit();nominationOpen=false;
  const [demoted]=await demoter.execute<any>(
   "UPDATE auth_users SET role='OWNER' WHERE id=? AND role='REVIEWER'",[reviewer]);
  assert.equal(Number(demoted.affectedRows),1);
  await assertQuarantined(reviewer,'OWNER');
 }finally{
  if(nominationOpen)await nominator.rollback().catch(()=>{});
  nominator.release();demoter.release();
 }
});
test('1FA: direct-SQL role change wins first; concurrent nomination cannot acquire stale reviewer row',async()=>{
 const {owner,reviewer}=await seededReviewer();
 const nominator=await db.getConnection(),demoter=await db.getConnection();
 let nomineeOpen=false,demoterOpen=false;
 try{
  await db.execute(
   "INSERT INTO app_reviewer_scope_grants (owner_user_id,reviewer_user_id,workflow_scope) VALUES (?,?,'QUOTES')",
   [owner,reviewer]);
  await db.execute(
   'INSERT INTO auth_sessions (token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 1 HOUR))',
   [randomBytes(32).toString('hex'),reviewer,randomBytes(32).toString('base64url').slice(0,43)]);
  await demoter.beginTransaction();demoterOpen=true;
  const [changed]=await demoter.execute<any>(
   "UPDATE auth_users SET role='OWNER' WHERE id=? AND role='REVIEWER'",[reviewer]);
  assert.equal(Number(changed.affectedRows),1);
  await nominator.query('SET SESSION innodb_lock_wait_timeout=1');
  await nominator.beginTransaction();nomineeOpen=true;
  await assert.rejects(
   nominator.query('SELECT role,status FROM auth_users WHERE id=? FOR UPDATE',[reviewer]),
   lockTimeout,'nominator must not observe and act on a stale REVIEWER row');
  await nominator.rollback();nomineeOpen=false;
  await demoter.commit();demoterOpen=false;
  const [current]=await nominator.query<any[]>(
   'SELECT role,status FROM auth_users WHERE id=? FOR UPDATE',[reviewer]);
  assert.equal(current[0].role,'OWNER','a fresh nomination must reject a demoted subject');
  await assertQuarantined(reviewer,'OWNER');
 }finally{
  if(nomineeOpen)await nominator.rollback().catch(()=>{});
  if(demoterOpen)await demoter.rollback().catch(()=>{});
  nominator.release();demoter.release();
 }
});
test('1FA nomination route retains acting-owner and subject row locks; no production authority',()=>{
 const route=readFileSync('server/security/reviewerScopeRouter.ts','utf8');
 assert.match(route,/SELECT id,role,status FROM auth_users WHERE id=\? FOR UPDATE/g);
 assert.match(route,/users\[0\]\.role!=='REVIEWER'/);
 assert.match(route,/users\[0\]\.status!=='ACTIVE'/);
 assert.match(route,/productionReleaseAuthorized:false,releaseDecision:'HOLD'/);
});
