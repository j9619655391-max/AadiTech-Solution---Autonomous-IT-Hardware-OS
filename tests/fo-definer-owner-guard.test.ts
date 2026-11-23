import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {CRMOwnerInactiveError,lockActiveCrmOwner,ownerGuardMode} from '../server/crm/repository';
import {assessRuntimeGrantEnvelope,verifiedRuntimeDefinerOwnerGuard,OWNER_GUARD_ROUTINE}
 from '../scripts/phase1fb-runtime-db-privileges';

const schema='aaditech_staging_fo';
const acct="'runtime'@'%'";
const usage='GRANT USAGE ON *.* TO '+acct;
const data='GRANT SELECT, INSERT, UPDATE ON '+schema+'.crm_customers TO '+acct;
const routine='GRANT EXECUTE ON PROCEDURE '+schema+'.'+OWNER_GUARD_ROUTINE+' TO '+acct;
const valid=[{ROUTINE_NAME:OWNER_GUARD_ROUTINE,ROUTINE_SCHEMA:schema,ROUTINE_TYPE:'PROCEDURE',SECURITY_TYPE:'DEFINER'}];

test('1FO disallows raw runtime OWNER SELECT in staging/production by configuration',()=>{
 assert.equal(ownerGuardMode({NODE_ENV:'test'}),'DIRECT_DEVELOPMENT');
 assert.equal(ownerGuardMode({NODE_ENV:'development',AUTH_OWNER_GUARD_MODE:'direct'}),'DIRECT_DEVELOPMENT');
 assert.equal(ownerGuardMode({NODE_ENV:'test',AUTH_OWNER_GUARD_MODE:'procedure'}),'DEFINER_PROCEDURE');
 assert.equal(ownerGuardMode({NODE_ENV:'staging',AUTH_OWNER_GUARD_MODE:'procedure'}),'DEFINER_PROCEDURE');
 assert.equal(ownerGuardMode({NODE_ENV:'production',AUTH_OWNER_GUARD_MODE:'procedure'}),'DEFINER_PROCEDURE');
 for(const mode of ['staging','production']){
  for(const setting of [undefined,'direct','','unknown','PROCEDURE']){
   assert.equal(ownerGuardMode({NODE_ENV:mode,AUTH_OWNER_GUARD_MODE:setting}),'HOLD');
  }
 }
 assert.equal(ownerGuardMode({NODE_ENV:'undefined'}),'HOLD');
});

test('1FO grants only a specific routine EXECUTE; never general functions, schema or auth tables',()=>{
 const ok=assessRuntimeGrantEnvelope([usage,data,routine],schema);
 assert.equal(ok.allowed,true,ok.reasons.join(','));
 assert.equal(ok.dataGrantCount,1);
 assert.equal(ok.routineGrantCount,1);
 assert.deepEqual(ok.dataGrantTables,['crm_customers']);
 for(const bad of [
  'GRANT EXECUTE ON '+schema+'.* TO '+acct,
  'GRANT EXECUTE ON PROCEDURE '+schema+'.other_guard TO '+acct,
  'GRANT EXECUTE ON FUNCTION '+schema+'.'+OWNER_GUARD_ROUTINE+' TO '+acct,
  'GRANT EXECUTE ON PROCEDURE other_schema.'+OWNER_GUARD_ROUTINE+' TO '+acct,
  'GRANT EXECUTE, ALTER ROUTINE ON PROCEDURE '+schema+'.'+OWNER_GUARD_ROUTINE+' TO '+acct,
  'GRANT EXECUTE ON PROCEDURE '+schema+'.* TO '+acct,
  'GRANT SELECT ON '+schema+'.auth_users TO '+acct,
  'GRANT UPDATE ON '+schema+'.auth_users TO '+acct,
  'GRANT SELECT ON '+schema+'.auth_totp_credentials TO '+acct,
  'GRANT ALL PRIVILEGES ON '+schema+'.* TO '+acct
 ]){
  const result=assessRuntimeGrantEnvelope([usage,data,bad],schema);
  assert.equal(result.allowed,false,bad);
 }
 assert.equal(assessRuntimeGrantEnvelope([usage,data,routine,routine],schema).allowed,false);
 const quoted='GRANT EXECUTE ON PROCEDURE '+String.fromCharCode(96)+schema+
  String.fromCharCode(96)+'.'+String.fromCharCode(96)+OWNER_GUARD_ROUTINE+
  String.fromCharCode(96)+' TO '+acct;
 assert.equal(assessRuntimeGrantEnvelope([usage,data,quoted],schema).routineGrantCount,1);
});

test('1FO same-session routine metadata requires one exact schema DEFINER procedure',()=>{
 assert.equal(verifiedRuntimeDefinerOwnerGuard(valid,schema),true);
 for(const records of [
  [],[valid[0],valid[0]],
  [{...valid[0],SECURITY_TYPE:'INVOKER'}],
  [{...valid[0],ROUTINE_TYPE:'FUNCTION'}],
  [{...valid[0],ROUTINE_SCHEMA:'other_schema'}],
  [{...valid[0],ROUTINE_NAME:'other_guard'}],
  [{...valid[0],ROUTINE_NAME:OWNER_GUARD_ROUTINE.toUpperCase()}],
  [null],[{...valid[0],ROUTINE_TYPE:null}]
 ])assert.equal(verifiedRuntimeDefinerOwnerGuard(records,schema),false);
});

test('1FO procedure-mode OWNER lock issues exactly one CALL; rejected signal fails closed',async()=>{
 const original=process.env.AUTH_OWNER_GUARD_MODE;
 try{
  process.env.AUTH_OWNER_GUARD_MODE='procedure';
  const calls:{sql:string;args:unknown[]}[]=[];
  const session={query:async(sql:string,args:unknown[])=>{calls.push({sql,args});return [[],[]];}};
  await lockActiveCrmOwner(session as any,'actor');
  assert.deepEqual(calls,[{sql:'CALL aaditech_guard_active_owner(?)',args:['actor']}]);
  const rejected=Object.assign(new Error('not allowed'),{
   code:'ER_SIGNAL_EXCEPTION',sqlState:'45000',sqlMessage:'AUTH_OWNER_INACTIVE'});
  await assert.rejects(lockActiveCrmOwner({query:async()=>{throw rejected;}} as any,'actor'),
   (e:unknown)=>e instanceof CRMOwnerInactiveError);
  const missing=Object.assign(new Error('missing'),{code:'ER_SP_DOES_NOT_EXIST'});
  await assert.rejects(lockActiveCrmOwner({query:async()=>{throw missing;}} as any,'actor'),
   (e:unknown)=>e===missing,'missing routine must never trigger a direct SELECT fallback');
  const timeout=Object.assign(new Error('timeout'),{code:'ER_LOCK_WAIT_TIMEOUT'});
  await assert.rejects(lockActiveCrmOwner({query:async()=>{throw timeout;}} as any,'actor'),
   (e:unknown)=>e===timeout,'concurrent transaction locks may not be bypassed');
 }finally{
  if(original===undefined)delete process.env.AUTH_OWNER_GUARD_MODE;
  else process.env.AUTH_OWNER_GUARD_MODE=original;
 }
});

test('1FO reviewed routine body cannot disclose raw auth, write role or enable dispatch',()=>{
 const sql=readFileSync('database/authority/phase1fo_active_owner_guard.sql','utf8');
 assert.match(sql,/SQL SECURITY DEFINER/);
 assert.match(sql,/WHERE id=p_actor FOR UPDATE/);
 assert.match(sql,/SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='AUTH_OWNER_INACTIVE'/);
 assert.doesNotMatch(sql,/GRANT|UPDATE auth_users|DELETE FROM|INSERT INTO|SELECT \*|DROP TABLE/i);
 const staging=readFileSync('scripts/staging-preflight.ts','utf8');
 assert.match(staging,/requireOwnerGuard:true/);
 assert.match(staging,/verifiedRuntimeDefinerOwnerGuard/);
 const crm=readFileSync('server/crm/repository.ts','utf8');
 const quote=readFileSync('server/quotes/router.ts','utf8');
 const ticket=readFileSync('server/serviceDesk/router.ts','utf8');
 assert.match(crm,/CALL aaditech_guard_active_owner\(\?\)/);
 assert.match(quote,/await lockActiveCrmOwner\(/);
 assert.match(ticket,/await lockActiveCrmOwner\(/);
});
