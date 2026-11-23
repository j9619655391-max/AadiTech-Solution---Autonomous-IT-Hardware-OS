import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import mysql from 'mysql2/promise';
import {getDatabaseConfig,getPool} from '../server/db';
import {checkStagingRuntimeDbPrivilegeIntegrity} from '../scripts/staging-preflight';

// Provision/remove randomly named accounts only on isolated disposable CI DB.
// Never probe or modify real staging, production or third-party credentials.
if(process.env.NODE_ENV!=='test'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.DB_SSL!=='false')
 throw Error('1FC real privilege test requires disposable aaditech_ci test database without TLS');
const admin=getPool();
if(!admin)throw Error('1FC CI-only MySQL root pool unavailable');
after(async()=>{await admin.end();});
test('1FC actual MySQL grants: bounded SELECT passes, added TRIGGER privilege fails closed',async()=>{
 const user='ci_fc_'+randomBytes(8).toString('hex');
 const password=randomBytes(32).toString('base64url');
 const literal="'"+user+"'@'%'";
 let userCreated=false;
 let candidate:mysql.Pool|undefined;
 try{
  await admin.query('CREATE USER '+literal+' IDENTIFIED BY ?',[password]);
  userCreated=true;
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.* TO '+literal);
  candidate=mysql.createPool({...getDatabaseConfig(),user,password,
   connectionLimit:1,waitForConnections:true});
  const allowed=await checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci');
  assert.equal(allowed.grantCount,2);
  assert.equal(allowed.dataGrantCount,1);
  await admin.query('GRANT TRIGGER ON \x60aaditech_ci\x60.* TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Trigger DDL privilege must be observed and refused on actual MySQL');
  await admin.query('REVOKE TRIGGER ON \x60aaditech_ci\x60.* FROM '+literal);
  const recovered=await checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci');
  assert.equal(recovered.dataGrantCount,1);
 }finally{
  if(candidate)await candidate.end();
  if(userCreated)await admin.query('DROP USER '+literal);
 }
});
