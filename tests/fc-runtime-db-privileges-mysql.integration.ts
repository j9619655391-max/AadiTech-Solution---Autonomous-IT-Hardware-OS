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
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.\x60crm_customers\x60 TO '+literal);
  candidate=mysql.createPool({...getDatabaseConfig(),user,password,
   connectionLimit:1,waitForConnections:true});
  const allowed=await checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci');
  assert.equal(allowed.grantCount,2);
  assert.equal(allowed.dataGrantCount,1);
  // Phase 1FF: even schema-wide SELECT exposes confidential auth/CRM data.
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.* TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Wildcard schema reads must fail even when writes remain table-scoped');
  await admin.query('REVOKE SELECT ON \x60aaditech_ci\x60.* FROM '+literal);
  // Phase 1FH: table-specific SELECT is not an exemption for secret-bearing
  // identity/MFA tables; this uses actual SHOW GRANTS from disposable MySQL.
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.\x60auth_users\x60 TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Explicit auth_users SELECT must fail before separate auth-reader design');
  await admin.query('REVOKE SELECT ON \x60aaditech_ci\x60.\x60auth_users\x60 FROM '+literal);
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.\x60auth_totp_credentials\x60 TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Explicit TOTP material read must fail');
  await admin.query('REVOKE SELECT ON \x60aaditech_ci\x60.\x60auth_totp_credentials\x60 FROM '+literal);
  await admin.query('GRANT TRIGGER ON \x60aaditech_ci\x60.* TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Trigger DDL privilege must be observed and refused on actual MySQL');
  await admin.query('REVOKE TRIGGER ON \x60aaditech_ci\x60.* FROM '+literal);
  // A normal MySQL table-scoped grant could restore a reviewer nomination
  // after the auth_users quarantine trigger. Technical gate must reject it.
  await admin.query('GRANT UPDATE ON \x60aaditech_ci\x60.\x60app_reviewer_scope_grants\x60 TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Direct reviewer authority mutation must be refused even without DDL');
  await admin.query('REVOKE UPDATE ON \x60aaditech_ci\x60.\x60app_reviewer_scope_grants\x60 FROM '+literal);
  await admin.query('GRANT INSERT ON \x60aaditech_ci\x60.* TO '+literal);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FC runtime database grant envelope unverified/,
   'Schema-wide application data mutation must be refused');
  await admin.query('REVOKE INSERT ON \x60aaditech_ci\x60.* FROM '+literal);
  const recovered=await checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci');
  assert.equal(recovered.dataGrantCount,1);
 }finally{
  if(candidate)await candidate.end();
  if(userCreated)await admin.query('DROP USER '+literal);
 }
});

test('1FG real MySQL activated default role is denied on the observed runtime session',async()=>{
 const user='ci_fg_user_'+randomBytes(7).toString('hex');
 const role='ci_fg_role_'+randomBytes(7).toString('hex');
 const password=randomBytes(32).toString('base64url');
 const account="'"+user+"'@'%'",delegatedRole="'"+role+"'@'%'";
 let userCreated=false,roleCreated=false;
 let rolePool:mysql.Pool|undefined;
 try{
  await admin.query('CREATE USER '+account+' IDENTIFIED BY ?',[password]);
  userCreated=true;
  await admin.query('GRANT SELECT ON aaditech_ci.crm_customers TO '+account);
  await admin.query('CREATE ROLE '+delegatedRole);
  roleCreated=true;
  await admin.query('GRANT SELECT ON aaditech_ci.auth_users TO '+delegatedRole);
  await admin.query('GRANT '+delegatedRole+' TO '+account);
  await admin.query('SET DEFAULT ROLE '+delegatedRole+' TO '+account);
  // Fresh login activates the default role; prior test's pooled account
  // session cannot be reused to make this assertion meaningful.
  rolePool=mysql.createPool({...getDatabaseConfig(),user,password,
   connectionLimit:1,waitForConnections:true});
  const [identity]=await rolePool.query<any[]>('SELECT CURRENT_ROLE() AS active_roles');
  assert.equal(identity.length,1);
  assert.equal(typeof identity[0].active_roles,'string');
  assert.notEqual(identity[0].active_roles,'NONE','MySQL role must actually be active');
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(rolePool,'aaditech_ci'),
   /1FC runtime database identity\/schema mismatch/,
   'active default role must deny staging grant preflight');
 }finally{
  if(rolePool)await rolePool.end();
  if(userCreated)await admin.query('DROP USER '+account);
  if(roleCreated)await admin.query('DROP ROLE '+delegatedRole);
 }
});

// 1FJ SQL SECURITY DEFINER view: grants on the view can expose definer-readable
// auth rows even though raw auth_users grants are explicitly denied. This is
// disposable CI only; only metadata is inspected, never protected row values.
test('1FJ actual MySQL view GRANT is quarantined until revoked',async()=>{
 const user='ci_fj_user_'+randomBytes(7).toString('hex');
 const password=randomBytes(32).toString('base64url');
 const view='ci_fj_view_'+randomBytes(7).toString('hex');
 const account="'"+user+"'@'%'";
 const object='\x60aaditech_ci\x60.\x60'+view+'\x60';
 let userCreated=false,viewCreated=false;
 let candidate:mysql.Pool|undefined;
 try{
  await admin.query('CREATE SQL SECURITY DEFINER VIEW '+object+
   ' AS SELECT id FROM \x60aaditech_ci\x60.\x60auth_users\x60');
  viewCreated=true;
  await admin.query('CREATE USER '+account+' IDENTIFIED BY ?',[password]);
  userCreated=true;
  await admin.query('GRANT SELECT ON '+object+' TO '+account);
  candidate=mysql.createPool({...getDatabaseConfig(),user,password,
   connectionLimit:1,waitForConnections:true});
  await assert.rejects(checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci'),
   /1FJ runtime grant target base-table metadata unverified/,
   'A table-scoped SELECT on definer view must fail even without underlying auth grant');
  await admin.query('REVOKE SELECT ON '+object+' FROM '+account);
  await admin.query('GRANT SELECT ON \x60aaditech_ci\x60.\x60crm_customers\x60 TO '+account);
  const restored=await checkStagingRuntimeDbPrivilegeIntegrity(candidate,'aaditech_ci');
  assert.equal(restored.dataGrantCount,1);
 }finally{
  if(candidate)await candidate.end();
  if(userCreated)await admin.query('DROP USER '+account);
  if(viewCreated)await admin.query('DROP VIEW '+object);
 }
});

// 1FL actual temporary MySQL principals: a user-supplied distinct credential
// string alone is not a privileges guarantee. Observe independent server-side
// identities and protected-table SQL denial on isolated disposable aaditech_ci.
test('1FL actual temporary MySQL principals enforce auth/runtime read separation',async()=>{
 const suffix=randomBytes(7).toString('hex');
 const runtimeUser='ci_fl_runtime_'+suffix,authUser='ci_fl_auth_'+suffix;
 const runtimeAccount="'"+runtimeUser+"'@'%'",authAccount="'"+authUser+"'@'%'";
 const runtimePassword=randomBytes(32).toString('base64url'),
  authPassword=randomBytes(32).toString('base64url');
 let runtimeCreated=false,authCreated=false;
 let runtimePool:mysql.Pool|undefined,authPool:mysql.Pool|undefined;
 try{
  await admin.query('CREATE USER '+runtimeAccount+' IDENTIFIED BY ?',[runtimePassword]);
  runtimeCreated=true;
  await admin.query('CREATE USER '+authAccount+' IDENTIFIED BY ?',[authPassword]);
  authCreated=true;
  await admin.query('GRANT SELECT ON aaditech_ci.crm_customers TO '+runtimeAccount);
  await admin.query('GRANT SELECT ON aaditech_ci.auth_users TO '+authAccount);
  runtimePool=mysql.createPool({...getDatabaseConfig(),user:runtimeUser,password:runtimePassword,
   connectionLimit:1,waitForConnections:true});
  authPool=mysql.createPool({...getDatabaseConfig(),user:authUser,password:authPassword,
   connectionLimit:1,waitForConnections:true});
  const [runtimeWho]=await runtimePool.query<any[]>('SELECT CURRENT_USER() AS principal_name');
  const [authWho]=await authPool.query<any[]>('SELECT CURRENT_USER() AS principal_name');
  assert.equal(runtimeWho.length,1);
  assert.equal(authWho.length,1);
  assert.notEqual(runtimeWho[0].principal_name,authWho[0].principal_name);
  await runtimePool.query('SELECT id FROM crm_customers LIMIT 1');
  await authPool.query('SELECT id FROM auth_users LIMIT 1');
  await assert.rejects(
   runtimePool.query('SELECT id FROM auth_users LIMIT 1'),
   (err:any)=>err?.code==='ER_TABLEACCESS_DENIED_ERROR'||err?.code==='ER_DBACCESS_DENIED_ERROR');
  await assert.rejects(
   authPool.query('SELECT id FROM crm_customers LIMIT 1'),
   (err:any)=>err?.code==='ER_TABLEACCESS_DENIED_ERROR'||err?.code==='ER_DBACCESS_DENIED_ERROR');
 }finally{
  if(runtimePool)await runtimePool.end();
  if(authPool)await authPool.end();
  if(runtimeCreated)await admin.query('DROP USER '+runtimeAccount);
  if(authCreated)await admin.query('DROP USER '+authAccount);
 }
});
