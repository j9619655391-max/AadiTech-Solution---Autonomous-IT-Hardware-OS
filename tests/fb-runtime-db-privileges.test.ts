import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessRuntimeGrantEnvelope,runtimePrivilegePreflightTarget} from '../scripts/phase1fb-runtime-db-privileges';

const schema='aaditech_staging_safe';
const account="'runtime'@'%'";
const tick=String.fromCharCode(96);
const usage='GRANT USAGE ON *.* TO '+account;
const scoped='GRANT SELECT ON '+tick+schema+tick+'.'+tick+'crm_customers'+tick+' TO '+account;
const schemaWideRead='GRANT SELECT ON '+tick+schema+tick+'.* TO '+account;
const scopedWrite='GRANT SELECT, INSERT, UPDATE, DELETE ON '+tick+schema+tick+'.* TO '+account;
const ordinaryWrite='GRANT INSERT, UPDATE ON '+tick+schema+tick+'.'+tick+'crm_leads'+tick+' TO '+account;
const table='GRANT SELECT ON '+tick+schema+tick+'.'+tick+'auth_users'+tick+' TO '+account;

test('1FB rejects production, CI, unapproved staging, missing TLS and ambiguous target labels',()=>{
 const valid={RUNTIME_DB_PRIVILEGE_PREFLIGHT:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:schema,DB_SSL:'true',NODE_ENV:'staging'};
 assert.equal(runtimePrivilegePreflightTarget(valid),'staging');
 for(const env of [
  {},{...valid,RUNTIME_DB_PRIVILEGE_PREFLIGHT:'no'},
  {...valid,DB_NAME:'aaditech_prod'},
  {...valid,DB_NAME:'aaditech_staging_safe;DROP'},
  {...valid,DB_SSL:'false'},{...valid,NODE_ENV:'production'},
  {...valid,NODE_ENV:'test'},{...valid,CRM_TEST_DB:'1'},
  {...valid,STAGING_DISPOSABLE_CONFIRMED:'NO'}
 ])assert.throws(()=>runtimePrivilegePreflightTarget(env),/refused/);
});
test('1FF accepts global USAGE, explicit table read and non-authority table-scoped writes',()=>{
 for(const grants of [[usage,scoped],[usage,table],[scoped],[usage,scoped,table],
  [usage,scoped,ordinaryWrite]]){
  const a=assessRuntimeGrantEnvelope(grants,schema);
  assert.equal(a.allowed,true,JSON.stringify(a.reasons));
  assert.ok(a.dataGrantCount>=1);
  assert.equal(a.grantCount,grants.length);
 }
});
test('1FF schema-wide read cannot expose unreviewed auth, MFA, CRM and evidence tables',()=>{
 const wide=assessRuntimeGrantEnvelope([usage,schemaWideRead],schema);
 assert.equal(wide.allowed,false);
 assert.ok(wide.reasons.includes('Runtime schema-wide data access forbidden'));
 const focused=assessRuntimeGrantEnvelope([usage,table,scoped,ordinaryWrite],schema);
 assert.equal(focused.allowed,true);
 assert.equal(focused.dataGrantCount,3);
});
test('1FB denies global SELECT, admin/DDL, roles, non-target scopes and unrecognized grant shapes',()=>{
 const bad=[
  schemaWideRead,
  'GRANT SELECT ON '+schema+'.* TO '+account,
  'GRANT SELECT, UPDATE ON '+schema+'.* TO '+account,
  scopedWrite,
  'GRANT UPDATE ON '+schema+'.auth_users TO '+account,
  'GRANT DELETE ON '+schema+'.auth_sessions TO '+account,
  'GRANT INSERT ON '+schema+'.app_reviewer_scope_grants TO '+account,
  'GRANT UPDATE ON '+schema+'.app_reviewer_scope_events TO '+account,
  'GRANT DELETE ON '+schema+'.auth_security_events TO '+account,
  'GRANT UPDATE ON '+schema+'.auth_totp_credentials TO '+account,
  'GRANT INSERT ON '+schema+'.auth_totp_recovery_codes TO '+account,
  'GRANT DELETE ON '+schema+'.auth_mfa_challenges TO '+account,
  'GRANT ALL PRIVILEGES ON *.* TO '+account,
  'GRANT SELECT ON *.* TO '+account,
  'GRANT CREATE ON '+schema+'.* TO '+account,
  'GRANT TRIGGER ON '+schema+'.* TO '+account,
  'GRANT ALTER, DELETE ON '+schema+'.* TO '+account,
  'GRANT FILE ON *.* TO '+account,
  'GRANT SELECT ON other_schema.* TO '+account,
  'GRANT SELECT ON '+schema+'.* TO '+account+' WITH GRANT OPTION',
  'GRANT '+tick+'admin_role'+tick+'@'+tick+'%'+tick+' TO '+account,
  'GRANT PROXY ON '+account+' TO '+account,
  'GRANT SELECT ON '+schema+'.* TO '+account+'\nGRANT UPDATE ON *.* TO '+account,
  'GRANT SELECT ON '+schema+'.*;DROP TABLE auth_users TO '+account,
  'GRANT SELECT (password_hash) ON '+schema+'.auth_users TO '+account,
  'GRANT SELECT ON '+schema+'.* TO '+account+' WITH ADMIN OPTION',
  ''
 ];
 for(const grant of bad){
  const observed=assessRuntimeGrantEnvelope([usage,scoped,grant],schema);
  assert.equal(observed.allowed,false,grant);
  assert.ok(observed.reasons.length>0);
  assert.equal(observed.reasons.some(reason=>reason.includes(account)),false,
   'failure receipt must not echo DB account or raw grant');
 }
});
test('1FB never certifies an absent DML entitlement or malformed grant inventory',()=>{
 for(const grants of [[],[usage],[usage,''],Array(129).fill(usage)]){
  assert.equal(assessRuntimeGrantEnvelope(grants,schema).allowed,false);
 }
 for(const target of ['','DB-NAME','aaditech_staging_valid;DROP','a'.repeat(65)])
  assert.equal(assessRuntimeGrantEnvelope([scoped],target).allowed,false);
});
test('1FB source uses only current-user read-only grant observation and returns HOLD release flags',()=>{
 const src=readFileSync('scripts/phase1fb-runtime-db-privileges.ts','utf8');
 assert.match(src,/SELECT CURRENT_USER\(\) AS authenticated_user, DATABASE\(\) AS selected_schema/);
 assert.match(src,/SHOW GRANTS FOR CURRENT_USER\(\)/);
 assert.match(src,/getDatabaseConfig\(\)/);
 assert.match(src,/productionReleaseAuthorized:false,releaseDecision:'HOLD'/);
 assert.match(src,/outsideDbaControlVerified:false/);
 assert.match(src,/if\(!allowed\)process.exitCode=1/);
 assert.doesNotMatch(src,/\b(?:conn|db)\.(?:execute|run)\s*\(/);
});
