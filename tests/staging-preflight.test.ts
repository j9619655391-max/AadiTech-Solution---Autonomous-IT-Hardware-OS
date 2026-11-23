import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkPreflightTarget,migrationChecksums,MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {checkInstalledEwTriggerIntegrity,checkStagingRuntimeDbPrivilegeIntegrity} from '../scripts/staging-preflight';
import type {EwInstalledTrigger} from '../scripts/migrate-ew-role-cycle';
test('read-only readiness is denied by default and outside disposable DB',()=>{
 assert.throws(()=>checkPreflightTarget({}),/STAGING_PREFLIGHT/);
 assert.throws(()=>checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_production'}),/Refusing/);
 assert.throws(()=>checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_staging_test',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'false'}),/Refusing/);
 assert.throws(()=>checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_staging_test',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true',NODE_ENV:'production'}),/Refusing/);
 assert.equal(checkPreflightTarget({STAGING_PREFLIGHT:'1',CRM_TEST_DB:'1',
  DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_staging_restore',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true'}),'staging');
});
test('all known migration checksums derive from checked-in SQL bytes',()=>{
 const entries=migrationChecksums();
 assert.equal(entries.length,MIGRATIONS.length);
 assert.equal(entries.at(-3)?.id,'0046_ep_proof_key_trust_review_scopes');
 assert.equal(entries.at(-2)?.id,'0047_eq_provider_review_scopes');
 assert.equal(entries.at(-1)?.id,'0048_ew_role_cycle_quarantine');
 assert.equal(new Set(entries.map(x=>x.id)).size,entries.length);
 assert.deepEqual(entries.map(x=>x.id),[...MIGRATIONS]);
 assert.ok(entries.every(x=>/^[a-f0-9]{64}$/.test(x.checksum)));
});

const ewInstalled:EwInstalledTrigger[]=[
 {TRIGGER_NAME:'trg_ew_reviewer_grant_quarantine',
  ACTION_STATEMENT:"UPDATE app_reviewer_scope_grants SET state='REVOKED' WHERE reviewer_user_id=NEW.id AND state='ACTIVE' AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)",
  ACTION_TIMING:'AFTER',EVENT_MANIPULATION:'UPDATE'},
 {TRIGGER_NAME:'trg_ew_reviewer_session_quarantine',
  ACTION_STATEMENT:'DELETE FROM auth_sessions WHERE user_id=NEW.id AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)',
  ACTION_TIMING:'AFTER',EVENT_MANIPULATION:'UPDATE'}
];
function observedEwTriggers(rows:EwInstalledTrigger[],deny=false){
 const statements:string[]=[];
 const db={query:async(sql:string)=>{
  statements.push(sql);
  if(deny)throw Error('ACCESS DENIED: sensitive connector detail');
  return [rows,[]];
 }} as unknown as Parameters<typeof checkInstalledEwTriggerIntegrity>[0];
 return {db,statements};
}
test('1EZ staging preflight independently queries all installed auth_users UPDATE triggers read-only',async()=>{
 const {db,statements}=observedEwTriggers(ewInstalled);
 await checkInstalledEwTriggerIntegrity(db);
 assert.equal(statements.length,1);
 assert.match(statements[0],/SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING,EVENT_MANIPULATION FROM information_schema\.TRIGGERS/);
 assert.match(statements[0],/TRIGGER_SCHEMA=DATABASE\(\)/);
 assert.match(statements[0],/EVENT_OBJECT_TABLE='auth_users'/);
 assert.doesNotMatch(statements[0],/AND EVENT_MANIPULATION='UPDATE'/);
 assert.doesNotMatch(statements[0],/ACTION_TIMING='AFTER'/);
 assert.doesNotMatch(statements[0],/\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+(?:TABLE|TRIGGER|INTO|auth_users)\b/i);
});
test('1EZ fail-closed on missing or tampered trigger metadata, including BEFORE timing',async()=>{
 const changed=ewInstalled.map((row,i)=>i===0?{
  ...row,ACTION_STATEMENT:String(row.ACTION_STATEMENT).replace("'REVOKED'","'REV`OKED'")
 }:row);
 const before=[...ewInstalled,{TRIGGER_NAME:'trg_shadow_before',
  ACTION_STATEMENT:'SET NEW.role=OLD.role',ACTION_TIMING:'BEFORE',EVENT_MANIPULATION:'UPDATE'}];
 const unexpected=[...ewInstalled,{TRIGGER_NAME:'trg_shadow_insert',
  ACTION_STATEMENT:'SET @x=1',ACTION_TIMING:'AFTER',EVENT_MANIPULATION:'INSERT'}];
 const wrongEvent=ewInstalled.map((row,i)=>i===0?{...row,EVENT_MANIPULATION:'DELETE'}:row);
 for(const rows of [[],ewInstalled.slice(0,1),changed,before,unexpected,wrongEvent]){
  const {db}=observedEwTriggers(rows);
  await assert.rejects(checkInstalledEwTriggerIntegrity(db),/1E[XY]|1FB/);
 }
 const {db}=observedEwTriggers(ewInstalled,true);
 await assert.rejects(checkInstalledEwTriggerIntegrity(db),/ACCESS DENIED/);
});
test('1EZ CLI keeps failed live trigger checks as HOLD and never treats checksum-only preflight as ready',()=>{
 const src=readFileSync('scripts/staging-preflight.ts','utf8');
 assert.match(src,/await checkInstalledEwTriggerIntegrity\(connection\)/);
 assert.match(src,/ready:result\.ready&&triggerIntegrity==='PASS'/);
 assert.match(src,/triggerIntegrity:'PASS'\|'HOLD'/);
 assert.match(src,/1EZ installed auth_users UPDATE trigger integrity unverified/);
 assert.match(src,/if\(!inspected\.ready\)process\.exitCode=1/);
 assert.match(src,/checkPreflightTarget\(process\.env\)/);
});

function observedRuntimeGrants({
 user="runtime_service@%",schema='aaditech_staging_disposable',
 grants=["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
  "GRANT SELECT, INSERT, UPDATE, DELETE ON aaditech_staging_disposable.* TO 'runtime_service'@'%'"],
 deny=false
}:{user?:string;schema?:string;grants?:string[];deny?:boolean}={}){
 const sql:string[]=[];
 let acquire=0,release=0;
 const db={getConnection:async()=>{
  acquire++;
  return {query:async(query:string)=>{
   sql.push(query);
   if(deny)throw Error("ACCESS DENIED to account 'secret'@'private'");
   if(query.startsWith('SELECT CURRENT_USER()'))
    return [[{authenticated_user:user,selected_schema:schema}],[]];
   if(query==='SHOW GRANTS FOR CURRENT_USER()')
    return [grants.map(value=>({'Grants for CURRENT_USER()':value})),[]];
   throw Error('Unexpected SQL');
  },release:()=>{release++;}};
 }} as unknown as Parameters<typeof checkStagingRuntimeDbPrivilegeIntegrity>[0];
 return {db,sql,acquired:()=>acquire,released:()=>release};
}
test('1FC read-only staging runtime privilege gate observes authenticated current user and grants on same SQL connection',async()=>{
 const {db,sql,acquired,released}=observedRuntimeGrants();
 const value=await checkStagingRuntimeDbPrivilegeIntegrity(db,'aaditech_staging_disposable');
 assert.deepEqual(value,{grantCount:2,dataGrantCount:1});
 assert.equal(acquired(),1);
 assert.equal(released(),1);
 assert.deepEqual(sql,[
  'SELECT CURRENT_USER() AS authenticated_user, DATABASE() AS selected_schema',
  'SHOW GRANTS FOR CURRENT_USER()'
 ]);
});
test('1FC privilege checks fail-closed on unexpected identity/schema, global grants, role grants and SQL denial',async()=>{
 const hostile=[
  {schema:'aaditech_production'},
  {user:''},
  {grants:[]},
  {grants:["GRANT ALL PRIVILEGES ON *.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT CREATE, INSERT ON aaditech_staging_disposable.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT 'role_admin'@'%' TO 'runtime_service'@'%'"]},
  {deny:true}
 ];
 for(const scenario of hostile){
  const {db,released}=observedRuntimeGrants(scenario);
  await assert.rejects(
   checkStagingRuntimeDbPrivilegeIntegrity(db,'aaditech_staging_disposable'),
   /1FC|ACCESS DENIED/);
  assert.equal(released(),1,'connection must release even on denied metadata');
 }
});
test('1FC staging CLI requires grant PASS; CI result explicitly declines actual staging privilege certification',()=>{
 const src=readFileSync('scripts/staging-preflight.ts','utf8');
 assert.match(src,/await checkStagingRuntimeDbPrivilegeIntegrity\(connection,cfg\.database\)/);
 assert.match(src,/runtimePrivilegePreflightTarget\(process\.env\)/);
 assert.match(src,/target==='ci'\?'NOT_EVALUATED_CI':'HOLD'/);
 assert.match(src,/target==='ci'\|\|runtimeDbPrivileges==='PASS'/);
 assert.match(src,/1FC staging runtime DB grant envelope unverified/);
 assert.match(src,/independentDbaApprovalVerified:false/);
 assert.match(src,/const conn=await db\.getConnection\(\)/);
 assert.match(src,/finally\{conn\.release\(\);\}/);
 assert.match(src,/if\(!inspected\.ready\)process\.exitCode=1/);
});
