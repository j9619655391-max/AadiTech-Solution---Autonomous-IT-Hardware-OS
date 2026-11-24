import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkPreflightTarget,migrationChecksums,MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {checkInstalledEwTriggerIntegrity,checkStagingRuntimeDbPrivilegeIntegrity,checkStagingAuthPrincipalBoundary} from '../scripts/staging-preflight';
import {authDatabaseCredentialState} from '../server/db';
import type {EwInstalledTrigger} from '../scripts/migrate-ew-role-cycle';
import {verifiedGfOriginColumn,assertGfFreshInstall,assertGfHistoricalIntegrity,gfMigrationTarget} from '../scripts/migrate-gf-provenance';
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
 assert.equal(entries[45]?.id,'0046_ep_proof_key_trust_review_scopes');
 assert.equal(entries[46]?.id,'0047_eq_provider_review_scopes');
 assert.equal(entries[47]?.id,'0048_ew_role_cycle_quarantine');
 assert.equal(entries[48]?.id,'0049_fn_service_tickets_internal');
 assert.equal(entries[49]?.id,'0050_ga_field_service_plans_internal');
 assert.equal(entries[50]?.id,'0051_gf_crm_quote_write_once');
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
 user="runtime_service@%",schema='aaditech_staging_disposable',roles='NONE',
 grants=["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
  "GRANT SELECT ON aaditech_staging_disposable.crm_customers TO 'runtime_service'@'%'"],
 deny=false,tableTypes=[{TABLE_NAME:'crm_customers',TABLE_TYPE:'BASE TABLE'}]
}:{user?:string;schema?:string;roles?:unknown;grants?:string[];deny?:boolean;
  tableTypes?:Array<{TABLE_NAME:string;TABLE_TYPE:string}>}={}){
 const sql:string[]=[];
 let acquire=0,release=0;
 const db={getConnection:async()=>{
  acquire++;
  return {query:async(query:string)=>{
   sql.push(query);
   if(deny)throw Error("ACCESS DENIED to account 'secret'@'private'");
   if(query.startsWith('SELECT CURRENT_USER()'))
    return [[{authenticated_user:user,selected_schema:schema,active_roles:roles}],[]];
   if(query==='SHOW GRANTS FOR CURRENT_USER()')
    return [grants.map(value=>({'Grants for CURRENT_USER()':value})),[]];
   if(query==='SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')
    return [tableTypes,[]];
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
  'SELECT CURRENT_USER() AS authenticated_user, DATABASE() AS selected_schema, CURRENT_ROLE() AS active_roles',
  'SHOW GRANTS FOR CURRENT_USER()',
  'SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()'
 ]);
});
test('1FC privilege checks fail-closed on unexpected identity/schema, global grants, role grants and SQL denial',async()=>{
 const hostile=[
  {schema:'aaditech_production'},
  {user:''},
  {roles:null},
  {roles:'none'},
  {roles:"'authority_role'@'%'"},
  {grants:[]},
  {grants:["GRANT ALL PRIVILEGES ON *.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT CREATE, INSERT ON aaditech_staging_disposable.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT SELECT ON aaditech_staging_disposable.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT SELECT, UPDATE ON aaditech_staging_disposable.* TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT UPDATE ON aaditech_staging_disposable.app_reviewer_scope_grants TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT SELECT ON aaditech_staging_disposable.auth_users TO 'runtime_service'@'%'"]},
  {grants:["GRANT USAGE ON *.* TO 'runtime_service'@'%'",
   "GRANT SELECT ON aaditech_staging_disposable.auth_totp_credentials TO 'runtime_service'@'%'"]},
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
 assert.match(src,/await checkStagingRuntimeDbPrivilegeIntegrity\(connection,cfg\.database,\s*\{requireOwnerGuard:true\}\)/);
 assert.match(src,/ownerGuardMode\(process\.env\)!=='DEFINER_PROCEDURE'/);
 assert.match(src,/CURRENT_ROLE\(\) AS active_roles/);
 assert.match(src,/!inactiveRuntimeRoles\(identity\[0\]\.active_roles\)/);
 assert.match(src,/runtimePrivilegePreflightTarget\(process\.env\)/);
 assert.match(src,/target==='ci'\?'NOT_EVALUATED_CI':'HOLD'/);
 assert.match(src,/target==='ci'\|\|runtimeDbPrivileges==='PASS'/);
 assert.match(src,/1FC staging runtime DB grant envelope unverified/);
 assert.match(src,/independentDbaApprovalVerified:false/);
 assert.match(src,/const conn=await db\.getConnection\(\)/);
 assert.match(src,/finally\{conn\.release\(\);\}/);
 assert.match(src,/if\(!inspected\.ready\)process\.exitCode=1/);
});

// 1FJ: even a very narrowly scoped SELECT grant can reference a DEFINER VIEW.
// Refuse view aliases, absent/incomplete object inventory, and duplicate names.
test('1FJ same-session base-table metadata denies DEFINER views and ambiguous objects',async()=>{
 const granted="GRANT SELECT ON aaditech_staging_disposable.crm_customers TO 'runtime_service'@'%'";
 const usage="GRANT USAGE ON *.* TO 'runtime_service'@'%'";
 for(const tableTypes of [
  [{TABLE_NAME:'crm_customers',TABLE_TYPE:'VIEW'}],
  [],
  [{TABLE_NAME:'crm_customers',TABLE_TYPE:'BASE TABLE'},
   {TABLE_NAME:'CRM_CUSTOMERS',TABLE_TYPE:'VIEW'}],
  [{TABLE_NAME:'other_table',TABLE_TYPE:'BASE TABLE'}]
 ]){
  const {db,released}=observedRuntimeGrants({grants:[usage,granted],tableTypes});
  await assert.rejects(checkStagingRuntimeDbPrivilegeIntegrity(db,'aaditech_staging_disposable'),/1FJ/);
  assert.equal(released(),1);
 }
 const {db}=observedRuntimeGrants();
 assert.equal((await checkStagingRuntimeDbPrivilegeIntegrity(db,'aaditech_staging_disposable')).dataGrantCount,1);
});

// 1FL does not pretend this configuration check authenticates effective grants.
test('1FL auth pool only permits explicit distinct credential candidate outside developer CI',()=>{
 const common={DB_USER:'runtime_ci',DB_PASSWORD:'runtime_secret',DB_SSL:'true',
  DB_NAME:'aaditech_staging_safe'};
 assert.equal(authDatabaseCredentialState({...common,NODE_ENV:'test'}),'DEV_SHARED');
 assert.equal(authDatabaseCredentialState({...common,NODE_ENV:'development'}),'DEV_SHARED');
 assert.equal(authDatabaseCredentialState({...common,NODE_ENV:'production'}),'HOLD');
 assert.equal(authDatabaseCredentialState({...common,NODE_ENV:'staging'}),'HOLD');
 const separate={...common,NODE_ENV:'staging',AUTH_DB_USER:'auth_ci',
  AUTH_DB_PASSWORD:'auth_secret'};
 assert.equal(authDatabaseCredentialState(separate),'SEPARATE_CANDIDATE');
 for(const env of [
  {...separate,AUTH_DB_USER:''},
  {...separate,AUTH_DB_PASSWORD:''},
  {...separate,AUTH_DB_USER:common.DB_USER},
  {...separate,AUTH_DB_PASSWORD:common.DB_PASSWORD},
  {...separate,AUTH_DB_USER:' auth_ci'},
  {...separate,AUTH_DB_USER:'a'.repeat(33)},
  {...separate,AUTH_DB_USER:'auth@ci'},
  {...separate,NODE_ENV:'prod'},
  {...separate,NODE_ENV:'unknown'},
  {...separate,AUTH_DB_USER:'auth\nci'},
  {...separate,DB_USER:''},
  {...separate,DB_PASSWORD:''}
 ])assert.equal(authDatabaseCredentialState(env),'HOLD');
});
test('1FL production/staging authority handlers cannot fall back to the runtime pool',()=>{
 const db=readFileSync('server/db.ts','utf8');
 assert.match(db,/if\(state==='HOLD'\)return null/);
 assert.match(db,/if\(state==='DEV_SHARED'\)return getPool\(\)/);
 assert.match(db,/user:process\.env\.AUTH_DB_USER!,password:process\.env\.AUTH_DB_PASSWORD!/);
 for(const file of [
  'server/auth/router.ts',
  'server/auth/mfaRouter.ts',
  'server/security/adminRouter.ts',
  'server/security/reviewerScopeRouter.ts'
 ]){
  const src=readFileSync(file,'utf8');
  assert.match(src,/\bgetAuthPool\(\)/,file);
  assert.doesNotMatch(src,/\bgetPool\(\)/,file);
 }
 const preflight=readFileSync('scripts/staging-preflight.ts','utf8');
 assert.match(preflight,/authFunctionalSeparationVerified:false/);
 assert.match(preflight,/authCredentialSeparation/);
 assert.match(preflight,/&&target==='ci'/);
 assert.match(preflight,/1FL auth\/runtime credential and end-to-end service separation not independently verified/);
});

// 1FO: claimed separate AUTH_DB_USER strings are not accepted as MySQL proof.
// Both checked-out sessions must match their expected actual principal, have
// no active roles, and exhibit opposite zero-row auth_users SELECT behavior.
function observedAuthBoundary({
 user,roles='NONE',schema='aaditech_staging_safe',
 protectedTableDenied=false,denialCode='ER_TABLEACCESS_DENIED_ERROR',
 identityRows=1,failAcquire=false
}:{user:string;roles?:unknown;schema?:string;protectedTableDenied?:boolean;
  denialCode?:string;identityRows?:number;failAcquire?:boolean}){
 let released=0;const statements:string[]=[];
 const db={getConnection:async()=>{
  if(failAcquire)throw Error('connection unavailable');
  return {query:async(sql:string)=>{
   statements.push(sql);
   if(sql.startsWith('SELECT CURRENT_USER() AS principal_name')){
    return [Array.from({length:identityRows},()=>({
     principal_name:user,selected_schema:schema,active_roles:roles})),[]];
   }
   if(sql==='SELECT id FROM auth_users LIMIT 0'){
    if(protectedTableDenied)throw Object.assign(new Error('privilege denied'),{code:denialCode});
    return [[],[]];
   }
   throw Error('Unexpected SQL');
  },release:()=>{released++;}};
 }} as unknown as Parameters<typeof checkStagingAuthPrincipalBoundary>[0];
 return {db,statements,released:()=>released};
}
test('1FO actual two-session principal observer requires opposite bounded auth SELECT privileges',async()=>{
 const rt=observedAuthBoundary({user:'runtime_ci@%',protectedTableDenied:true});
 const au=observedAuthBoundary({user:'auth_ci@%'});
 const result=await checkStagingAuthPrincipalBoundary(rt.db,au.db,
  'aaditech_staging_safe','runtime_ci','auth_ci');
 assert.match(result.runtimeFingerprint,/^[0-9a-f]{16}$/);
 assert.match(result.authFingerprint,/^[0-9a-f]{16}$/);
 assert.notEqual(result.runtimeFingerprint,result.authFingerprint);
 assert.equal(rt.released(),1);assert.equal(au.released(),1);
 assert.deepEqual(rt.statements,[
  'SELECT CURRENT_USER() AS principal_name, DATABASE() AS selected_schema, CURRENT_ROLE() AS active_roles',
  'SELECT id FROM auth_users LIMIT 0'
 ]);
 assert.deepEqual(au.statements,rt.statements);
 assert.doesNotMatch(JSON.stringify(result),/runtime_ci|auth_ci|@/);
});
test('1FO dual-principal observer rejects shared identity, missing metadata, active roles and unexpected SQL errors',async()=>{
 const scenarios=[
  {runtime:{user:'runtime_ci@%',protectedTableDenied:false},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true,denialCode:'ER_PARSE_ERROR'},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true},auth:{user:'auth_ci@%',protectedTableDenied:true}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true,roles:'role@%'},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true},auth:{user:'auth_ci@%',roles:'role@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true,schema:'aaditech_production'},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true,identityRows:0},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true},auth:{user:'auth_ci@%',identityRows:2}},
  {runtime:{user:'auth_ci@%',protectedTableDenied:true},auth:{user:'auth_ci@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true},auth:{user:'bad_auth@%'}},
  {runtime:{user:'runtime_ci@%',protectedTableDenied:true},auth:{user:'auth_ci@%',failAcquire:true}}
 ];
 for(const scenario of scenarios){
  const rt=observedAuthBoundary(scenario.runtime);
  const au=observedAuthBoundary(scenario.auth);
  await assert.rejects(checkStagingAuthPrincipalBoundary(rt.db,au.db,
   'aaditech_staging_safe','runtime_ci','auth_ci'));
  assert.equal(rt.released(),1,'runtime connection must always release');
  assert.equal(au.released(),('failAcquire' in scenario.auth && scenario.auth.failAcquire)?0:1,
   'auth connection must release when acquired');
 }
 for(const [runtime,auth] of [['bad@name','auth_ci'],['runtime_ci','runtime_ci'],['runtime_ci','']] ){
  const rt=observedAuthBoundary({user:'runtime_ci@%',protectedTableDenied:true});
  const au=observedAuthBoundary({user:'auth_ci@%'});
  await assert.rejects(checkStagingAuthPrincipalBoundary(rt.db,au.db,
   'aaditech_staging_safe',runtime,auth),/1FO/);
  assert.equal(rt.released(),0);assert.equal(au.released(),0);
 }
});
test('1FO staging reports technical dual-principal observation but never promotes release-ready',()=>{
 const src=readFileSync('scripts/staging-preflight.ts','utf8');
 assert.match(src,/authPrincipalBoundary:'PASS'\|'HOLD'\|'NOT_EVALUATED_CI'/);
 assert.match(src,/await checkStagingAuthPrincipalBoundary\(/);
 assert.match(src,/authPrincipalFingerprints/);
 assert.match(src,/1FO authenticated dual-principal and runtime protected-table denial unverified/);
 assert.match(src,/&&target==='ci'/);
 assert.match(src,/authFunctionalSeparationVerified:false/);
 assert.match(src,/independentDbaApprovalVerified:false/);
});

test('1GG generated CRM origin readback accepts only narrow equivalent SQL formatting',()=>{
 const row={EXTRA:'STORED GENERATED',DATA_TYPE:'char',CHARACTER_MAXIMUM_LENGTH:36,IS_NULLABLE:'YES',
  COLLATION_NAME:'utf8mb4_unicode_ci',GENERATION_EXPRESSION:"case when (\x60operation\x60 = _utf8mb4'CREATE') then \x60entity_id\x60 else NULL end"};
 for(const expression of [
  row.GENERATION_EXPRESSION,
  "CASE WHEN operation='CREATE' THEN entity_id ELSE NULL END",
  "case when (operation = _utf8mb3'CREATE') then entity_id else null end",
  "case when operation = _utf8'CREATE' then entity_id end"
 ])assert.equal(verifiedGfOriginColumn([{...row,GENERATION_EXPRESSION:expression}]),true,expression);
 for(const expression of [
  "CASE WHEN operation='DELETE' THEN entity_id ELSE NULL END",
  "CASE WHEN operation='create' THEN entity_id ELSE NULL END",
  "CASE WHEN operation='CREATE' THEN actor_user_id ELSE NULL END",
  "CASE WHEN operation='CREATE' THEN entity_id ELSE entity_id END",
  "CASE WHEN operation='CREATE' OR 1=1 THEN entity_id ELSE NULL END",
  "CASE WHEN operation=_latin1'CREATE' THEN entity_id ELSE NULL END",
  "CASE WHEN operation='CRE ATE' THEN entity_id ELSE NULL END",
  "CASE WHEN operation='CREATE' THEN CONCAT(entity_id,'') ELSE NULL END"
 ])assert.equal(verifiedGfOriginColumn([{...row,GENERATION_EXPRESSION:expression}]),false,expression);
 for(const changed of [{EXTRA:'VIRTUAL GENERATED'},{DATA_TYPE:'varchar'},{CHARACTER_MAXIMUM_LENGTH:35},
  {IS_NULLABLE:'NO'},{COLLATION_NAME:'utf8mb4_bin'}])
  assert.equal(verifiedGfOriginColumn([{...row,...changed}]),false);
 assert.equal(verifiedGfOriginColumn([]),false);
 assert.equal(verifiedGfOriginColumn([row,row]),false);
});
test('1GG pre-DDL inspection refuses partial artifacts, historical conflicts and metadata errors',async()=>{
 type Reader=Parameters<typeof assertGfFreshInstall>[0];
 const mock=(replies:unknown[][],fail=false)=>{
  const queries:string[]=[];
  const db={query:async(sql:string)=>{
   queries.push(sql);if(fail)throw Error('metadata unavailable');
   return [replies[queries.length-1]??[],[]];
  }} as unknown as Reader;
  return {db,queries};
 };
 const fresh=mock([[]]);await assertGfFreshInstall(fresh.db);
 assert.match(fresh.queries[0],/information_schema\.COLUMNS/);
 assert.match(fresh.queries[0],/information_schema\.STATISTICS/);
 assert.match(fresh.queries[0],/information_schema\.TRIGGERS/);
 await assert.rejects(assertGfFreshInstall(mock([[{present:1}]]).db),/partial or conflicting/);
 await assert.rejects(assertGfFreshInstall(mock([],true).db),/metadata unavailable/);
 const valid=mock([[],[],[]]);await assertGfHistoricalIntegrity(valid.db);assert.equal(valid.queries.length,3);
 for(let i=0;i<3;i++){
  const rows:unknown[][]=[[],[],[]];rows[i]=[{present:1}];
  await assert.rejects(assertGfHistoricalIntegrity(mock(rows).db),/manual quarantine required/);
 }
 await assert.rejects(assertGfHistoricalIntegrity(mock([],true).db),/metadata unavailable/);
 assert.throws(()=>gfMigrationTarget({NODE_ENV:'production',DB_NAME:'aaditech_ci',DB_SSL:'false',CRM_TEST_DB:'1'}),/CI-only/);
});
