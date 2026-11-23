import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkPreflightTarget,migrationChecksums,MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {checkInstalledEwTriggerIntegrity} from '../scripts/staging-preflight';
import type {EwInstalledTrigger} from '../scripts/migrate-ew-role-cycle';
test('read-only readiness is denied by default and outside disposable DB',()=>{
 assert.throws(()=>checkPreflightTarget({}),/STAGING_PREFLIGHT/);
 assert.throws(()=>checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_production'}),/Refusing/);
 assert.throws(()=>checkPreflightTarget({STAGING_PREFLIGHT:'1',DB_NAME:'aaditech_staging_test',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'false'}),/Refusing/);
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
  ACTION_TIMING:'AFTER'},
 {TRIGGER_NAME:'trg_ew_reviewer_session_quarantine',
  ACTION_STATEMENT:'DELETE FROM auth_sessions WHERE user_id=NEW.id AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)',
  ACTION_TIMING:'AFTER'}
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
 assert.match(statements[0],/SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING FROM information_schema\.TRIGGERS/);
 assert.match(statements[0],/TRIGGER_SCHEMA=DATABASE\(\)/);
 assert.match(statements[0],/EVENT_OBJECT_TABLE='auth_users'/);
 assert.match(statements[0],/EVENT_MANIPULATION='UPDATE'/);
 assert.doesNotMatch(statements[0],/ACTION_TIMING='AFTER'/);
 assert.doesNotMatch(statements[0],/\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+(?:TABLE|TRIGGER|INTO|auth_users)\b/i);
});
test('1EZ fail-closed on missing or tampered trigger metadata, including BEFORE timing',async()=>{
 const changed=ewInstalled.map((row,i)=>i===0?{
  ...row,ACTION_STATEMENT:String(row.ACTION_STATEMENT).replace("'REVOKED'","'REV`OKED'")
 }:row);
 const before=[...ewInstalled,{TRIGGER_NAME:'trg_shadow_before',
  ACTION_STATEMENT:'SET NEW.role=OLD.role',ACTION_TIMING:'BEFORE'}];
 for(const rows of [[],ewInstalled.slice(0,1),changed,before]){
  const {db}=observedEwTriggers(rows);
  await assert.rejects(checkInstalledEwTriggerIntegrity(db),/1E[XY]/);
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
