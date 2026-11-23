import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyEwTriggerBodies,type EwInstalledTrigger} from '../scripts/migrate-ew-role-cycle';

// Observations deliberately imitate information_schema.TRIGGERS rather than
// trusting that a trigger name proves the enforcement body has not been changed.
const expected:EwInstalledTrigger[]=[
 {TRIGGER_NAME:'trg_ew_reviewer_grant_quarantine',
  ACTION_STATEMENT:"UPDATE app_reviewer_scope_grants SET state='REVOKED' WHERE reviewer_user_id=NEW.id AND state='ACTIVE' AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)",ACTION_TIMING:'AFTER'},
 {TRIGGER_NAME:'trg_ew_reviewer_session_quarantine',
  ACTION_STATEMENT:'DELETE FROM auth_sessions WHERE user_id=NEW.id AND (OLD.role<>NEW.role OR OLD.status<>NEW.status)',ACTION_TIMING:'AFTER'}
];
function changed(index:number,body:string):EwInstalledTrigger[]{
 return expected.map((row,i)=>i===index?{...row,ACTION_STATEMENT:body}:{...row});
}
test('1EX accepts the exact enforcement bodies with MySQL whitespace/identifier-format variance',()=>{
 assert.doesNotThrow(()=>verifyEwTriggerBodies(expected));
 const formatted=expected.map(row=>({
  TRIGGER_NAME:row.TRIGGER_NAME.toUpperCase(),
  ACTION_TIMING:row.ACTION_TIMING,
  ACTION_STATEMENT:'  '+(row.ACTION_STATEMENT??'').replace(/ WHERE /g,'\n  WHERE ')
   .replace(/=/g,' = ').replace(/app_reviewer_scope_grants/g,'`app_reviewer_scope_grants`')+' '
 }));
 assert.doesNotThrow(()=>verifyEwTriggerBodies(formatted));
});
test('1EX fails closed when a privileged actor preserves the names but changes trigger semantics',()=>{
 const grant=String(expected[0].ACTION_STATEMENT);
 const session=String(expected[1].ACTION_STATEMENT);
 for(const rows of [
  changed(0,grant.replace("state='REVOKED'","state='ACTIVE'")),
  changed(0,grant.replace('OLD.status<>NEW.status','OLD.status=NEW.status')),
  changed(0,grant.replace(' OR ',' AND ')),
  changed(0,grant.replace('app_reviewer_scope_grants','other_grants')),
  changed(1,session.replace('DELETE FROM auth_sessions','SELECT * FROM auth_sessions')),
  changed(1,session.replace('OLD.role<>NEW.role OR ',''))
 ])assert.throws(()=>verifyEwTriggerBodies(rows),/1EX trigger ACTION_STATEMENT drift/);
});
test('1EX fails closed on missing, extra, duplicate, swapped and NULL trigger bodies',()=>{
 for(const rows of [
  expected.slice(0,1),
  [...expected,{TRIGGER_NAME:'trg_unapproved',ACTION_STATEMENT:'SELECT 1',ACTION_TIMING:'AFTER'}],
  [expected[0],expected[0]],
  [expected[1],expected[0],expected[1]],
  changed(1,String(expected[0].ACTION_STATEMENT)),
  changed(0,''),
  expected.map((row,i)=>i===1?{...row,ACTION_STATEMENT:null}:row)
 ])assert.throws(()=>verifyEwTriggerBodies(rows),/1EX/);
});
test('1EX runner queries installed body and checks on first apply and checksum-verified rerun',()=>{
 const src=readFileSync('scripts/migrate-ew-role-cycle.ts','utf8');
 assert.match(src,/SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING FROM information_schema\.TRIGGERS/);
 assert.match(src,/verifyEwTriggerBodies\(rows\)/);
 assert.match(src,/if\(applied\.has\(id\)\)/);
 assert.match(src,/if\(applied\.get\(id\)!==checksum\)/);
 assert.match(src,/await assertInstalled\(conn\)/g);
 assert.match(src,/migration denied outside disposable CI or explicitly approved isolated TLS staging/);
});

test('1EY does not normalize altered SQL literal bytes or unsafe identifier quoting',()=>{
 const grant=String(expected[0].ACTION_STATEMENT);
 const session=String(expected[1].ACTION_STATEMENT);
 for(const rows of [
  changed(0,grant.replace("'REVOKED'","'REV`OKED'")),
  changed(0,grant.replace("'ACTIVE'","'ACT`IVE'")),
  changed(0,grant.replace("'REVOKED'","'REVO  KED'")),
  changed(0,grant.replace("NEW.id","`NE`W`.id")),
  changed(1,session.replace("NEW.id","`NEW`.`other_id`"))
 ]) assert.throws(()=>verifyEwTriggerBodies(rows),/1E[XY]/);
 const quoted=expected.map(row=>({...row,ACTION_STATEMENT:String(row.ACTION_STATEMENT)
  .replace(/NEW\.id/g,'`NEW`.`id`').replace(/OLD\.status/g,'`OLD`.`status`')}));
 assert.doesNotThrow(()=>verifyEwTriggerBodies(quoted));
});
test('1EY rejects unexpected BEFORE UPDATE triggers even when AFTER bodies still match',()=>{
 assert.throws(()=>verifyEwTriggerBodies(expected.map((x,i)=>i===0?{...x,ACTION_TIMING:'BEFORE'}:x)),/1EY/);
 assert.throws(()=>verifyEwTriggerBodies([...expected,{
  TRIGGER_NAME:'trg_shadow_before',ACTION_STATEMENT:'SET NEW.role=OLD.role',ACTION_TIMING:'BEFORE'
 }]),/1EX|1EY/);
 const src=readFileSync('scripts/migrate-ew-role-cycle.ts','utf8');
 assert.match(src,/SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING FROM information_schema\.TRIGGERS/);
 assert.doesNotMatch(src,/AND ACTION_TIMING='AFTER'/);
 assert.match(src,/row\.ACTION_TIMING!=='AFTER'/);
});
