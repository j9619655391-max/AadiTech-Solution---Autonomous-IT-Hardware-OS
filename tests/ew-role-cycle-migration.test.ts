import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {ewRoleCycleMigrationTarget} from '../scripts/migrate-ew-role-cycle';

test('1EW migration is version-locked, deny-only and never executes on production',()=>{
 const ci={CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'};
 assert.equal(ewRoleCycleMigrationTarget(ci),'ci');
 for(const env of [
  {...ci,DB_NAME:'aaditech_prod'},
  {...ci,NODE_ENV:'production'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'production',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EW_ROLE_CYCLE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'staging',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EW_ROLE_CYCLE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'staging',DB_SSL:'true',
   EW_ROLE_CYCLE_MIGRATION_APPROVED:'YES'}
 ]) assert.throws(()=>ewRoleCycleMigrationTarget(env),/migration denied/);
 assert.equal(ewRoleCycleMigrationTarget({DB_NAME:'aaditech_staging_disposable',
  NODE_ENV:'staging',DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EW_ROLE_CYCLE_MIGRATION_APPROVED:'YES'}),'staging');
 assert.equal(MIGRATIONS[47],'0048_ew_role_cycle_quarantine');
 const sql=readFileSync('database/migrations/0048_ew_role_cycle_quarantine.sql','utf8');
 assert.match(sql,/CREATE TRIGGER trg_ew_reviewer_grant_quarantine[\s\S]*AFTER UPDATE ON auth_users/);
 assert.match(sql,/CREATE TRIGGER trg_ew_reviewer_session_quarantine[\s\S]*AFTER UPDATE ON auth_users/);
 assert.match(sql,/OLD\.role<>NEW\.role OR OLD\.status<>NEW\.status/g);
 assert.match(sql,/SET state='REVOKED'/);
 assert.match(sql,/DELETE FROM auth_sessions/);
 for(const forbidden of ['DROP TABLE','TRUNCATE','SET state=\'ACTIVE\'','GRANT ALL'])
  assert.equal(sql.toUpperCase().includes(forbidden.toUpperCase()),false,forbidden);
});
test('1EW API status change revokes grants and sessions before database status update',()=>{
 const src=readFileSync('server/security/adminRouter.ts','utf8');
 const grant=src.indexOf("UPDATE app_reviewer_scope_grants SET state='REVOKED'");
 const session=src.indexOf("DELETE FROM auth_sessions WHERE user_id=?");
 const account=src.indexOf("UPDATE auth_users SET status=? WHERE id=?");
 assert.ok(grant>=0&&grant<session&&session<account);
 assert.match(src,/revokedSessions=revoked\.affectedRows/);
 assert.match(src,/productionReleaseAuthorized:false,releaseDecision:'HOLD'/);
});
