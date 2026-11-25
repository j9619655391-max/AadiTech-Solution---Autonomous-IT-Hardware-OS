import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {reviewerScopeMigrationTarget} from '../scripts/migrate-el-reviewer-scopes';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';

test('1EL additive reviewer migration refuses all production and unauthorized targets',()=>{
 const base={DB_NAME:'aaditech_ci',NODE_ENV:'test',CRM_TEST_DB:'1'};
 assert.equal(reviewerScopeMigrationTarget(base),'ci');
 for(const changed of [
  {...base,DB_NAME:'aaditech_prod'},
  {...base,NODE_ENV:'production'},
  {...base,CRM_TEST_DB:'0'},
  {NODE_ENV:'production',DB_NAME:'aaditech_staging_private',
   DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
   EL_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {NODE_ENV:'staging',DB_NAME:'aaditech_staging_private',
   DB_SSL:'false',STAGING_DISPOSABLE_CONFIRMED:'YES',
   EL_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {NODE_ENV:'staging',DB_NAME:'aaditech_staging_private',
   DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {NODE_ENV:'staging',DB_NAME:'aaditech_staging_private',
   DB_SSL:'true',EL_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}
 ])assert.throws(()=>reviewerScopeMigrationTarget(changed),
  /migration denied/);
 assert.equal(reviewerScopeMigrationTarget({
  NODE_ENV:'staging',DB_NAME:'aaditech_staging_disposable',
  DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EL_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}),'staging');
});
test('1EL registered 0043 schema has no implicit reviewer grants or business-activated tenants',()=>{
 assert.ok(MIGRATIONS.length>=43);
 assert.equal(MIGRATIONS[42],'0043_el_reviewer_scope_candidates');
 const source=readFileSync('database/migrations/0043_el_reviewer_scope_candidates.sql','utf8');
 assert.match(source,/CREATE TABLE IF NOT EXISTS app_reviewer_scope_grants/i);
 assert.match(source,/PRIMARY KEY \(owner_user_id,reviewer_user_id,workflow_scope\)/);
 assert.match(source,/CREATE TABLE IF NOT EXISTS app_reviewer_scope_events/i);
 assert.match(source,/INDEX idx_el_reviewer_queue/);
 assert.match(source,/legal_registry_verified ENUM\('NO'\)/);
 assert.match(source,/signatory_mandate_verified ENUM\('NO'\)/);
 assert.match(source,/production_tenant_activated ENUM\('NO'\)/);
 assert.match(source,/grant_business_data_access ENUM\('NO'\)/);
 assert.doesNotMatch(source,/\bINSERT\s+INTO\b/i);
 assert.doesNotMatch(source,/\bDELETE\s+FROM\b/i);
 assert.doesNotMatch(source,/\bDROP\s+TABLE\b/i);
 assert.doesNotMatch(source,/\bUPDATE\s+crm_/i);
});
