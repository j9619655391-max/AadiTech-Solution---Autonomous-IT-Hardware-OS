import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {enReviewerScopeMigrationTarget} from '../scripts/migrate-en-reviewer-scopes';

test('1EN add-only scope migration refuses production and unapproved staging',()=>{
 const ci={CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'};
 assert.equal(enReviewerScopeMigrationTarget(ci),'ci');
 for(const invalid of [
  {...ci,DB_NAME:'aaditech_prod'},
  {...ci,CRM_TEST_DB:'0'},
  {...ci,NODE_ENV:'production'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'production',DB_SSL:'true',
    STAGING_DISPOSABLE_CONFIRMED:'YES',EN_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'false',
    STAGING_DISPOSABLE_CONFIRMED:'YES',EN_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'true',
    STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'true',
    EN_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}
 ])assert.throws(()=>enReviewerScopeMigrationTarget(invalid),/migration denied/);
 assert.equal(enReviewerScopeMigrationTarget({DB_NAME:'aaditech_staging_scoped',
  NODE_ENV:'staging',DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EN_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}),'staging');
});
test('1EN immutable predecessor and no retroactive reviewer grants',()=>{
 assert.equal(MIGRATIONS.length,44);
 assert.equal(MIGRATIONS[42],'0043_el_reviewer_scope_candidates');
 assert.equal(MIGRATIONS[43],'0044_en_workflow_review_scopes');
 const sql=readFileSync('database/migrations/0044_en_workflow_review_scopes.sql','utf8');
 assert.match(sql,/ALTER TABLE app_reviewer_scope_grants/i);
 assert.match(sql,/ALTER TABLE app_reviewer_scope_events/i);
 for(const scope of ['QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE'])
  assert.equal(sql.match(new RegExp("'"+scope+"'","g"))?.length,2);
 assert.doesNotMatch(sql,/\\b(?:INSERT|UPDATE|DELETE|DROP|TRUNCATE)\\s+(?:INTO|FROM|TABLE)?\\b/i);
 assert.doesNotMatch(sql,/\\bGRANT\\s+ALL\\b/i);
 assert.doesNotMatch(sql,/\\b(?:production_tenant_activated|grant_business_data_access)\\b\\s*=\\s*'YES'/i);
 const original=readFileSync('database/migrations/0043_el_reviewer_scope_candidates.sql','utf8');
 assert.match(original,/workflow_scope ENUM\\('QUOTES','PROCUREMENT'\\)/);
});
