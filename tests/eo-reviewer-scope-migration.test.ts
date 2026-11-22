import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {eoReviewerScopeMigrationTarget} from '../scripts/migrate-eo-reviewer-scopes';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';

test('1EO review extension rejects production, wrong DB and unapproved staging',()=>{
 const ci={CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'};
 assert.equal(eoReviewerScopeMigrationTarget(ci),'ci');
 for(const x of [
  {...ci,DB_NAME:'aaditech_real'},
  {...ci,CRM_TEST_DB:'0'},
  {...ci,NODE_ENV:'production'},
  {DB_NAME:'aaditech_staging_x',NODE_ENV:'production',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EO_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_x',NODE_ENV:'staging',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EO_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_x',NODE_ENV:'staging',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {DB_NAME:'aaditech_staging_x',NODE_ENV:'staging',DB_SSL:'true',
   EO_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}
 ])assert.throws(()=>eoReviewerScopeMigrationTarget(x),/migration denied/);
 assert.equal(eoReviewerScopeMigrationTarget({
  DB_NAME:'aaditech_staging_nonproduction',NODE_ENV:'staging',
  DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EO_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}),'staging');
});
test('1EO app-only stock/journal scopes append in 0045 with no retroactive authority',()=>{
 assert.equal(MIGRATIONS.length,45);
 assert.equal(MIGRATIONS[43],'0044_en_workflow_review_scopes');
 assert.equal(MIGRATIONS[44],'0045_eo_stock_journal_review_scopes');
 const sql=readFileSync('database/migrations/0045_eo_stock_journal_review_scopes.sql','utf8');
 assert.equal(sql.includes('ALTER TABLE app_reviewer_scope_grants'),true);
 assert.equal(sql.includes('ALTER TABLE app_reviewer_scope_events'),true);
 for(const scope of ['QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL'])
  assert.equal(sql.match(new RegExp("'"+scope+"'","g"))?.length,2);
 for(const forbidden of ['INSERT INTO','UPDATE ','DELETE FROM','DROP TABLE',
  'TRUNCATE TABLE','GRANT ALL'])
  assert.equal(sql.toUpperCase().includes(forbidden),false);
 const predecessor=readFileSync('database/migrations/0044_en_workflow_review_scopes.sql','utf8');
 assert.equal(predecessor.includes("ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE')"),true);
 assert.equal(predecessor.includes("'STOCK'"),false);
 assert.equal(predecessor.includes("'JOURNAL'"),false);
});
