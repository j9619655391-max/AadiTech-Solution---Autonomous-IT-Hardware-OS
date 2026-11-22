import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {epReviewerScopeMigrationTarget} from '../scripts/migrate-ep-reviewer-scopes';

test('1EP review grant extension denies production and unapproved staging targets',()=>{
 const ci={CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'};
 assert.equal(epReviewerScopeMigrationTarget(ci),'ci');
 for(const bad of [
  {...ci,DB_NAME:'aaditech_prod'},
  {...ci,CRM_TEST_DB:'0'},
  {...ci,NODE_ENV:'production'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'production',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EP_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EP_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {DB_NAME:'aaditech_staging_private',NODE_ENV:'staging',DB_SSL:'true',
   EP_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}
 ])assert.throws(()=>epReviewerScopeMigrationTarget(bad),/migration denied/);
 assert.equal(epReviewerScopeMigrationTarget({DB_NAME:'aaditech_staging_disposable',
  NODE_ENV:'staging',DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EP_REVIEW_SCOPE_MIGRATION_APPROVED:'YES'}),'staging');
});
test('1EP migration 0046 only appends review scopes; no past grants or legal trust',()=>{
 assert.equal(MIGRATIONS.length,46);
 assert.equal(MIGRATIONS[44],'0045_eo_stock_journal_review_scopes');
 assert.equal(MIGRATIONS[45],'0046_ep_proof_key_trust_review_scopes');
 const sql=readFileSync('database/migrations/0046_ep_proof_key_trust_review_scopes.sql','utf8');
 assert.equal(sql.includes('ALTER TABLE app_reviewer_scope_grants'),true);
 assert.equal(sql.includes('ALTER TABLE app_reviewer_scope_events'),true);
 for(const scope of ['QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK',
  'JOURNAL','PROOF','KEY_LIFECYCLE','EXTERNAL_TRUST'])
  assert.equal(sql.match(new RegExp("'"+scope+"'","g"))?.length,2,scope);
 for(const bad of ['INSERT INTO','UPDATE ','DELETE FROM','DROP TABLE','TRUNCATE TABLE','GRANT ALL'])
  assert.equal(sql.toUpperCase().includes(bad),false,bad);
 const original=readFileSync('database/migrations/0045_eo_stock_journal_review_scopes.sql','utf8');
 assert.equal(original.includes("'JOURNAL'"),true);
 assert.equal(original.includes("'PROOF'"),false);
 assert.equal(original.includes("'EXTERNAL_TRUST'"),false);
});
