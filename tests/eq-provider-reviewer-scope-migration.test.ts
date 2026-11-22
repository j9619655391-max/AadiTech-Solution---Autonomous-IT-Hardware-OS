import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
import {eqProviderScopeMigrationTarget} from '../scripts/migrate-eq-provider-scopes';

test('1EQ guarded migration denies production/unapproved staging and no retroactive grants',()=>{
 const ci={CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'};
 assert.equal(eqProviderScopeMigrationTarget(ci),'ci');
 for(const bad of [
  {...ci,DB_NAME:'aaditech_prod'},{...ci,NODE_ENV:'production'}, {...ci,CRM_TEST_DB:'0'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'production',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EQ_PROVIDER_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'staging',DB_SSL:'false',
   STAGING_DISPOSABLE_CONFIRMED:'YES',EQ_PROVIDER_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'staging',DB_SSL:'true',
   EQ_PROVIDER_SCOPE_MIGRATION_APPROVED:'YES'},
  {DB_NAME:'aaditech_staging_test',NODE_ENV:'staging',DB_SSL:'true',
   STAGING_DISPOSABLE_CONFIRMED:'YES'}
 ])assert.throws(()=>eqProviderScopeMigrationTarget(bad),/migration denied/);
 assert.equal(eqProviderScopeMigrationTarget({DB_NAME:'aaditech_staging_disposable',
  NODE_ENV:'staging',DB_SSL:'true',STAGING_DISPOSABLE_CONFIRMED:'YES',
  EQ_PROVIDER_SCOPE_MIGRATION_APPROVED:'YES'}),'staging');
 assert.equal(MIGRATIONS[45],'0046_ep_proof_key_trust_review_scopes');
 assert.equal(MIGRATIONS[46],'0047_eq_provider_review_scopes');
 const sql=readFileSync('database/migrations/0047_eq_provider_review_scopes.sql','utf8');
 for(const scope of ['PROVIDER_BRIDGE','PROVIDER_SANDBOX','PROVIDER_SELECTION',
  'PROVIDER_ONBOARDING','EXTERNAL_TRUST','PROOF','KEY_LIFECYCLE','QUOTES'])
  assert.equal(sql.match(new RegExp("'"+scope+"'","g"))?.length,2,scope);
 for(const forbidden of ['INSERT INTO','UPDATE ','DELETE FROM','DROP TABLE','TRUNCATE TABLE','GRANT ALL'])
  assert.equal(sql.toUpperCase().includes(forbidden),false,forbidden);
});
test('1EQ provider queue and decisions must both enforce the same owner nomination',()=>{
 for(const [family,queues] of [['providerBridge',2],['providerSandbox',2],
  ['providerSelection',3],['providerOnboarding',3]] as const){
  const source=readFileSync('server/'+family+'/reviewRouter.ts','utf8');
  assert.equal(source.split('providerScopeSql(').length-1,queues,family+' queues');
  assert.ok(source.split('requireProviderReviewerScope(').length-1>=queues,family+' decisions/detail');
  assert.match(source,/ProviderReviewScopeDenied/);
 }
 const helper=readFileSync('server/security/providerReviewScope.ts','utf8');
 for(const required of ["g.state='ACTIVE'","o.status='ACTIVE'","v.status='ACTIVE'",'activeSensitiveReviewerScope','scope,lock'])
  assert.equal(helper.includes(required),true,required);
});
