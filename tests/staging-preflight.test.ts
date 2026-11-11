import test from 'node:test';
import assert from 'node:assert/strict';
import {checkPreflightTarget,migrationChecksums,MIGRATIONS} from '../scripts/lib/stagingPreflight';
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
 assert.equal(entries.length,21);
 assert.equal(new Set(entries.map(x=>x.id)).size,entries.length);
 assert.deepEqual(entries.map(x=>x.id),[...MIGRATIONS]);
 assert.ok(entries.every(x=>/^[a-f0-9]{64}$/.test(x.checksum)));
});
