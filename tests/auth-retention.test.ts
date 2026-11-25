import test from 'node:test';
import assert from 'node:assert/strict';
import {rateWindowBucket} from '../server/auth/limiter';
import {assertSafeRetentionEnvironment,rateBucketCutoff,RETENTION_BUCKET_DAYS,MAX_DELETE_BATCH} from '../scripts/lib/authRetention';

test('retention refuses production, staging and unconfirmed destructive operations',()=>{
 assert.throws(()=>assertSafeRetentionEnvironment({},false),/disposable/);
 assert.throws(()=>assertSafeRetentionEnvironment({
  DB_NAME:'aaditech_production',CRM_TEST_DB:'1',NODE_ENV:'test'},true),/disposable/);
 assert.throws(()=>assertSafeRetentionEnvironment({
  DB_NAME:'aaditech_staging_preview',CRM_TEST_DB:'1',NODE_ENV:'test'},true),/disposable/);
 const env={DB_NAME:'aaditech_ci',CRM_TEST_DB:'1',NODE_ENV:'test'};
 assert.doesNotThrow(()=>assertSafeRetentionEnvironment(env,false));
 assert.throws(()=>assertSafeRetentionEnvironment(env,true),/RETENTION_APPLY/);
 assert.doesNotThrow(()=>assertSafeRetentionEnvironment({...env,RETENTION_APPLY:'YES_DELETE_TEST_ONLY'},true));
});
test('rate counters remain for at least seven days with bounded deletions',()=>{
 const now=Date.UTC(2026,10,9,12,30);
 const cutoff=rateBucketCutoff(now);
 assert.equal(cutoff,rateWindowBucket(now-RETENTION_BUCKET_DAYS*86400000));
 assert.equal(MAX_DELETE_BATCH,250);
 assert.ok(cutoff<rateWindowBucket(now));
 assert.throws(()=>rateBucketCutoff(-1));
});
