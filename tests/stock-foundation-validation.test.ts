import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {releaseInput,releaseDecisionInput,planInput,
 releaseSnapshot,releaseHoldSnapshot,planDigest,noNegativeProjection,
 rejectLiveAllocation,ChainInputError,ChainConflictError} from '../server/stockFoundation/validation';
import {stockFoundationMigrationTarget} from '../scripts/migrate-stock-foundation';
const heldGrnId=randomUUID(),releaseIntentId=randomUUID(),productId=randomUUID();
test('strict stock release and reservation-plan contracts deny posting or allocation flags',()=>{
 assert.deepEqual(releaseInput({heldGrnId}),{heldGrnId});
 assert.throws(()=>releaseInput({heldGrnId,postNow:true}),ChainInputError);
 assert.throws(()=>releaseInput({heldGrnId:'not-a-uuid'}),ChainInputError);
 const request={releaseIntentId,productId,quantity:2,planningRef:'PLANNING-REF-2026'};
 assert.deepEqual(planInput(request),request);
 for(const x of [{quantity:0},{quantity:1.5},{quantity:1001},{productId:'invalid'},
  {planningRef:'X'},{reserveNow:true}])
  assert.throws(()=>planInput({...request,...x}),ChainInputError);
 const decision={decision:'REVIEWED_HELD',reason:'Independently verified internal physical count',
  evidenceRef:'REVIEW-RELEASE-2026',sourceInspected:true};
 assert.deepEqual(releaseDecisionInput(decision),decision);
 assert.throws(()=>releaseDecisionInput({...decision,sourceInspected:false}),ChainInputError);
 assert.throws(()=>releaseDecisionInput({...decision,decision:'POSTED'}),ChainInputError);
 assert.equal(releaseDecisionInput({...decision,decision:'REJECTED_INTERNAL',
  sourceInspected:false}).decision,'REJECTED_INTERNAL');
});
test('frozen release and plan hashes capture serial identity and remain disabled',()=>{
 const source={heldGrnId,heldGrnSha256:'a'.repeat(64),observationId:randomUUID(),
  siteId:randomUUID(),ownerId:randomUUID(),holdId:randomUUID(),
  lines:[{productId,quantity:2,trackingMode:'SERIAL' as const,lotCode:null,
   serialNumbers:['SERIAL-B-2026','SERIAL-A-2026']}]};
 const snapshot=releaseSnapshot(source);
 assert.deepEqual(snapshot.lines[0].serialNumbers,['SERIAL-A-2026','SERIAL-B-2026']);
 assert.equal(snapshot.postingState,'DISABLED');
 assert.equal(snapshot.stockPosted,false);assert.equal(snapshot.availableToSell,null);
 assert.equal(releaseHoldSnapshot(releaseIntentId,'a'.repeat(64),randomUUID()).postingState,'DISABLED');
 const req={releaseIntentId,productId,quantity:2,planningRef:'PLANNING-REF-2026'};
 assert.notEqual(planDigest(req,'a'.repeat(64),source.siteId),
  planDigest({...req,quantity:1},'a'.repeat(64),source.siteId));
});
test('pure no-negative-stock function requires conservation and sufficient available funds',()=>{
 assert.deepEqual(noNegativeProjection({available:8,reserved:2,picked:1,posted:11,request:5}),
  {remaining:3});
 for(const value of [
  {available:0,reserved:0,picked:0,posted:0,request:1},
  {available:5,reserved:6,picked:0,posted:10,request:1},
  {available:5,reserved:0,picked:0,posted:6,request:1},
  {available:1,reserved:0,picked:0,posted:1,request:2},
  {available:-1,reserved:0,picked:0,posted:0,request:1},
  {available:1.2,reserved:0,picked:0,posted:1,request:1}
 ])assert.throws(()=>noNegativeProjection(value),/./);
 assert.throws(()=>rejectLiveAllocation(1),ChainConflictError);
 assert.throws(()=>rejectLiveAllocation(1000),ChainConflictError);
});
test('stock schema migration refuses real or unapproved databases',()=>{
 assert.equal(stockFoundationMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',
  NODE_ENV:'test'}),'ci');
 assert.equal(stockFoundationMigrationTarget({STOCK_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_stock',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{NODE_ENV:'production',STOCK_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_stock',DB_SSL:'true'},
 {NODE_ENV:'development',STOCK_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_live',DB_SSL:'true'},
 {NODE_ENV:'development',STOCK_FOUNDATION_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_stock',DB_SSL:'false'}])
  assert.throws(()=>stockFoundationMigrationTarget(env));
});
