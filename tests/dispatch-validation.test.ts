import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {validateDestination,validateDestinationReview,validatePreparation,
 validateDispatchReview,dispatchManifest,verifyManifestJson,sha,DispatchInputError,DispatchConflictError} from '../server/dispatch/validation';
import {dispatchMigrationTarget} from '../scripts/migrate-dispatch-holds';

const supplierId=randomUUID(),holdId=randomUUID(),destinationId=randomUUID();
test('supplier destination requires strictly normalized, lower-case, single accountable address',()=>{
 const input={supplierId,email:'vendor@example.invalid',evidenceRef:'ADDRESS-EVIDENCE-2026'};
 assert.deepEqual(validateDestination(input),input);
 for(const email of ['Vendor@example.invalid','vendor@localhost','a@b','a+b@x.example',
 'hello\r\nBcc:evil@example.invalid','vendor..admin@example.invalid',' test@example.invalid','v@x.invalid\n'])
  assert.throws(()=>validateDestination({...input,email}),DispatchInputError);
 assert.throws(()=>validateDestination({...input,verified:true}),DispatchInputError);
 assert.throws(()=>validateDestination({...input,supplierId:'bad'}),DispatchInputError);
});
test('two independent decisions are strict, evidence-bearing, and disallow self-issued state',()=>{
 assert.deepEqual(validateDestinationReview({decision:'REVIEWED_INTERNAL',
  evidenceRef:'DEST-CHECK-2026',reason:'Independently inspected destination evidence',identityAttested:true}).decision,
  'REVIEWED_INTERNAL');
 assert.throws(()=>validateDestinationReview({decision:'REVIEWED_INTERNAL',
  evidenceRef:'DEST-CHECK-2026',reason:'Independently inspected destination evidence',identityAttested:false}));
 assert.deepEqual(validatePreparation({holdId,destinationId,authorizationEvidenceRef:'AUTH-CHECK-2026'}),
  {holdId,destinationId,authorizationEvidenceRef:'AUTH-CHECK-2026'});
 assert.throws(()=>validatePreparation({holdId,destinationId,authorizationEvidenceRef:'AUTH-CHECK-2026',sendNow:true}));
 const decision={decision:'APPROVED_INTERNAL',reason:'Independent authorization and destination inspection recorded',
  evidenceRef:'REVIEW-AUTH-2026',destinationAttested:true};
 assert.deepEqual(validateDispatchReview(decision),decision);
 assert.throws(()=>validateDispatchReview({...decision,destinationAttested:false}));
 assert.throws(()=>validateDispatchReview({...decision,decision:'SENT_TO_SUPPLIER'}));
 assert.equal(validateDispatchReview({...decision,decision:'REJECTED_INTERNAL',
  destinationAttested:false}).decision,'REJECTED_INTERNAL');
});
test('canonical HELD dispatch manifest cannot be mutated to claim issuance or change recipient',()=>{
 const manifest=dispatchManifest({holdId,holdSha256:'a'.repeat(64),destinationId,
  supplierId,email:'supplier@example.invalid',authorizationEvidenceRef:'AUTH-EVIDENCE-2026'});
 const digest=sha(JSON.stringify(manifest));
 assert.deepEqual(verifyManifestJson(Object.fromEntries(Object.entries(manifest).reverse()),digest),manifest);
 assert.throws(()=>verifyManifestJson({...manifest,externalOrderIssued:true},digest),DispatchConflictError);
 assert.throws(()=>verifyManifestJson({...manifest,email:'other@example.invalid'},digest),DispatchConflictError);
 assert.throws(()=>verifyManifestJson({...manifest,dispatchState:'ENABLED'},digest),DispatchConflictError);
 assert.throws(()=>verifyManifestJson(manifest,'a'.repeat(64)),DispatchConflictError);
});
test('supplier dispatch migration cannot target production or arbitrary DB',()=>{
 assert.equal(dispatchMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(dispatchMigrationTarget({DISPATCH_HOLDS_MIGRATION_APPROVED:'YES',
  STAGING_DISPOSABLE_CONFIRMED:'YES',DB_NAME:'aaditech_staging_disposable',
  DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{NODE_ENV:'production',DB_NAME:'aaditech_staging_disposable',
  DISPATCH_HOLDS_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',DB_SSL:'true'},
  {NODE_ENV:'development',DB_NAME:'aaditech_real',DB_SSL:'true',
  DISPATCH_HOLDS_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'},
  {NODE_ENV:'development',DB_NAME:'aaditech_staging_disposable',DB_SSL:'false',
  DISPATCH_HOLDS_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'}])
  assert.throws(()=>dispatchMigrationTarget(env));
});
