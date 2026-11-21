import test from 'node:test';
import assert from 'node:assert/strict';
import {validateSupplier,validateSupplierReview,validateRequisition,validateDecision,
 purchaseHash,ProcurementInputError} from '../server/procurement/validation';
import {procurementMigrationTarget} from '../scripts/migrate-procurement';

const supplierId='11111111-1111-4111-8111-111111111111';
const siteId='22222222-2222-4222-8222-222222222222';
const productId='33333333-3333-4333-8333-333333333333';
test('supplier entry never auto-verifies identity',()=>{
 const input=validateSupplier({code:'VENDOR_A',legalName:' Example Vendor ',taxId:null});
 assert.deepEqual(input,{code:'VENDOR_A',legalName:'Example Vendor',taxId:null});
 for(const code of ['x','aabb','VEN DO','X'.repeat(33)]){
  assert.throws(()=>validateSupplier({code,legalName:'Vendor',taxId:null}),ProcurementInputError);
 }
 assert.throws(()=>validateSupplier({code:'VENDOR_A',legalName:'Vendor',taxId:null,status:'REVIEWED_INTERNAL'}));
 assert.throws(()=>validateSupplierReview({evidenceRef:'ID-EVID-001',attestIdentified:false}));
 assert.deepEqual(validateSupplierReview({evidenceRef:'IDENTITY-REF-01',attestIdentified:true}),
  {evidenceRef:'IDENTITY-REF-01'});
});
test('requisition requires supplier/site/product and bounded exact quote prices',()=>{
 const input={supplierId,siteId,quoteEvidenceRef:'QUOTE-REF-2026-01',
  items:[{productId,quantity:2,quotedUnitCost:'100.20'}]};
 const v=validateRequisition(input);
 assert.equal(v.subtotal,'200.40');
 assert.equal(v.items[0].quotedUnitCost,'100.20');
 assert.match(purchaseHash(v),/^[a-f0-9]{64}$/);
 assert.notEqual(purchaseHash(v),purchaseHash(validateRequisition({...input,
  items:[{productId,quantity:3,quotedUnitCost:'100.20'}]})));
 for(const quantity of [-1,0,0.1,1001,'2',NaN,Infinity])
  assert.throws(()=>validateRequisition({...input,items:[{productId,quantity,quotedUnitCost:'100.20'}]}));
 for(const quotedUnitCost of ['-1','0','0.00','1e9','2.123',100,undefined])
  assert.throws(()=>validateRequisition({...input,items:[{productId,quantity:2,quotedUnitCost}]}));
 assert.throws(()=>validateRequisition({...input,items:[
  {productId,quantity:1,quotedUnitCost:'20'},
  {productId,quantity:2,quotedUnitCost:'20'}]}));
 assert.throws(()=>validateRequisition({...input,dispatchEnabled:true}));
 assert.throws(()=>validateRequisition({...input,quoteEvidenceRef:'missing'}));
});
test('independent decision requires explicit evidence acknowledgement and reason',()=>{
 const valid={decision:'APPROVED_INTERNAL',reason:'Supplier quote independently inspected',evidenceAttested:true};
 assert.deepEqual(validateDecision(valid),valid);
 assert.throws(()=>validateDecision({...valid,evidenceAttested:false}));
 assert.throws(()=>validateDecision({...valid,reason:'short'}));
 assert.throws(()=>validateDecision({...valid,decision:'ISSUED'}));
 assert.deepEqual(validateDecision({...valid,decision:'REJECTED_INTERNAL',evidenceAttested:false}),
  {...valid,decision:'REJECTED_INTERNAL',evidenceAttested:false});
});
test('procurement migration blocks all unapproved production and arbitrary targets',()=>{
 assert.equal(procurementMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(procurementMigrationTarget({PROCUREMENT_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_disposable',DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{DB_NAME:'production',PROCUREMENT_MIGRATION_APPROVED:'YES'},
  {PROCUREMENT_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
   DB_NAME:'aaditech_staging_disposable',DB_SSL:'false'},
  {PROCUREMENT_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
   DB_NAME:'aaditech_staging_disposable',DB_SSL:'true',NODE_ENV:'production'}])
  assert.throws(()=>procurementMigrationTarget(env));
});
