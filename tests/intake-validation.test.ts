import test from 'node:test';
import assert from 'node:assert/strict';
import {validateInbound,validateWitness,canonicalIntakeHash,reconstructHoldHash,
 IntakeConflictError,IntakeInputError} from '../server/intake/validation';
import {intakeMigrationTarget} from '../scripts/migrate-intake';
import {createHash} from 'node:crypto';

const holdId='11111111-1111-4111-8111-111111111111';
const productId='22222222-2222-4222-8222-222222222222';
const another='33333333-3333-4333-8333-333333333333';
const observation={holdId,deliveryEvidenceRef:'DELIVERY-DOC-2026-001',
 physicalCountRef:'COUNT-WITNESS-2026-001',
 items:[{productId,quantity:2,trackingMode:'SERIAL',
  lotCode:null,serialNumbers:['SERIAL-AB1234','SERIAL-AB1235']}]};
test('exact incoming observation and normalized serialized unit controls',()=>{
 const result=validateInbound(observation);
 assert.deepEqual(result,observation);
 assert.match(canonicalIntakeHash(result),/^[a-f0-9]{64}$/);
 for(const serialNumbers of [
  ['SERIAL-AB1234'],
  ['SERIAL-AB1234','SERIAL-AB1234'],
  ['serial-ab1234','SERIAL-AB1235'],
  ['SERIAL-A B12','SERIAL-AB1235'],
  ['SERIAL-AB1234',100]
 ]){
  assert.throws(()=>validateInbound({...observation,
   items:[{...observation.items[0],serialNumbers}]}),IntakeInputError);
 }
 for(const quantity of [0,-1,1.1,1001,'2',Infinity])
  assert.throws(()=>validateInbound({...observation,
   items:[{...observation.items[0],quantity}]}),IntakeInputError);
 assert.throws(()=>validateInbound({...observation,availableToSell:200}));
 assert.throws(()=>validateInbound({...observation,items:[...observation.items,observation.items[0]]}));
});
test('lot items require code and explicitly no serials; no inferred availability',()=>{
 const line={productId:another,quantity:2,trackingMode:'LOT',lotCode:'LOT-2026-01',serialNumbers:[]};
 assert.deepEqual(validateInbound({...observation,items:[line]}).items,[line]);
 assert.throws(()=>validateInbound({...observation,items:[{...line,serialNumbers:['SERIAL-AB1234']}]}));
 assert.throws(()=>validateInbound({...observation,items:[{...line,lotCode:null}]}));
 assert.throws(()=>validateInbound({...observation,items:[{...line,lotCode:'unsafe lot'}]}));
});
test('witness acceptance requires independent physical count declaration and evidence',()=>{
 const body={outcome:'ACCEPT_QUARANTINE',reason:'All serials inspected in sealed quarantine',
  inspectionEvidenceRef:'REVIEW-COUNT-2026-001',physicallyInspected:true};
 assert.deepEqual(validateWitness(body),body);
 assert.throws(()=>validateWitness({...body,physicallyInspected:false}));
 assert.throws(()=>validateWitness({...body,outcome:'ACCEPT_STOCK'}));
 assert.throws(()=>validateWitness({...body,reason:'short'}));
 assert.throws(()=>validateWitness({...body,dispatchEnabled:true}));
 assert.equal(validateWitness({...body,outcome:'REJECT_INTERNAL',physicallyInspected:false}).outcome,'REJECT_INTERNAL');
});
test('held PO snapshot hash can be reconstructed independent of MySQL JSON field order',()=>{
 const raw={format:'aaditech-internal-po-hold-v1',requestId:holdId,
  supplierId:another,supplierCode:'SUP_A',supplierName:'Test Supplier',siteId:productId,
  supplierQuoteEvidenceRef:'QUOTE-EVID-01',subtotal:'123.00',reviewId:another,
  lines:[{productId,sku:'A',name:'Test',quantity:2,quotedUnitCost:'61.50',lineSubtotal:'123.00'}]};
 const sha=createHash('sha256').update(JSON.stringify(raw)).digest('hex');
 const scrambled=Object.fromEntries(Object.entries(raw).reverse());
 assert.equal(reconstructHoldHash(scrambled),sha);
 assert.throws(()=>reconstructHoldHash({...raw,format:'live-po'}),IntakeConflictError);
});
test('intake migration cannot target production or arbitrary database',()=>{
 assert.equal(intakeMigrationTarget({CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',NODE_ENV:'test'}),'ci');
 assert.equal(intakeMigrationTarget({INTAKE_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
  DB_NAME:'aaditech_staging_isolated',DB_SSL:'true',NODE_ENV:'development'}),'staging');
 for(const env of [{},{DB_NAME:'production',INTAKE_MIGRATION_APPROVED:'YES'},
  {INTAKE_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
   DB_NAME:'aaditech_staging_isolated',DB_SSL:'false'},
  {INTAKE_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES',
   DB_NAME:'aaditech_staging_isolated',DB_SSL:'true',NODE_ENV:'production'}])
  assert.throws(()=>intakeMigrationTarget(env));
});
