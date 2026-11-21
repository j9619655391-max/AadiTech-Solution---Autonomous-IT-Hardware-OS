import test from 'node:test';
import assert from 'node:assert/strict';
import { InputError, parsePagination,parseVersion,validate } from '../server/crm/validation';
import { validId } from '../server/crm/repository';

test('Customer validation trims strings and denies unknown or privileged balances',()=>{
  const good=validate('customers',{name:'  AadiTech Client ',contactPerson:'Owner',email:'a@example.in',phone:'1234567890',city:'Mumbai',state:'Maharashtra'});
  assert.equal(good.name,'AadiTech Client');
  assert.throws(()=>validate('customers',{...good,currentOutstanding:123}),InputError);
  assert.throws(()=>validate('customers',{...good,role:'OWNER'}),InputError);
});
test('Lead source and score are strict; qualification ranges enforced',()=>{
  const lead={name:'X',company:'ABC',email:'x@example.in',phone:'1234567890',source:'WEBSITE',requirement:'20 laptops'};
  assert.equal(validate('leads',{...lead,intentScore:100}).intentScore,100);
  assert.throws(()=>validate('leads',{...lead,intentScore:101}),InputError);
  assert.throws(()=>validate('leads',{...lead,source:'UNVERIFIED'}),InputError);
  assert.throws(()=>validate('leads',{...lead,estimatedBudget:10000}),InputError);
});
test('Product amounts must be fixed-precision strings; inventory fields cannot be forged',()=>{
  const p={sku:'A-01',brand:'Dell',model:'R760',category:'SERVER',specs:'Xeon',unitCost:'10000.00',sellingPrice:'15000.00',minPrice:'12000.00',hsn:'8471'};
  assert.equal(validate('products',p).unitCost,'10000.00');
  assert.throws(()=>validate('products',{...p,stockBhiwandi:300}),InputError);
  assert.throws(()=>validate('products',{...p,sellingPrice:'11000'}),InputError);
  assert.throws(()=>validate('products',{...p,unitCost:-3}),InputError);
});
test('Patches require specific fields; paging and optimistic version validated',()=>{
  assert.equal(validate('leads',{status:'QUALIFIED'},true).status,'QUALIFIED');
  assert.throws(()=>validate('leads',{},true),InputError);
  assert.throws(()=>validate('customers',{deleted_at:'2026-01-01'},true),InputError);
  assert.deepEqual(parsePagination({page:'2',limit:'10'}),{page:2,limit:10,offset:10});
  assert.throws(()=>parsePagination({limit:'1000'}),InputError);
  assert.equal(parseVersion('3'),3);
  assert.throws(()=>parseVersion(0),InputError);
  assert.equal(validId('a51bb03b-1ea8-40a6-aafb-123456789abc'),true);
  assert.equal(validId('1 OR 1=1'),false);
});
