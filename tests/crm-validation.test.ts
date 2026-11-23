import test from 'node:test';
import assert from 'node:assert/strict';
import { InputError, crmMoneyPaise, isMinPriceAboveSellingPrice, parsePagination,parseVersion,validate } from '../server/crm/validation';
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
test('1FI exact paise prevents large DECIMAL(18,2) product price-floor rounding bypass',()=>{
 const p={sku:'FI-DECIMAL',brand:'Example',model:'Precision test',category:'SERVER',
  specs:'Synthetic fixture',unitCost:'0.01',minPrice:'9007199254740992.01',
  sellingPrice:'9007199254740992.02',hsn:'8471'};
 assert.equal(crmMoneyPaise('9007199254740992.01'),900719925474099201n);
 assert.equal(crmMoneyPaise('9999999999999999.99'),999999999999999999n);
 assert.equal(crmMoneyPaise('0'),0n);
 assert.equal(crmMoneyPaise('0.1'),10n);
 assert.equal(isMinPriceAboveSellingPrice('9007199254740992.01','9007199254740992.00'),true);
 assert.equal(isMinPriceAboveSellingPrice('9007199254740992.01','9007199254740992.01'),false);
 assert.equal(validate('products',p).minPrice,'9007199254740992.01');
 assert.throws(()=>validate('products',{...p,sellingPrice:'9007199254740992.00'}),/minPrice cannot exceed sellingPrice/);
 assert.throws(()=>validate('products',{...p,minPrice:'9007199254740992.03'}),/minPrice cannot exceed sellingPrice/);
 for(const value of ['1e3','01.00','-1.00','0.001','10000000000000000.00','',123,null])
  assert.throws(()=>crmMoneyPaise(value),InputError);
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
