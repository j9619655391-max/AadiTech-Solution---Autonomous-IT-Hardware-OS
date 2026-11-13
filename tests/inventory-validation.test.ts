import test from 'node:test';
import assert from 'node:assert/strict';
import {validateSite,validateOpeningCount,openingRequestHash} from '../server/inventory/validation';

const productId='11111111-1111-4111-8111-111111111111';
const siteId='22222222-2222-4222-8222-222222222222';
test('warehouse site requires explicit valid code and name',()=>{
 assert.deepEqual(validateSite({code:'WH_A',name:' Verified warehouse '}),{
  code:'WH_A',name:'Verified warehouse'});
 for(const code of ['a','aa','WH SITE','x'.repeat(33),'__','W!'])
  assert.throws(()=>validateSite({code,name:'Warehouse'}));
 assert.throws(()=>validateSite({code:'WH_A',name:'Warehouse',approved:true}));
});
test('opening counts accept zero, reject negative/fractional/implicit evidence',()=>{
 const input={productId,siteId,quantity:0,evidenceRef:'COUNT-2026-0001'};
 assert.deepEqual(validateOpeningCount(input),input);
 for(const quantity of [-1,0.5,1000001,'1',Infinity,NaN])
  assert.throws(()=>validateOpeningCount({...input,quantity}));
 for(const evidenceRef of ['','count','secret value','a'.repeat(161)])
  assert.throws(()=>validateOpeningCount({...input,evidenceRef}));
 assert.throws(()=>validateOpeningCount({...input,availableToSell:100}));
 assert.throws(()=>validateOpeningCount({...input,siteId:'invalid'}));
});
test('idempotency hash includes exact product, site, quantity and evidence',()=>{
 const base=validateOpeningCount({productId,siteId,quantity:9,evidenceRef:'COUNT-2026-0001'});
 const hash=openingRequestHash(base);
 assert.match(hash,/^[a-f0-9]{64}$/);
 assert.equal(hash,openingRequestHash({...base}));
 assert.notEqual(hash,openingRequestHash({...base,quantity:10}));
 assert.notEqual(hash,openingRequestHash({...base,evidenceRef:'COUNT-2026-0002'}));
});
