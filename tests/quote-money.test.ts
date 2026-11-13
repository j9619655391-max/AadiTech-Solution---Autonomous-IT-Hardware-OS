import test from 'node:test';
import assert from 'node:assert/strict';
import {paise,rupees,calculateLine,QuoteInputError} from '../server/quotes/money';

test('paise integer conversion preserves exact two decimal precision',()=>{
  assert.equal(paise('199.99'),19999n);
  assert.equal(rupees(19999n),'199.99');
  assert.equal(rupees(0n),'0.00');
  assert.throws(()=>paise('5.001'),QuoteInputError);
  assert.throws(()=>paise('-5'),QuoteInputError);
});
test('line computation uses stored prices and rounds estimated GST to paise',()=>{
  const l=calculateLine('100.01',3,'18.00');
  assert.equal(rupees(l.subtotal),'300.03');
  assert.equal(rupees(l.tax),'54.01');
  assert.throws(()=>calculateLine('10.00',0,'18.00'),QuoteInputError);
  assert.throws(()=>calculateLine('10.00',2,'101.00'),QuoteInputError);
});
