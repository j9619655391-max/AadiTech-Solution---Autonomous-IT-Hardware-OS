import test from 'node:test';
import assert from 'node:assert/strict';
import { crmFields, CRMRecordToForm, prepareCRMFields } from '../src/services/crmFields';

test('customer create form requires real contact data and does not fabricate values', () => {
  const input = { name: 'Example Buyer', contactPerson: 'Anita', email: 'a@example.in', phone: '1234567890', city: 'Mumbai', state: 'Maharashtra' };
  const payload = prepareCRMFields('customers', input);
  assert.deepEqual(payload, input);
  assert.equal('creditLimit' in payload, false);
  assert.throws(() => prepareCRMFields('customers', { ...input, email: '' }), /required/);
});

test('lead money remains decimal string and optional values can remain absent', () => {
  const input = { name: 'Contact', company: 'Company', email: 'c@example.in', phone: '12345', source: 'EMAIL', requirement: 'Server', estimatedBudget: '125000.50', intentScore: '42' };
  const output = prepareCRMFields('leads', input);
  assert.equal(output.estimatedBudget, '125000.50');
  assert.equal(output.intentScore, 42);
  assert.equal('gstin' in output, false);
  assert.throws(() => prepareCRMFields('leads', { ...input, estimatedBudget: '12.333' }), /two decimals/);
});

test('product entry excludes stock and credit fields; edit form maps backend record', () => {
  const record = { id: 'id', version: 3, sku: 'SKU-1', brand: 'Dell', model: 'Test', category: 'SERVER', specs: 'CPU', unitCost: '100.00', sellingPrice: '150.00', minPrice: '120.00', hsn: '8471', stockBhiwandi: 25 };
  const draft = CRMRecordToForm('products', record);
  const input = prepareCRMFields('products', draft, true);
  assert.equal(input.sku, 'SKU-1');
  assert.equal(input.unitCost, '100.00');
  assert.equal('stockBhiwandi' in input, false);
  assert.equal(crmFields.products.some(f => f.key === 'reservedStock'), false);
});
