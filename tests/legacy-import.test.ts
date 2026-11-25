import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLegacyBackup } from '../src/services/legacyImport';

const row = { id:'LEAD-A-001', name:'Ravi', company:'ACME Hardware', email:'ravi@acme.in',
  phone:'9876543210', source:'EMAIL', requirement:'Ten workstations', estimatedBudget:150000 };
const pack = (rows:unknown[]) => JSON.stringify({format:'aaditech-legacy-browser-backup-v1',
  exportedAt:'2026-11-06T00:00:00.000Z',data:{aaditech_leads:rows}});

test('preview is read-only, preserves source ID but strips financial and authority fields',()=>{
  const before=JSON.stringify(row);
  const result=parseLegacyBackup(pack([{...row,creditLimit:900000,stockBhiwandi:40}]));
  assert.equal(result.candidates.length,1);
  const item=result.candidates[0];
  assert.equal(item.sourceId,'LEAD-A-001');
  assert.equal(item.fields.estimatedBudget,'150000');
  assert.equal(item.fields.email,'ravi@acme.in');
  assert.equal('creditLimit' in item.fields,false);
  assert.equal('stockBhiwandi' in item.fields,false);
  assert.equal(JSON.stringify(row),before);
});
test('duplicate emails in backup and in loaded MySQL data are flagged',()=>{
  const existing={leads:[{id:'db',email:'ravi@acme.in',version:1}]};
  const result=parseLegacyBackup(pack([row,{...row,id:'LEAD-A-002',email:'RAVI@ACME.IN'}]),existing);
  assert.equal(result.candidates[0].duplicate,true);
  assert.equal(result.candidates[1].duplicate,true);
  assert.ok(result.candidates[1].issues.some(x=>x.includes('Repeated')));
});
test('generated placeholders and missing required fields are blocked from instant review',()=>{
  const result=parseLegacyBackup(pack([{...row,email:'procurement@company.in'},
    {...row,id:'',name:''}]));
  assert.ok(result.candidates[0].issues.some(x=>x.includes('demo/default')));
  assert.ok(result.candidates[1].issues.some(x=>x.includes('Missing original')));
  assert.ok(result.invalid>=1);
});
test('invalid formats, object payloads, excessive records and sizes are rejected',()=>{
  assert.throws(()=>parseLegacyBackup('{bad'),/Invalid JSON/);
  assert.throws(()=>parseLegacyBackup(JSON.stringify({data:{aaditech_leads:[]}})),/Unsupported/);
  assert.throws(()=>parseLegacyBackup(JSON.stringify({format:'aaditech-legacy-browser-backup-v1',data:{aaditech_leads:{}}})),/Expected an array/);
  assert.throws(()=>parseLegacyBackup(pack(Array.from({length:301},()=>row))),/more than 300/);
  assert.throws(()=>parseLegacyBackup(' '.repeat(2*1024*1024+1)),/2 MB/);
});
