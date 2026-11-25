import test from 'node:test';
import assert from 'node:assert/strict';
import {planningCatalog} from '../src/services/internalPlanningCatalog';
import {formSchemas,blankForm,exampleForm,encodeForm} from '../src/services/internalPlanningForms';
import {evaluateInternalPlan} from '../server/internalPlanning/planners';
for(const {id,example} of planningCatalog){
 const first=formSchemas[id][0].key;
 test('1GW '+id+'-01 example roundtrip',()=>{assert.deepEqual(encodeForm(id,exampleForm(id,example)),example);});
 test('1GW '+id+'-02 planner parity',()=>{assert.deepEqual(evaluateInternalPlan(id,encodeForm(id,exampleForm(id,example))),evaluateInternalPlan(id,example));});
 test('1GW '+id+'-03 blank form rejected',()=>{assert.throws(()=>encodeForm(id,blankForm(id)));});
 test('1GW '+id+'-04 missing field rejected',()=>{const x=exampleForm(id,example);delete x[first];assert.throws(()=>encodeForm(id,x));});
 test('1GW '+id+'-05 wrong field type rejected',()=>{assert.throws(()=>encodeForm(id,{...exampleForm(id,example),[first]:null}));});
}
test('1GW catalog coverage and unsupported module',()=>{assert.deepEqual(Object.keys(formSchemas),planningCatalog.map(x=>x.id));assert.throws(()=>blankForm('M30'));});
test('1GW repeated row bounds',()=>{const a=exampleForm('M05',planningCatalog[0].example);assert.throws(()=>encodeForm('M05',{...a,lines:[]}));assert.throws(()=>encodeForm('M05',{...a,lines:Array(41).fill((a.lines as unknown[])[0])}));});
test('1GW multi-choice duplicate and unsupported fields',()=>{const a=exampleForm('M18',planningCatalog.find(x=>x.id==='M18')!.example);assert.throws(()=>encodeForm('M18',{...a,requestedFields:['status','status']}));assert.throws(()=>encodeForm('M18',{...a,requestedFields:['privateField']}));});
