import test from 'node:test';
import assert from 'node:assert/strict';
import {planningCatalog} from '../src/services/internalPlanningCatalog';
import {evaluateInternalPlan} from '../server/internalPlanning/planners';
import {summarizePlanningResult,comparePlanningResults,GX_MODULES} from '../src/services/internalPlanningResults';
const invalid:Record<string,[string,unknown]>={
  "M05": [
    "estimatedTotal",
    "0.01"
  ],
  "M13": [
    "remaining",
    999
  ],
  "M14": [
    "unmatchedAmount",
    "1.00"
  ],
  "M15": [
    "purchaseEvidencePresent",
    false
  ],
  "M18": [
    "proposedFields",
    [
      "supportReference"
    ]
  ],
  "M19": [
    "priceComparison",
    "BELOW_DECLARED_FLOOR"
  ],
  "M20": [
    "cappedEstimate",
    "91.00"
  ],
  "M21": [
    "declaredMatchCount",
    0
  ],
  "M22": [
    "classification",
    "EXTERNAL_ACTION_BLOCKED"
  ],
  "M23": [
    "scenarioTotalUnits",
    999
  ],
  "M24": [
    "scenarioDelaySeconds",
    null
  ],
  "M25": [
    "sha256",
    "x"
  ]
};
for(const item of planningCatalog){
 const id=item.id,actual=evaluateInternalPlan(id,item.example);
 test('1GX '+id+'-01 structured result and evidence requirements',()=>{
  const v=summarizePlanningResult(id,actual);assert.equal(v.module,id);assert.equal(v.releaseDecision,'HOLD');assert.ok(v.metrics.length>0);assert.ok(v.blockers.every(x=>x.description.length>0));
 });
 test('1GX '+id+'-02 missing metric fails closed',()=>{
  const value={...actual} as Record<string,unknown>,key=summarizePlanningResult(id,actual).metrics[0].key;delete value[key];assert.throws(()=>summarizePlanningResult(id,value),/Invalid held/);
 });
 test('1GX '+id+'-03 inconsistent result rejected',()=>{
  const [key,value]=invalid[id];assert.throws(()=>summarizePlanningResult(id,{...actual,[key]:value}),/Invalid held/);
 });
 test('1GX '+id+'-04 missing or unknown evidence requirement rejected',()=>{
  for(const blockers of [[],['UNRECOGNIZED_REQUIREMENT']])assert.throws(()=>summarizePlanningResult(id,{...actual,blockers}),/Invalid held/);
 });
 test('1GX '+id+'-05 identical scenario comparison remains held',()=>{
  const result=comparePlanningResults(id,actual,actual);assert.ok(result.metrics.every(x=>!x.changed));assert.equal(result.detailChanged,false);assert.equal(result.blockersChanged,false);assert.equal(result.releaseDecision,'HOLD');
 });
}
test('1GX complete catalog and cross-module comparison denied',()=>{
 assert.deepEqual(GX_MODULES,planningCatalog.map(x=>x.id));
 const a=evaluateInternalPlan('M05',planningCatalog[0].example),b=evaluateInternalPlan('M13',planningCatalog[1].example);
 assert.throws(()=>comparePlanningResults('M05',a,b),/Invalid held/);
});
test('1GX payment comparison identifies changed scenario metrics',()=>{
 const x=planningCatalog.find(v=>v.id==='M14')!.example;
 const a=evaluateInternalPlan('M14',x),b=evaluateInternalPlan('M14',{...x,receivedAmount:'50'});
 const c=comparePlanningResults('M14',a,b);assert.deepEqual(c.metrics.filter(v=>v.changed).map(v=>v.label),['Received amount','Comparison','Unmatched amount']);
});
test('1GX warranty comparison identifies changed evidence requirement',()=>{
 const x=planningCatalog.find(v=>v.id==='M15')!.example;
 const a=evaluateInternalPlan('M15',x),b=evaluateInternalPlan('M15',{...x,purchaseEvidencePresent:false});assert.equal(comparePlanningResults('M15',a,b).blockersChanged,true);
});
test('1GX line detail changes and non-HOLD responses rejected',()=>{
 const a=evaluateInternalPlan('M05',planningCatalog[0].example),b=evaluateInternalPlan('M05',{lines:[{sku:'S2',quantity:2,unitPrice:'100.00',gstRate:'18.00'}],discount:'10.00'});
 assert.equal(comparePlanningResults('M05',a,b).detailChanged,true);
 for(const patch of [{releaseDecision:'APPROVED'},{externalExecutionEnabled:true},{productionReleaseAuthorized:true},{requiresHumanReview:false}])assert.throws(()=>summarizePlanningResult('M05',{...a,...patch}),/Invalid held/);
});
