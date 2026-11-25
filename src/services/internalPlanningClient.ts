import {authenticatedFetch} from './authClient';
import {summarizePlanningResult} from './internalPlanningResults';
export type PlanningResult=Record<string,unknown>;
export type PlanningRecord={id:string;module:string;createdAt:string;result:PlanningResult;replayed?:boolean};
function verify(value:unknown,module:string):PlanningResult{
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('Invalid planning response');
 const v=value as PlanningResult;
 if(v.module!==module||v.releaseDecision!=='HOLD'||v.externalExecutionEnabled!==false||v.productionReleaseAuthorized!==false||v.requiresHumanReview!==true||v.evidenceStatus!=='OPERATOR_SUPPLIED_UNVERIFIED')throw Error('Unverified planning response');summarizePlanningResult(module,v);return v;
}
async function call(path:string,init:RequestInit={}):Promise<unknown>{const response=await authenticatedFetch('/api/internal-planning'+path,init);if(!response.ok)throw Error('Planning request failed (HTTP '+response.status+'). No external action authorized.');return response.json();}
function record(value:unknown,module?:string):PlanningRecord{
 if(!value||typeof value!=='object')throw Error('Invalid record response');const v=value as PlanningRecord;
 if(typeof v.id!=='string'||typeof v.module!=='string'||typeof v.createdAt!=='string'||(module&&v.module!==module))throw Error('Invalid record response');verify(v.result,v.module);return v;
}
export const internalPlanningClient={
 async catalog(){const v=await call('/') as {modules?:unknown;persistenceEnabled?:unknown;releaseDecision?:unknown;externalExecutionEnabled?:unknown;productionReleaseAuthorized?:unknown};if(!v||!Array.isArray(v.modules)||v.releaseDecision!=='HOLD'||v.externalExecutionEnabled!==false||v.productionReleaseAuthorized!==false||typeof v.persistenceEnabled!=='boolean')throw Error('Invalid planning catalog');return {modules:v.modules.filter((x):x is string=>typeof x==='string'),persistenceEnabled:v.persistenceEnabled};},
 async evaluate(module:string,input:unknown){return verify(await call('/'+encodeURIComponent(module),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)}),module);},
 async save(module:string,input:unknown,key:string){return record(await call('/records/'+encodeURIComponent(module),{method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':key},body:JSON.stringify(input)}),module);},
 async list(){const v=await call('/records') as {items?:unknown;releaseDecision?:unknown;externalExecutionEnabled?:unknown};if(!v||!Array.isArray(v.items)||v.releaseDecision!=='HOLD'||v.externalExecutionEnabled!==false)throw Error('Invalid record list');return v.items.map(x=>record(x));},
 async read(id:string){return record(await call('/records/'+encodeURIComponent(id)));}
};
