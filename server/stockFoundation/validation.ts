import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
import {sha} from '../dispatch/validation';
export {ChainInputError,ChainConflictError};
export function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainInputError('Exact JSON object required');
 const x=raw as Record<string,unknown>;
 if(Object.keys(x).sort().join('|')!==keys.slice().sort().join('|'))
  throw new ChainInputError('Unsupported or missing stock foundation fields');
 return x;
}
export function releaseInput(raw:unknown){
 const x=exact(raw,['heldGrnId']);
 if(!inventoryId(x.heldGrnId))throw new ChainInputError('Valid HELD GRN evidence ID required');
 return {heldGrnId:x.heldGrnId as string};
}
export function releaseDecisionInput(raw:unknown){
 const x=exact(raw,['decision','reason','evidenceRef','sourceInspected']);
 if(x.decision!=='REVIEWED_HELD'&&x.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Internal release decision required');
 if(typeof x.reason!=='string'||x.reason.trim().length<12||x.reason.trim().length>1000)
  throw new ChainInputError('Written reason 12–1000 characters required');
 if(typeof x.sourceInspected!=='boolean'||(x.decision==='REVIEWED_HELD'&&!x.sourceInspected))
  throw new ChainInputError('Reviewer must inspect internal source before HELD acceptance');
 return {decision:x.decision as 'REVIEWED_HELD'|'REJECTED_INTERNAL',
  reason:x.reason.trim(),evidenceRef:chainEvidence(x.evidenceRef),
  sourceInspected:x.sourceInspected};
}
export function planInput(raw:unknown){
 const x=exact(raw,['releaseIntentId','productId','quantity','planningRef']);
 if(!inventoryId(x.releaseIntentId)||!inventoryId(x.productId))
  throw new ChainInputError('Valid release intent and product IDs required');
 if(typeof x.quantity!=='number'||!Number.isSafeInteger(x.quantity)||
  x.quantity<1||x.quantity>1000)
  throw new ChainInputError('Positive planning quantity 1–1000 required');
 return {releaseIntentId:x.releaseIntentId as string,productId:x.productId as string,
  quantity:x.quantity,planningRef:chainEvidence(x.planningRef)};
}
export type ReleaseLine={productId:string;quantity:number;trackingMode:'SERIAL'|'LOT';
 lotCode:string|null;serialNumbers:string[]};
export type ReleaseSource={heldGrnId:string;heldGrnSha256:string;
 observationId:string;siteId:string;ownerId:string;holdId:string;lines:ReleaseLine[]};
export function releaseSnapshot(source:ReleaseSource){
 return {format:'aaditech-inventory-release-HELD-v1',
  heldGrnId:source.heldGrnId,heldGrnSha256:source.heldGrnSha256,
  observationId:source.observationId,holdId:source.holdId,siteId:source.siteId,
  lines:source.lines.map(l=>({productId:l.productId,quantity:l.quantity,
   trackingMode:l.trackingMode,lotCode:l.lotCode,serialNumbers:[...l.serialNumbers].sort()})),
  postingState:'DISABLED',stockPosted:false,availableToSell:null} as const;
}
export function releaseHoldSnapshot(intentId:string,digest:string,decisionId:string){
 return {format:'aaditech-release-outbox-HELD-v1',releaseIntentId:intentId,
  intentSha256:digest,decisionId,postingState:'DISABLED',stockPosted:false};
}
export function planDigest(p:ReturnType<typeof planInput>,sourceSha:string,siteId:string){
 return sha(JSON.stringify({format:'aaditech-nonallocating-reservation-plan-v1',
  releaseIntentId:p.releaseIntentId,productId:p.productId,requestedQuantity:p.quantity,
  planningRef:p.planningRef,releaseSha256:sourceSha,siteId,
  reservationState:'DISABLED',allocatedQuantity:0}));
}
export function noNegativeProjection(input:{available:number;reserved:number;
 picked:number;posted:number;request:number}){
 const values=Object.values(input);
 if(values.some(v=>!Number.isSafeInteger(v)||v<0))throw new ChainInputError('Non-negative safe integer quantities only');
 if(input.reserved+input.picked>input.posted||input.available+input.reserved+input.picked!==input.posted)
  throw new ChainConflictError('Stock projection does not balance');
 if(input.request>input.available)
  throw new ChainConflictError('Insufficient available stock; negative projection denied');
 return {remaining:input.available-input.request};
}
export function rejectLiveAllocation(requested:number){
 // 1AG has no verified stock receipt source and no live availability authority.
 // This is intentionally invoked even for a user-visible, internally reviewed HELD plan.
 return noNegativeProjection({available:0,reserved:0,picked:0,posted:0,request:requested});
}

/** Deep JSON equality: unordered object keys, ordered arrays and exact primitive values.
 *  Only trusted, re-constructed canonical snapshots may be passed as expected. */
function jsonEquals(actual:unknown,expected:unknown):boolean{
 if(actual===expected)return true;
 if(Array.isArray(actual)||Array.isArray(expected)){
  return Array.isArray(actual)&&Array.isArray(expected)&&
   actual.length===expected.length&&
   actual.every((item,index)=>jsonEquals(item,expected[index]));
 }
 if(!actual||!expected||typeof actual!=='object'||typeof expected!=='object')
  return false;
 const a=actual as Record<string,unknown>,b=expected as Record<string,unknown>;
 const keysA=Object.keys(a).sort(),keysB=Object.keys(b).sort();
 return keysA.length===keysB.length&&keysA.every((key,index)=>
  key===keysB[index]&&jsonEquals(a[key],b[key]));
}
export function verifyDeepFrozenSnapshot(raw:unknown,expected:object,digest:string){
 let stored:unknown=raw;
 if(typeof stored==='string'){
  try{stored=JSON.parse(stored);}catch{throw new ChainConflictError('Unparseable stock snapshot');}
 }
 if(!jsonEquals(stored,expected)||sha(JSON.stringify(expected))!==digest)
  throw new ChainConflictError('Nested stock line or snapshot checksum mismatch');
 return expected;
}
