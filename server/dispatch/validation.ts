import {createHash} from 'node:crypto';
import {inventoryId} from '../inventory/validation';
import {evidenceRef} from '../procurement/validation';
export class DispatchInputError extends Error {}
export class DispatchConflictError extends Error {}
function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new DispatchInputError('JSON object required');
 const v=raw as Record<string,unknown>,a=Object.keys(v).sort(),b=keys.slice().sort();
 if(a.length!==b.length||a.some((x,i)=>x!==b[i]))throw new DispatchInputError('Missing or unsupported fields');
 return v;
}
export function reference(x:unknown):string{
 try{return evidenceRef(x);}catch{throw new DispatchInputError('Non-sensitive evidence ticket required');}
}
export function supplierEmail(input:unknown):string{
 if(typeof input!=='string'||input.length>254||input!==input.trim()||
   /[^\x21-\x7E]/.test(input)||input.includes('..')||input.includes('=')||
   input.includes('%')||input.includes('+')||input.includes('!'))
  throw new DispatchInputError('Normalized supplier email required');
 const email=input.toLowerCase();
 if(email!==input||!/^[a-z0-9](?:[a-z0-9._-]{0,62})@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(email))
  throw new DispatchInputError('Lowercase ASCII supplier email required');
 return email;
}
export function validateDestination(raw:unknown){
 const v=exact(raw,['supplierId','email','evidenceRef']);
 if(!inventoryId(v.supplierId))throw new DispatchInputError('Valid supplier ID required');
 return {supplierId:v.supplierId as string,email:supplierEmail(v.email),
  evidenceRef:reference(v.evidenceRef)};
}
export function validateDestinationReview(raw:unknown){
 const v=exact(raw,['decision','evidenceRef','reason','identityAttested']);
 if(!['REVIEWED_INTERNAL','REJECTED_INTERNAL'].includes(String(v.decision)))
  throw new DispatchInputError('Valid internal destination review required');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new DispatchInputError('Detailed reason 12–1000 characters required');
 if(typeof v.identityAttested!=='boolean'||(v.decision==='REVIEWED_INTERNAL'&&!v.identityAttested))
  throw new DispatchInputError('Explicit destination identity attestation required');
 return {decision:v.decision as 'REVIEWED_INTERNAL'|'REJECTED_INTERNAL',
  evidenceRef:reference(v.evidenceRef),reason:v.reason.trim(),identityAttested:v.identityAttested};
}
export function validatePreparation(raw:unknown){
 const v=exact(raw,['holdId','destinationId','authorizationEvidenceRef']);
 if(!inventoryId(v.holdId)||!inventoryId(v.destinationId))
  throw new DispatchInputError('Valid internal hold and destination IDs required');
 return {holdId:v.holdId as string,destinationId:v.destinationId as string,
  authorizationEvidenceRef:reference(v.authorizationEvidenceRef)};
}
export function validateDispatchReview(raw:unknown){
 const v=exact(raw,['decision','reason','evidenceRef','destinationAttested']);
 if(v.decision!=='APPROVED_INTERNAL'&&v.decision!=='REJECTED_INTERNAL')
  throw new DispatchInputError('Internal decision required');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new DispatchInputError('Detailed review justification required');
 if(typeof v.destinationAttested!=='boolean'||(v.decision==='APPROVED_INTERNAL'&&!v.destinationAttested))
  throw new DispatchInputError('Internal approval requires destination attestation');
 return {decision:v.decision as 'APPROVED_INTERNAL'|'REJECTED_INTERNAL',reason:v.reason.trim(),
  evidenceRef:reference(v.evidenceRef),destinationAttested:v.destinationAttested};
}
export function sha(value:string){return createHash('sha256').update(value).digest('hex');}
export function dispatchManifest(source:{holdId:string;holdSha256:string;
 destinationId:string;supplierId:string;email:string;authorizationEvidenceRef:string}){
 return {format:'aaditech-po-dispatch-HELD-v1',holdId:source.holdId,
  holdSha256:source.holdSha256,destinationId:source.destinationId,
  supplierId:source.supplierId,email:source.email,
  authorizationEvidenceRef:source.authorizationEvidenceRef,
  externalOrderIssued:false,dispatchState:'DISABLED'} as const;
}
export function verifyManifestJson(stored:unknown,digest:string){
 let raw:unknown=stored;
 if(typeof raw==='string'){try{raw=JSON.parse(raw);}catch{throw new DispatchConflictError('Corrupt dispatch manifest');}}
 if(!raw||typeof raw!=='object'||Array.isArray(raw))
  throw new DispatchConflictError('Missing dispatch manifest');
 const v=raw as Record<string,unknown>;
 const source={holdId:v.holdId,holdSha256:v.holdSha256,destinationId:v.destinationId,
  supplierId:v.supplierId,email:v.email,authorizationEvidenceRef:v.authorizationEvidenceRef};
 if(!inventoryId(source.holdId)||!inventoryId(source.destinationId)||!inventoryId(source.supplierId)||
  typeof source.holdSha256!=='string'||!/^[a-f0-9]{64}$/.test(source.holdSha256)||
  typeof source.authorizationEvidenceRef!=='string'||typeof source.email!=='string')
  throw new DispatchConflictError('Invalid dispatch manifest properties');
 let canonical:ReturnType<typeof dispatchManifest>;
 try{canonical=dispatchManifest(source as Parameters<typeof dispatchManifest>[0]);
  supplierEmail(source.email);reference(source.authorizationEvidenceRef);
 }catch{throw new DispatchConflictError('Invalid dispatch manifest schema');}
 if(Object.keys(v).length!==Object.keys(canonical).length||
  Object.entries(canonical).some(([k,value])=>v[k]!==value)||
  sha(JSON.stringify(canonical))!==digest)
  throw new DispatchConflictError('Dispatch manifest digest mismatch');
 return canonical;
}
