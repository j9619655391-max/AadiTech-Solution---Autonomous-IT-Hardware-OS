import {sha} from '../dispatch/validation';
import {inventoryId} from '../inventory/validation';
import {evidenceRef} from '../procurement/validation';

export class ChainInputError extends Error {}
export class ChainConflictError extends Error {}
function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainInputError('Object required');
 const v=raw as Record<string,unknown>,received=Object.keys(v).sort(),expected=keys.slice().sort();
 if(received.length!==expected.length||received.some((k,i)=>k!==expected[i]))
  throw new ChainInputError('Missing or unsupported evidence fields');
 return v;
}
export function chainEvidence(x:unknown):string{
 try{return evidenceRef(x);}catch{throw new ChainInputError('Non-sensitive evidence reference required');}
}
export function sha256(x:unknown):string{
 if(typeof x!=='string'||!/^[a-f0-9]{64}$/.test(x))
  throw new ChainInputError('Lowercase document SHA-256 required');
 return x;
}
export function validateClaim(raw:unknown){
 const v=exact(raw,['preparationId','supplierAckRef','evidenceRef','documentSha256']);
 if(!inventoryId(v.preparationId))throw new ChainInputError('Valid preparation ID required');
 if(typeof v.supplierAckRef!=='string'||!/^[A-Z0-9][A-Z0-9_-]{7,79}$/.test(v.supplierAckRef))
  throw new ChainInputError('Uppercase supplier-reported reference 8–80 characters required');
 return {preparationId:v.preparationId as string,supplierAckRef:v.supplierAckRef as string,
  evidenceRef:chainEvidence(v.evidenceRef),documentSha256:sha256(v.documentSha256)};
}
export function validateClaimDecision(raw:unknown){
 const v=exact(raw,['decision','reason','reviewEvidenceRef','documentInspected']);
 if(v.decision!=='ATTESTED_INTERNAL'&&v.decision!=='DISPUTED_INTERNAL')
  throw new ChainInputError('Internal claim decision required');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed evidence review reason required');
 if(typeof v.documentInspected!=='boolean'||(v.decision==='ATTESTED_INTERNAL'&&!v.documentInspected))
  throw new ChainInputError('Claim attestation requires document inspection');
 return {decision:v.decision as 'ATTESTED_INTERNAL'|'DISPUTED_INTERNAL',
  reason:v.reason.trim(),reviewEvidenceRef:chainEvidence(v.reviewEvidenceRef),
  documentInspected:v.documentInspected};
}
export function validatePack(raw:unknown){
 const v=exact(raw,['claimId','observationId']);
 if(!inventoryId(v.claimId)||!inventoryId(v.observationId))
  throw new ChainInputError('Valid claim and observation IDs required');
 return {claimId:v.claimId as string,observationId:v.observationId as string};
}
export function validatePackDecision(raw:unknown){
 const v=exact(raw,['decision','reason','reviewEvidenceRef','custodyInspected']);
 if(v.decision!=='HELD_INTERNAL'&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Internal GRN pack decision required');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed GRN review reason required');
 if(typeof v.custodyInspected!=='boolean'||(v.decision==='HELD_INTERNAL'&&!v.custodyInspected))
  throw new ChainInputError('Custody inspection declaration required');
 return {decision:v.decision as 'HELD_INTERNAL'|'REJECTED_INTERNAL',
  reason:v.reason.trim(),reviewEvidenceRef:chainEvidence(v.reviewEvidenceRef),
  custodyInspected:v.custodyInspected};
}
export function claimDigest(c:ReturnType<typeof validateClaim>,outboxSha256:string){
 return sha(JSON.stringify({format:'aaditech-untrusted-supplier-ack-claim-v1',
  preparationId:c.preparationId,supplierAckRef:c.supplierAckRef,evidenceRef:c.evidenceRef,
  documentSha256:c.documentSha256,outboxSha256}));
}
export type GrnPackSnapshot={format:'aaditech-internal-GRN-reconciliation-HELD-v1';
 claimId:string;observationId:string;holdId:string;dispatchPreparationId:string;
 outboxSha256:string;claimSha256:string;observationSha256:string;holdSha256:string;
 quantityTotal:number;lineCount:number;externalPoIssued:false;acknowledgmentVerified:false;
 officialGrnCreated:false;stockPostingState:'DISABLED'};
export function packSnapshot(source:Omit<GrnPackSnapshot,'format'|'externalPoIssued'|'acknowledgmentVerified'|'officialGrnCreated'|'stockPostingState'>):GrnPackSnapshot{
 return {format:'aaditech-internal-GRN-reconciliation-HELD-v1',...source,
  externalPoIssued:false,acknowledgmentVerified:false,officialGrnCreated:false,
  stockPostingState:'DISABLED'};
}
export function normalizedJson(x:unknown):Record<string,unknown>{
 let raw=x;
 if(typeof raw==='string'){try{raw=JSON.parse(raw);}catch{throw new ChainConflictError('Corrupt held JSON');}}
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainConflictError('Invalid held JSON');
 return raw as Record<string,unknown>;
}
export function verifyExactSnapshot<T extends object>(raw:unknown,expected:T,digest:string){
 const v=normalizedJson(raw),canonical=JSON.stringify(expected);
 if(Object.keys(v).length!==Object.keys(expected).length||
  Object.entries(expected).some(([k,value])=>v[k]!==value)||
  sha(canonical)!==digest)
  throw new ChainConflictError('Immutable recorded evidence checksum mismatch');
 return expected;
}
export function verifyOutbox(raw:unknown,digest:string,source:{
 preparationId:string;manifestSha256:string;decisionId:string}){
 const expected={format:'aaditech-supplier-PO-outbox-HELD-v1',
  preparationId:source.preparationId,manifestSha256:source.manifestSha256,
  decisionId:source.decisionId,dispatchState:'DISABLED',externalPoIssued:false};
 return verifyExactSnapshot(raw,expected,digest);
}
export function heldGrnSnapshot(packId:string,packSha256:string,decisionId:string){
 return {format:'aaditech-GRN-reconciliation-outbox-HELD-v1',packId,packSha256,
  decisionId,stockPostingState:'DISABLED',officialGrnCreated:false,availableToSell:null};
}
