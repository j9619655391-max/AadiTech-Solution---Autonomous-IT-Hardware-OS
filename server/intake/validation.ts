import {createHash} from 'node:crypto';
import {inventoryId} from '../inventory/validation';
import {evidenceRef} from '../procurement/validation';

export class IntakeInputError extends Error {}
export class IntakeConflictError extends Error {}
function object(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new IntakeInputError('Object required');
 const value=raw as Record<string,unknown>;
 const got=Object.keys(value).sort(),expected=keys.slice().sort();
 if(got.length!==expected.length||got.some((key,i)=>key!==expected[i]))
  throw new IntakeInputError('Missing or unsupported intake fields');
 return value;
}
function evidence(input:unknown){
 try{return evidenceRef(input);}catch{throw new IntakeInputError('Valid non-sensitive evidence ticket ID required');}
}
const serialPattern=/^[A-Z0-9][A-Z0-9_-]{5,79}$/;
const lotPattern=/^[A-Z0-9][A-Z0-9_-]{3,79}$/;
export type IntakeLine={productId:string;quantity:number;trackingMode:'SERIAL'|'LOT';lotCode:string|null;serialNumbers:string[]};
export function validateInbound(raw:unknown){
 const v=object(raw,['holdId','deliveryEvidenceRef','physicalCountRef','items']);
 if(!inventoryId(v.holdId))throw new IntakeInputError('Valid held PO ID required');
 const deliveryEvidenceRef=evidence(v.deliveryEvidenceRef),physicalCountRef=evidence(v.physicalCountRef);
 if(!Array.isArray(v.items)||v.items.length<1||v.items.length>25)
  throw new IntakeInputError('1–25 recorded lines required');
 const seen=new Set<string>(),serialsGlobal=new Set<string>(),items:IntakeLine[]=[];
 for(const rawLine of v.items){
  const l=object(rawLine,['productId','quantity','trackingMode','lotCode','serialNumbers']);
  if(!inventoryId(l.productId)||seen.has(l.productId))
   throw new IntakeInputError('Distinct valid product ID required');
  seen.add(l.productId);
  if(typeof l.quantity!=='number'||!Number.isSafeInteger(l.quantity)||l.quantity<1||l.quantity>1000)
   throw new IntakeInputError('Quantity must be integer 1–1000');
  if(l.trackingMode!=='SERIAL'&&l.trackingMode!=='LOT')
   throw new IntakeInputError('Tracking mode must be SERIAL or LOT');
  if(!Array.isArray(l.serialNumbers))
   throw new IntakeInputError('Serial number array required');
  if(l.trackingMode==='SERIAL'){
   if(l.lotCode!==null||l.serialNumbers.length!==l.quantity)
    throw new IntakeInputError('Serialized items require exactly one serial per counted unit');
   const serialNumbers:string[]=[];
   for(const serial of l.serialNumbers){
    if(typeof serial!=='string'||!serialPattern.test(serial)||serialsGlobal.has(serial))
     throw new IntakeInputError('Serial invalid, duplicated, or not normalized uppercase');
    serialNumbers.push(serial);serialsGlobal.add(serial);
   }
   items.push({productId:l.productId,quantity:l.quantity,trackingMode:'SERIAL',
    lotCode:null,serialNumbers});
  }else{
   if(typeof l.lotCode!=='string'||!lotPattern.test(l.lotCode)||l.serialNumbers.length!==0)
    throw new IntakeInputError('Lot items require normalized lot code and empty serial array');
   items.push({productId:l.productId,quantity:l.quantity,trackingMode:'LOT',
    lotCode:l.lotCode,serialNumbers:[]});
  }
 }
 return {holdId:v.holdId,deliveryEvidenceRef,physicalCountRef,items};
}
export function validateWitness(raw:unknown){
 const v=object(raw,['outcome','reason','inspectionEvidenceRef','physicallyInspected']);
 if(v.outcome!=='ACCEPT_QUARANTINE'&&v.outcome!=='REJECT_INTERNAL')
  throw new IntakeInputError('Invalid witness decision');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new IntakeInputError('Inspection reason must be 12–1000 characters');
 if(v.physicallyInspected!==true&&v.physicallyInspected!==false)
  throw new IntakeInputError('Explicit inspection attestation required');
 if(v.outcome==='ACCEPT_QUARANTINE'&&v.physicallyInspected!==true)
  throw new IntakeInputError('Cannot quarantine-accept without independent inspection');
 return {outcome:v.outcome as 'ACCEPT_QUARANTINE'|'REJECT_INTERNAL',
  reason:v.reason.trim(),inspectionEvidenceRef:evidence(v.inspectionEvidenceRef),
  physicallyInspected:v.physicallyInspected};
}
export function canonicalIntakeHash(payload:ReturnType<typeof validateInbound>){
 return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}
export function reconstructHoldHash(value:unknown):string{
 if(!value||typeof value!=='object'||Array.isArray(value))
  throw new IntakeConflictError('Missing immutable PO snapshot');
 const raw=value as Record<string,unknown>;
 if(raw.format!=='aaditech-internal-po-hold-v1'||!Array.isArray(raw.lines)||raw.lines.length<1||
    raw.lines.length>25)throw new IntakeConflictError('Unsupported PO hold snapshot');
 const lines=raw.lines.map(rawLine=>{
  if(!rawLine||typeof rawLine!=='object'||Array.isArray(rawLine))
   throw new IntakeConflictError('Invalid PO line snapshot');
  const l=rawLine as Record<string,unknown>;
  if(!inventoryId(l.productId)||typeof l.sku!=='string'||typeof l.name!=='string'||
    typeof l.quantity!=='number'||!Number.isSafeInteger(l.quantity)||l.quantity<1||
    typeof l.quotedUnitCost!=='string'||typeof l.lineSubtotal!=='string')
   throw new IntakeConflictError('Invalid PO line snapshot');
  return {productId:l.productId,sku:l.sku,name:l.name,quantity:l.quantity,
   quotedUnitCost:l.quotedUnitCost,lineSubtotal:l.lineSubtotal};
 });
 for(const field of ['requestId','supplierId','siteId','reviewId']){
  if(!inventoryId(raw[field]))throw new IntakeConflictError('Invalid PO hold identity');
 }
 for(const field of ['supplierCode','supplierName','supplierQuoteEvidenceRef','subtotal']){
  if(typeof raw[field]!=='string')throw new IntakeConflictError('Invalid PO hold commercial snapshot');
 }
 // Reconstruct Phase 1AC's original key order: MySQL JSON reorders keys at rest.
 return createHash('sha256').update(JSON.stringify({
  format:raw.format,requestId:raw.requestId,supplierId:raw.supplierId,
  supplierCode:raw.supplierCode,supplierName:raw.supplierName,siteId:raw.siteId,
  supplierQuoteEvidenceRef:raw.supplierQuoteEvidenceRef,subtotal:raw.subtotal,
  reviewId:raw.reviewId,lines
 })).digest('hex');
}
