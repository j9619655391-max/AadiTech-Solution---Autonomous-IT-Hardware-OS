import {createHash} from 'node:crypto';
import {paise,rupees} from '../quotes/money';
import {inventoryId} from '../inventory/validation';

export class ProcurementInputError extends Error {}
export class ProcurementConflictError extends Error {}
function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))
  throw new ProcurementInputError('Object body required');
 const value=raw as Record<string,unknown>;
 const received=Object.keys(value).sort(),expected=keys.slice().sort();
 if(received.length!==expected.length||received.some((v,i)=>v!==expected[i]))
  throw new ProcurementInputError('Unexpected or missing fields');
 return value;
}
export function evidenceRef(raw:unknown):string{
 if(typeof raw!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:/-]{7,159}$/.test(raw))
  throw new ProcurementInputError('Non-sensitive evidence reference 8–160 characters required');
 return raw;
}
export function validateSupplier(raw:unknown){
 const v=exact(raw,['code','legalName','taxId']);
 if(typeof v.code!=='string'||!/^[A-Z][A-Z0-9_-]{1,31}$/.test(v.code))
  throw new ProcurementInputError('Supplier code 2–32 uppercase characters required');
 if(typeof v.legalName!=='string'||!v.legalName.trim()||v.legalName.trim().length>200)
  throw new ProcurementInputError('Valid legal supplier name required');
 if(v.taxId!==null && (typeof v.taxId!=='string'||!/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(v.taxId.toUpperCase())))
  throw new ProcurementInputError('Valid GSTIN or null required');
 return {code:v.code,legalName:v.legalName.trim(),
  taxId:v.taxId===null?null:(v.taxId as string).toUpperCase()};
}
export function validateSupplierReview(raw:unknown){
 const v=exact(raw,['evidenceRef','attestIdentified']);
 if(v.attestIdentified!==true)
  throw new ProcurementInputError('Explicit supplier identity attestation required');
 return {evidenceRef:evidenceRef(v.evidenceRef)};
}
export type PurchaseLine={productId:string;quantity:number;quotedUnitCost:string};
export function validateRequisition(raw:unknown){
 const v=exact(raw,['supplierId','siteId','quoteEvidenceRef','items']);
 if(!inventoryId(v.supplierId)||!inventoryId(v.siteId))
  throw new ProcurementInputError('Valid supplier and warehouse IDs required');
 const ref=evidenceRef(v.quoteEvidenceRef);
 if(!Array.isArray(v.items)||v.items.length<1||v.items.length>25)
  throw new ProcurementInputError('1–25 requested SKU lines required');
 const seen=new Set<string>(),items:PurchaseLine[]=[];
 let subtotal=0n;
 for(const rawLine of v.items){
  const line=exact(rawLine,['productId','quantity','quotedUnitCost']);
  if(!inventoryId(line.productId)||seen.has(line.productId))
   throw new ProcurementInputError('Unique valid product ID required');
  seen.add(line.productId);
  if(typeof line.quantity!=='number'||!Number.isSafeInteger(line.quantity)||
    line.quantity<1||line.quantity>1000)
   throw new ProcurementInputError('Integer quantity 1–1000 required');
  let cost:bigint;
  try{cost=paise(line.quotedUnitCost,'quotedUnitCost');}
  catch{throw new ProcurementInputError('Positive decimal quoted unit cost required');}
  if(cost<=0n)throw new ProcurementInputError('Positive supplier-quoted unit cost required');
  const lineTotal=cost*BigInt(line.quantity);
  if(lineTotal>9999999999999999n)throw new ProcurementInputError('Line exceeds decimal storage');
  subtotal+=lineTotal;
  if(subtotal>9999999999999999n)throw new ProcurementInputError('Aggregate request exceeds limit');
  items.push({productId:line.productId,quantity:line.quantity,
   quotedUnitCost:rupees(cost)});
 }
 return {supplierId:v.supplierId,siteId:v.siteId,quoteEvidenceRef:ref,
  items,subtotal:rupees(subtotal)};
}
export function validateDecision(raw:unknown){
 const v=exact(raw,['decision','reason','evidenceAttested']);
 if(v.decision!=='APPROVED_INTERNAL'&&v.decision!=='REJECTED_INTERNAL')
  throw new ProcurementInputError('Internal decision required');
 if(typeof v.reason!=='string'||v.reason.trim().length<10||v.reason.trim().length>1000)
  throw new ProcurementInputError('Reason must contain 10–1000 characters');
 if(typeof v.evidenceAttested!=='boolean'||(v.decision==='APPROVED_INTERNAL'&&!v.evidenceAttested))
  throw new ProcurementInputError('Approval requires explicit evidence attestation');
 return {decision:v.decision as 'APPROVED_INTERNAL'|'REJECTED_INTERNAL',
  reason:v.reason.trim(),evidenceAttested:v.evidenceAttested};
}
export function purchaseHash(input:ReturnType<typeof validateRequisition>){
 return createHash('sha256').update(JSON.stringify(input)).digest('hex');
}
