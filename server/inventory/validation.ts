import {createHash} from 'node:crypto';

export class InventoryInputError extends Error {}
export class InventoryConflictError extends Error {}

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function inventoryId(value:unknown):value is string{
 return typeof value==='string' && uuid.test(value);
}
function exactObject(body:unknown,keys:readonly string[]):Record<string,unknown>{
 if(!body||typeof body!=='object'||Array.isArray(body))
  throw new InventoryInputError('Object body required');
 const src=body as Record<string,unknown>;
 const fields=Object.keys(src).sort();
 if(fields.length!==keys.length || fields.some((f,i)=>f!==[...keys].sort()[i]))
  throw new InventoryInputError('Unexpected or missing inventory fields');
 return src;
}
export function validateSite(body:unknown){
 const fields=exactObject(body,['code','name']);
 if(typeof fields.code!=='string'||!(/^[A-Z][A-Z0-9_-]{1,31}$/).test(fields.code))
  throw new InventoryInputError('Site code must be 2–32 uppercase letters, digits, _ or -');
 if(typeof fields.name!=='string'||!fields.name.trim()||
    fields.name.trim().length>120)
  throw new InventoryInputError('Valid site name required');
 return {code:fields.code,name:fields.name.trim()};
}
export function validateOpeningCount(body:unknown){
 const fields=exactObject(body,['productId','siteId','quantity','evidenceRef']);
 if(!inventoryId(fields.productId)||!inventoryId(fields.siteId))
  throw new InventoryInputError('Valid product and site IDs required');
 if(typeof fields.quantity!=='number'||!Number.isSafeInteger(fields.quantity)||
    fields.quantity<0||fields.quantity>1000000)
  throw new InventoryInputError('Quantity must be an integer from zero to one million');
 if(typeof fields.evidenceRef!=='string'||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{7,159}$/.test(fields.evidenceRef))
  throw new InventoryInputError('Use an 8–160 character non-sensitive count evidence reference');
 return {productId:fields.productId,siteId:fields.siteId,
  quantity:fields.quantity,evidenceRef:fields.evidenceRef};
}
export function openingRequestHash(input:ReturnType<typeof validateOpeningCount>):string {
 return createHash('sha256').update(JSON.stringify(input)).digest('hex');
}
