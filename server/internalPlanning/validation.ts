// Pure, bounded inputs for internal previews; no operational authority.
import {paise,rupees} from '../quotes/money';
export class PlanningInputError extends Error {
 constructor(readonly code:string){super(code);}
}
export function reject(code:string):never{throw new PlanningInputError(code);}
export function exact(value:unknown,keys:readonly string[]):Record<string,unknown>{
 if(!value||typeof value!=='object'||Object.getPrototypeOf(value)!==Object.prototype)reject('INVALID_OBJECT');
 const v=value as Record<string,unknown>;
 if(Reflect.ownKeys(v).length!==keys.length||keys.some(k=>{
  const desc=Object.getOwnPropertyDescriptor(v,k);return !desc||!desc.enumerable||!('value' in desc);
 }))reject('INVALID_FIELDS');
 return v;
}
export function text(v:unknown,max=100):string{
 if(typeof v!=='string'||!v.length||v.trim()!==v||v.length>max||/[\u0000-\u001f\u007f]/.test(v))reject('INVALID_TEXT');
 return v;
}
export function ref(v:unknown):string{
 const x=text(v,80);if(!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(x))reject('INVALID_REFERENCE');return x;
}
export function integer(v:unknown,min:number,max:number):number{
 if(typeof v!=='number'||!Number.isSafeInteger(v)||v<min||v>max)reject('INVALID_INTEGER');return v;
}
export function flag(v:unknown):boolean{if(typeof v!=='boolean')reject('INVALID_BOOLEAN');return v;}
export function choice<T extends string>(v:unknown,allowed:readonly T[]):T{
 if(typeof v!=='string'||!allowed.includes(v as T))reject('INVALID_ENUM');return v as T;
}
export function date(v:unknown):string{
 if(typeof v!=='string'||!/^(20[0-9]{2})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/.test(v))reject('INVALID_DATE');
 const ms=Date.parse(v+'T00:00:00Z');if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==v)reject('INVALID_DATE');return v;
}
export function daySpan(a:string,b:string){return (Date.parse(b+'T00:00:00Z')-Date.parse(a+'T00:00:00Z'))/86400000;}
export function amount(v:unknown):bigint{
 try{return paise(v);}catch{return reject('INVALID_MONEY');}
}
export function rate(v:unknown):bigint{const x=amount(v);if(x>10000n)reject('INVALID_RATE');return x;}
export function roundRate(v:bigint,r:bigint){return (v*r+5000n)/10000n;}
export function money(v:bigint):string{
 if(v<0n||v>9999999999999999n)reject('AMOUNT_OUT_OF_RANGE');return rupees(v);
}
export function array(v:unknown,min:number,max:number):unknown[]{
 if(!Array.isArray(v)||v.length<min||v.length>max||Object.keys(v).length!==v.length)reject('INVALID_ARRAY');
 return Array.from({length:v.length},(_,i)=>{const x=Object.getOwnPropertyDescriptor(v,String(i));if(!x||!x.enumerable||!('value' in x))reject('INVALID_ARRAY');return x.value;});
}
export function unique(values:string[]){if(new Set(values).size!==values.length)reject('DUPLICATE_REFERENCE');}
