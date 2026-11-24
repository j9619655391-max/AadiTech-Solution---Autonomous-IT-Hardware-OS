// UI-only scenario input schema. Server validation remains authoritative.
export type Scalar={key:string;label:string;kind:'text'|'decimal'|'integer'|'date'|'month'|'select';options?:readonly string[];min?:number;max?:number;boolean?:true};
export type Rows={key:string;label:string;kind:'rows';fields:readonly Scalar[];min:number;max:number};
export type Multi={key:string;label:string;kind:'multi';options:readonly string[]};
export type Field=Scalar|Rows|Multi;
export type Draft=Record<string,string|string[]|Record<string,string>[]>;
const text=(key:string,label:string):Scalar=>({key,label,kind:'text'});
const decimal=(key:string,label:string):Scalar=>({key,label,kind:'decimal'});
const integer=(key:string,label:string,min:number,max:number):Scalar=>({key,label,kind:'integer',min,max});
const date=(key:string,label:string):Scalar=>({key,label,kind:'date'});
const select=(key:string,label:string,options:readonly string[]):Scalar=>({key,label,kind:'select',options});
const bool=(key:string,label:string):Scalar=>({key,label,kind:'select',options:['true','false'],boolean:true});
const rows=(key:string,label:string,min:number,max:number,fields:readonly Scalar[]):Rows=>({key,label,kind:'rows',min,max,fields});
const channels=['EMAIL','WHATSAPP'],scopes=['PUBLIC','INTERNAL','RESTRICTED'];
export const formSchemas:Record<string,readonly Field[]>={
 M05:[rows('lines','Estimate lines',1,40,[text('sku','SKU'),integer('quantity','Quantity',1,1000),decimal('unitPrice','Unit price (INR)'),decimal('gstRate','Declared GST rate (%)')]),decimal('discount','Discount (INR)')],
 M13:[text('orderReference','Order reference'),rows('items','Packing lines',1,100,[text('sku','SKU'),integer('ordered','Ordered units',1,10000),integer('packed','Packed units',0,10000)]),integer('packages','Packages',0,10000),text('destinationPostalCode','Destination PIN code')],
 M14:[text('invoiceReference','Invoice reference'),text('receiptReference','Receipt reference'),decimal('invoiceAmount','Invoice amount (INR)'),decimal('receivedAmount','Received amount (INR)'),select('currency','Currency',['INR'])],
 M15:[text('serialReference','Serial reference'),date('declaredStart','Declared start'),date('declaredEnd','Declared end'),date('claimDate','Claim date'),bool('purchaseEvidencePresent','Purchase evidence present?')],
 M18:[text('tenantReference','Tenant reference'),select('recordKind','Record type',['QUOTE','ORDER','TICKET']),{key:'requestedFields',label:'Proposed fields',kind:'multi',options:['displayReference','status','issuedDate','expiryDate','totalEstimate','publicDescription','quantity','supportReference']},bool('consentRecorded','Consent recorded?')],
 M19:[text('partnerReference','Partner reference'),text('sku','SKU'),decimal('requestedPrice','Requested price (INR)'),decimal('minimumPrice','Declared minimum price (INR)'),date('startsOn','Start date'),date('endsOn','End date')],
 M20:[text('partnerReference','Partner reference'),decimal('collected','Declared collections (INR)'),decimal('refunds','Refunds (INR)'),decimal('rate','Commission rate (%)'),decimal('cap','Commission cap (INR)')],
 M21:[select('channel','Campaign channel',channels),date('asOf','Screening date'),rows('recipients','Consent records',1,100,[text('contactReference','Contact reference'),select('consentChannel','Consent channel',channels),date('consentedOn','Consent date'),date('expiresOn','Expiry date'),bool('optedOut','Opted out?')])],
 M22:[select('action','Proposed action',['DRAFT','READ_SUMMARY','SEND','PAY','STOCK_POST','ISSUE_DOCUMENT','EXECUTE_COMMAND']),text('targetReference','Target reference'),bool('humanReviewRequested','Human review requested?')],
 M23:[rows('observations','Monthly observations',3,24,[{key:'month',label:'Month',kind:'month'},integer('units','Units',0,1000000)]),integer('horizon','Forecast horizon (months)',1,3)],
 M24:[text('jobReference','Job reference'),integer('attempt','Attempt',1,10),integer('maxAttempts','Maximum attempts',1,10),select('lastResult','Last result',['TRANSIENT_FAILURE','PERMANENT_FAILURE','SUCCESS','UNKNOWN_COMMIT']),text('idempotencyReference','Idempotency reference'),integer('baseDelaySeconds','Base delay (seconds)',1,300)],
 M25:[text('documentReference','Document reference'),text('sha256','SHA-256 digest'),select('rights','Declared rights',['DECLARED_OWNED','DECLARED_LICENSED','UNKNOWN','PROHIBITED']),select('scope','Declared scope',scopes),select('requestedScope','Requested scope',scopes),bool('containsPersonalData','Contains personal data?')]
};
function schema(module:string){if(!Object.prototype.hasOwnProperty.call(formSchemas,module))throw Error('Unknown planning module');return formSchemas[module];}
export const blankRow=(fields:readonly Scalar[])=>Object.fromEntries(fields.map(f=>[f.key,'']));
export function blankForm(module:string):Draft{return Object.fromEntries(schema(module).map(f=>[f.key,f.kind==='rows'?Array.from({length:f.min},()=>blankRow(f.fields)):f.kind==='multi'?[]:'']));}
function object(v:unknown,keys:readonly string[]):Record<string,unknown>{
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.getPrototypeOf(v)!==Object.prototype)throw Error('Invalid form object');
 if(Object.keys(v).length!==keys.length||keys.some(k=>!Object.prototype.hasOwnProperty.call(v,k)))throw Error('Unexpected or missing form field');
 return v as Record<string,unknown>;
}
function list(v:unknown,min:number,max:number):unknown[]{
 if(!Array.isArray(v)||v.length<min||v.length>max||Object.keys(v).length!==v.length)throw Error('Invalid list length');return v;
}
function scalar(f:Scalar,v:unknown):unknown{
 if(typeof v!=='string'||!v||v.trim()!==v)throw Error(f.label+' is required');
 if(f.kind==='select'){if(!f.options?.includes(v))throw Error(f.label+' is invalid');return f.boolean?v==='true':v;}
 if(f.kind==='integer'){const n=Number(v);if(!/^(0|[1-9][0-9]*)$/.test(v)||!Number.isSafeInteger(n)||n<f.min!||n>f.max!)throw Error(f.label+' is out of range');return n;}
 if(f.kind==='decimal'&&!/^(0|[1-9][0-9]{0,12})(\.[0-9]{1,2})?$/.test(v))throw Error(f.label+' must be a decimal');
 if(f.kind==='date'){const ms=Date.parse(v+'T00:00:00Z');if(!/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/.test(v)||!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==v)throw Error(f.label+' is invalid');}
 if(f.kind==='month'&&!/^20[0-9]{2}-(0[1-9]|1[0-2])$/.test(v))throw Error(f.label+' is invalid');
 if(f.kind==='text'&&v.length>80)throw Error(f.label+' is too long');return v;
}
export function encodeForm(module:string,draft:unknown):Record<string,unknown>{
 const fields=schema(module),v=object(draft,fields.map(f=>f.key));
 return Object.fromEntries(fields.map(f=>{
  if(f.kind==='rows')return [f.key,list(v[f.key],f.min,f.max).map(row=>{const x=object(row,f.fields.map(y=>y.key));return Object.fromEntries(f.fields.map(y=>[y.key,scalar(y,x[y.key])]));})];
  if(f.kind==='multi'){const x=list(v[f.key],1,f.options.length);if(x.some(y=>typeof y!=='string'||!f.options.includes(y))||new Set(x).size!==x.length)throw Error(f.label+' is invalid');return [f.key,x];}
  return [f.key,scalar(f,v[f.key])];
 }));
}
export function exampleForm(module:string,payload:unknown):Draft{
 const fields=schema(module),v=object(payload,fields.map(f=>f.key));
 const convert=(f:Scalar,x:unknown)=>{if(typeof x==='string'||f.kind==='integer'&&typeof x==='number'||f.boolean&&typeof x==='boolean')return String(x);throw Error('Invalid example');};
 const draft=Object.fromEntries(fields.map(f=>{
  if(f.kind==='rows')return [f.key,list(v[f.key],f.min,f.max).map(row=>{const x=object(row,f.fields.map(y=>y.key));return Object.fromEntries(f.fields.map(y=>[y.key,convert(y,x[y.key])]));})];
  if(f.kind==='multi')return [f.key,list(v[f.key],1,f.options.length).map(x=>{if(typeof x!=='string')throw Error('Invalid example choice');return x;})];
  return [f.key,convert(f,v[f.key])];
 })) as Draft;
 encodeForm(module,draft);return draft;
}
