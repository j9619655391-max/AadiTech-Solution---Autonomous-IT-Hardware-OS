// AI-generated items and copy are DRAFTS, never pricing, tax or action evidence.
export function requiredAiText(body:unknown,key:string,max=2000):string{
 if(!body||typeof body!=='object'||Array.isArray(body))throw Error('Invalid request body');
 const val=(body as Record<string,unknown>)[key];
 if(typeof val!=='string'||!val.trim()||val.trim().length>max)
  throw Error('Invalid '+key);
 return val.trim();
}
function record(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value))
  throw Error('AI result is not an object');
 return value as Record<string,unknown>;
}
function field(value:unknown,name:string,max:number):string{
 if(typeof value!=='string'||!value.trim()||value.length>max)
  throw Error('AI result has invalid '+name);
 return value.trim();
}
export function normalizeBomDraft(value:unknown){
 const source=record(value);
 if(!Array.isArray(source.items)||source.items.length<1||source.items.length>50)
  throw Error('AI BOM draft requires 1-50 items');
 const items=source.items.map((raw:unknown)=>{
  const item=record(raw),qty=item.qty;
  if(typeof qty!=='number'||!Number.isSafeInteger(qty)||qty<1||qty>10000)
   throw Error('Invalid BOM draft quantity');
  return {category:field(item.category,'category',100),
   name:field(item.name,'name',350),qty,
   unitCost:0,unitSell:0,hsn:''};
 });
 return {title:field(source.title,'title',250),items,
  compatibilityStatus:'FLAGGED' as const,
  compatibilityNotes:'UNVERIFIED AI draft. Independently check OEM specifications, power, licensing, stock, prices, GST and HSN before a quotation.',
  pricingVerified:false,compatibilityVerified:false,requiresHumanReview:true};
}
export function normalizeCampaignDraft(value:unknown){
 const source=record(value);
 return {headline:field(source.headline,'headline',250),
  whatsappMessage:field(source.whatsappMessage,'whatsappMessage',4000),
  emailSubject:field(source.emailSubject,'emailSubject',250),
  emailBody:field(source.emailBody,'emailBody',7000),
  projectedConversion:'NOT_MEASURED',estimatedPipelineValue:'NOT_MEASURED',
  requiresHumanReview:true,dispatchEnabled:false,evidenceStatus:'UNVERIFIED_AI_DRAFT'};
}
export function parseListenPort(value:string|undefined):number{
 if(value===undefined||value==='')return 3000;
 if(!/^[1-9][0-9]{0,4}$/.test(value))throw Error('PORT must be 1-65535');
 const port=Number(value);
 if(port>65535)throw Error('PORT out of range');
 return port;
}
