// Presentation contracts for operator-supplied held planning results.
type Metric={key:string;label:string;kind:'money'|'number'|'boolean'|'text'|'choice'|'nullableNumber';options?:readonly string[]};
type Table={key:string;label:string;columns:readonly Metric[];max:number};
type Spec={title:string;metrics:readonly Metric[];required:string;optional?:readonly string[];table?:Table;multi?:{key:string;label:string;options:readonly string[]}};
const m=(key:string,label:string,kind:Metric['kind']='text',options?:readonly string[]):Metric=>({key,label,kind,options});
const scope=['PUBLIC','INTERNAL','RESTRICTED'];
const spec:Record<string,Spec>={
 M05:{title:'Estimated GST and pricing',metrics:[m('subtotal','Subtotal','money'),m('discount','Discount','money'),m('taxable','Taxable value','money'),m('estimatedTax','Estimated GST','money'),m('estimatedTotal','Estimated total','money')],required:'GST_HSN_AND_OFFICIAL_INVOICE_AUTHORITY_REQUIRED',table:{key:'lines',label:'Estimated line breakdown',max:40,columns:[m('sku','SKU'),m('quantity','Quantity','number'),m('gross','Gross','money'),m('discount','Discount','money'),m('taxable','Taxable','money'),m('estimatedTax','Estimated GST','money')]}},
 M13:{title:'Declared packing reconciliation',metrics:[m('orderReference','Order reference'),m('ordered','Ordered','number'),m('packed','Packed','number'),m('remaining','Remaining','number'),m('packages','Packages','number'),m('packingComplete','Declared packing complete','boolean')],required:'ORDER_TITLE_AND_CARRIER_AUTHORITY_REQUIRED'},
 M14:{title:'Declared payment comparison',metrics:[m('invoiceReference','Invoice reference'),m('receiptReference','Receipt reference'),m('currency','Currency','choice',['INR']),m('invoiceAmount','Invoice amount','money'),m('receivedAmount','Received amount','money'),m('comparison','Comparison','choice',['EXACT','SHORT','EXCESS']),m('unmatchedAmount','Unmatched amount','money')],required:'BANK_SETTLEMENT_AND_LEDGER_AUTHORITY_REQUIRED'},
 M15:{title:'Declared warranty comparison',metrics:[m('serialReference','Serial reference'),m('declaredDateComparison','Date comparison','choice',['BEFORE_START','AFTER_END','WITHIN_DECLARED_INTERVAL']),m('purchaseEvidencePresent','Declared purchase evidence','boolean')],required:'OEM_ENTITLEMENT_AND_SERIAL_TITLE_REQUIRED',optional:['PURCHASE_EVIDENCE_MISSING']},
 M18:{title:'Proposed portal exposure',metrics:[m('tenantReference','Tenant reference'),m('recordKind','Record type','choice',['QUOTE','ORDER','TICKET'])],multi:{key:'proposedFields',label:'Proposed visible fields',options:['displayReference','status','issuedDate','expiryDate','totalEstimate','publicDescription','quantity','supportReference']},required:'TENANT_SCOPE_SSO_AND_ISSUED_RECORD_VERIFICATION_REQUIRED',optional:['CONSENT_NOT_RECORDED']},
 M19:{title:'Declared partner pricing comparison',metrics:[m('partnerReference','Partner reference'),m('sku','SKU'),m('requestedPrice','Requested price','money'),m('minimumPrice','Declared minimum','money'),m('priceComparison','Price comparison','choice',['BELOW_DECLARED_FLOOR','AT_OR_ABOVE_DECLARED_FLOOR']),m('days','Inclusive period (days)','number')],required:'PARTNER_LEGAL_AND_PRICE_AUTHORITY_REQUIRED'},
 M20:{title:'Commission estimate',metrics:[m('partnerReference','Partner reference'),m('declaredNetCollections','Declared net collections','money'),m('uncappedEstimate','Uncapped estimate','money'),m('cappedEstimate','Capped estimate','money'),m('capApplied','Cap applied','boolean')],required:'REVENUE_LEDGER_TAX_AND_PAYOUT_AUTHORITY_REQUIRED'},
 M21:{title:'Declared marketing consent screening',metrics:[m('channel','Channel','choice',['EMAIL','WHATSAPP']),m('screenedCount','Screened records','number'),m('declaredMatchCount','Declared matches','number')],table:{key:'results',label:'Consent screening by reference',max:100,columns:[m('reference','Contact reference'),m('screen','Screening outcome','choice',['OPTED_OUT','CHANNEL_MISMATCH','NOT_YET_EFFECTIVE','EXPIRED','DECLARED_CONSENT_MATCH'])]},required:'VERIFIED_CONSENT_APPROVED_PROVIDER_AND_HUMAN_REVIEW_REQUIRED'},
 M22:{title:'Proposed AI action screening',metrics:[m('action','Proposed action','choice',['DRAFT','READ_SUMMARY','SEND','PAY','STOCK_POST','ISSUE_DOCUMENT','EXECUTE_COMMAND']),m('targetReference','Target reference'),m('humanReviewRequested','Human review requested','boolean'),m('classification','Classification','choice',['DRAFT_REVIEW_ONLY','EXTERNAL_ACTION_BLOCKED'])],required:'SCOPED_TOOL_AUTHORITY_AND_INDEPENDENT_APPROVAL_REQUIRED'},
 M23:{title:'Demand scenario',metrics:[m('observationCount','Observations','number'),m('method','Method','choice',['TRAILING_3_MONTH_MEAN_ROUNDED']),m('horizon','Horizon (months)','number'),m('scenarioUnitsPerMonth','Scenario units/month','number'),m('scenarioTotalUnits','Scenario total units','number'),m('observedMinimum','Declared minimum','number'),m('observedMaximum','Declared maximum','number')],required:'VERIFIED_HISTORY_MODEL_VALIDATION_AND_HUMAN_REVIEW_REQUIRED'},
 M24:{title:'Workflow retry scenario',metrics:[m('jobReference','Job reference'),m('idempotencyReference','Idempotency reference'),m('classification','Classification','choice',['REVIEW_RETRY','RECONCILE_BEFORE_RETRY','NO_RETRY']),m('scenarioDelaySeconds','Scenario delay (seconds)','nullableNumber')],required:'DURABLE_QUEUE_AND_AUTHORIZED_WORKER_REQUIRED'},
 M25:{title:'Knowledge source review',metrics:[m('documentReference','Document reference'),m('sha256','Declared SHA-256'),m('declaredScope','Declared scope','choice',scope),m('requestedScope','Requested scope','choice',scope)],required:'SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED',optional:['RIGHTS_NOT_ESTABLISHED','SCOPE_WIDENING_BLOCKED','PERSONAL_DATA_REVIEW_REQUIRED']}
};
const reasons:Record<string,string>={
 GST_HSN_AND_OFFICIAL_INVOICE_AUTHORITY_REQUIRED:'Verified GST/HSN classification and official invoice authority required.',
 ORDER_TITLE_AND_CARRIER_AUTHORITY_REQUIRED:'Verified order title and carrier authority required.',
 BANK_SETTLEMENT_AND_LEDGER_AUTHORITY_REQUIRED:'Verified bank settlement and ledger authority required.',
 OEM_ENTITLEMENT_AND_SERIAL_TITLE_REQUIRED:'Verified OEM entitlement and serial ownership required.',
 PURCHASE_EVIDENCE_MISSING:'Purchase evidence is missing from the declared scenario.',
 TENANT_SCOPE_SSO_AND_ISSUED_RECORD_VERIFICATION_REQUIRED:'Verified tenant scope, SSO and issued record required.',
 CONSENT_NOT_RECORDED:'Consent has not been declared.',
 PARTNER_LEGAL_AND_PRICE_AUTHORITY_REQUIRED:'Verified partner legal identity and pricing authority required.',
 REVENUE_LEDGER_TAX_AND_PAYOUT_AUTHORITY_REQUIRED:'Verified revenue ledger, tax and payout authority required.',
 VERIFIED_CONSENT_APPROVED_PROVIDER_AND_HUMAN_REVIEW_REQUIRED:'Verified consent, approved provider and human review required.',
 SCOPED_TOOL_AUTHORITY_AND_INDEPENDENT_APPROVAL_REQUIRED:'Scoped tool authority and independent approval required.',
 VERIFIED_HISTORY_MODEL_VALIDATION_AND_HUMAN_REVIEW_REQUIRED:'Verified historical data, model validation and human review required.',
 DURABLE_QUEUE_AND_AUTHORIZED_WORKER_REQUIRED:'Durable queue and authorized worker required.',
 SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED:'Verified source rights and access authority required.',
 RIGHTS_NOT_ESTABLISHED:'Source rights are not established.',
 SCOPE_WIDENING_BLOCKED:'Proposed access scope widens the declared scope.',
 PERSONAL_DATA_REVIEW_REQUIRED:'Personal data review required.'
};
function fail():never{throw Error('Invalid held planning result');}
function obj(v:unknown,keys:readonly string[]):Record<string,unknown>{
 if(!v||typeof v!=='object'||Object.getPrototypeOf(v)!==Object.prototype)fail();
 if(Reflect.ownKeys(v).length!==keys.length||keys.some(k=>{const d=Object.getOwnPropertyDescriptor(v,k);return !d||!d.enumerable||!('value' in d);}))fail();
 return v as Record<string,unknown>;
}
function list(v:unknown,min:number,max:number):unknown[]{
 if(!Array.isArray(v)||v.length<min||v.length>max||Reflect.ownKeys(v).length!==v.length+1)fail();
 return Array.from({length:v.length},(_,i)=>{const d=Object.getOwnPropertyDescriptor(v,String(i));if(!d||!d.enumerable||!('value' in d))fail();return d.value;});
}
function integer(v:unknown):number{if(typeof v!=='number'||!Number.isSafeInteger(v)||v<0||v>1000000000)fail();return v;}
function amount(v:unknown):bigint{
 if(typeof v!=='string'||!/^(0|[1-9][0-9]{0,13})\.[0-9]{2}$/.test(v))fail();
 const n=BigInt(v.replace('.',''));if(n>9999999999999999n)fail();return n;
}
function format(f:Metric,v:unknown):string{
 if(f.kind==='money'){amount(v);return 'INR '+v;}
 if(f.kind==='number')return String(integer(v));
 if(f.kind==='nullableNumber')return v===null?'Not applicable':String(integer(v));
 if(f.kind==='boolean'){if(typeof v!=='boolean')fail();return v?'Yes':'No';}
 if(typeof v!=='string'||!v||v.length>100||/[\u0000-\u001f\u007f]/.test(v))fail();
 if(f.kind==='choice'&&!f.options?.includes(v))fail();
 return v;
}
const common=['module','evidenceStatus','releaseDecision','productionReleaseAuthorized','externalExecutionEnabled','requiresHumanReview','blockers'];
export const GX_MODULES=Object.freeze(Object.keys(spec));
export function summarizePlanningResult(module:string,value:unknown){
 if(!Object.prototype.hasOwnProperty.call(spec,module))fail();
 const s=spec[module],v=obj(value,[...common,...s.metrics.map(x=>x.key),...(s.table?[s.table.key]:[]),...(s.multi?[s.multi.key]:[])]);
 if(v.module!==module||v.evidenceStatus!=='OPERATOR_SUPPLIED_UNVERIFIED'||v.releaseDecision!=='HOLD'||v.productionReleaseAuthorized!==false||v.externalExecutionEnabled!==false||v.requiresHumanReview!==true)fail();
 const blockers=list(v.blockers,1,4);
 if(!blockers.includes(s.required)||new Set(blockers).size!==blockers.length||blockers.some(x=>typeof x!=='string'||![s.required,...(s.optional??[])].includes(x)))fail();
 const metrics=s.metrics.map(f=>({key:f.key,label:f.label,value:format(f,v[f.key])}));
 let table:{label:string;headers:string[];rows:string[][]}|undefined;
 let rawRows:Record<string,unknown>[]=[];
 if(s.table){const t=s.table;rawRows=list(v[t.key],1,t.max).map(row=>obj(row,t.columns.map(c=>c.key)));
  table={label:t.label,headers:t.columns.map(c=>c.label),rows:rawRows.map(row=>t.columns.map(c=>format(c,row[c.key])))};
  const key=t.columns[0].key;if(new Set(rawRows.map(x=>x[key])).size!==rawRows.length)fail();
 }
 if(s.multi){const options=s.multi.options,values=list(v[s.multi.key],1,options.length);
  if(new Set(values).size!==values.length||values.some(x=>typeof x!=='string'||!options.includes(x)))fail();
  const allowed=v.recordKind==='QUOTE'?options.filter(x=>x!=='supportReference'):v.recordKind==='ORDER'?['displayReference','status','issuedDate','publicDescription','quantity']:['displayReference','status','publicDescription','supportReference'];
  if(values.some(x=>!allowed.includes(String(x))))fail();
  metrics.push({key:s.multi.key,label:s.multi.label,value:values.join(', ')});
 }
 // Cross-field consistency is a presentation safeguard, not independent evidence.
 const n=(k:string)=>integer(v[k]),a=(k:string)=>amount(v[k]);
 switch(module){
  case 'M05':{
   let gross=0n,discount=0n,taxable=0n,tax=0n;
   for(const row of rawRows){const g=amount(row.gross),d=amount(row.discount),b=amount(row.taxable),t=amount(row.estimatedTax);
    if(integer(row.quantity)<1||integer(row.quantity)>1000||g-d!==b||t>b)fail();gross+=g;discount+=d;taxable+=b;tax+=t;}
   if(gross!==a('subtotal')||discount!==a('discount')||taxable!==a('taxable')||tax!==a('estimatedTax')||taxable+tax!==a('estimatedTotal'))fail();break;
  }
  case 'M13':if(n('ordered')<1||n('packed')>n('ordered')||n('ordered')-n('packed')!==n('remaining')||v.packingComplete!==(n('remaining')===0)||(n('packed')===0)!==(n('packages')===0)||n('packages')>n('packed'))fail();break;
  case 'M14':{const i=a('invoiceAmount'),p=a('receivedAmount');if(i===0n||v.comparison!==(i===p?'EXACT':p<i?'SHORT':'EXCESS')||a('unmatchedAmount')!==(p<i?i-p:p-i))fail();break;}
  case 'M15':if(blockers.includes('PURCHASE_EVIDENCE_MISSING')===(v.purchaseEvidencePresent===true))fail();break;
  case 'M19':if(a('minimumPrice')===0n||a('requestedPrice')===0n||v.priceComparison!==(a('requestedPrice')<a('minimumPrice')?'BELOW_DECLARED_FLOOR':'AT_OR_ABOVE_DECLARED_FLOOR')||n('days')<1||n('days')>91)fail();break;
  case 'M20':if(a('uncappedEstimate')>a('declaredNetCollections')||a('cappedEstimate')>a('uncappedEstimate')||v.capApplied!==(a('cappedEstimate')<a('uncappedEstimate')))fail();break;
  case 'M21':if(n('screenedCount')!==rawRows.length||n('declaredMatchCount')!==rawRows.filter(x=>x.screen==='DECLARED_CONSENT_MATCH').length)fail();break;
  case 'M22':if(v.classification!==(['DRAFT','READ_SUMMARY'].includes(String(v.action))?'DRAFT_REVIEW_ONLY':'EXTERNAL_ACTION_BLOCKED'))fail();break;
  case 'M23':if(n('observationCount')<3||n('observationCount')>24||n('horizon')<1||n('horizon')>3||n('scenarioTotalUnits')!==n('scenarioUnitsPerMonth')*n('horizon')||n('observedMinimum')>n('scenarioUnitsPerMonth')||n('scenarioUnitsPerMonth')>n('observedMaximum'))fail();break;
  case 'M24':if(v.classification==='REVIEW_RETRY'?(v.scenarioDelaySeconds===null||n('scenarioDelaySeconds')<1||n('scenarioDelaySeconds')>3600):v.scenarioDelaySeconds!==null)fail();break;
  case 'M25':if(typeof v.sha256!=='string'||!/^[0-9a-f]{64}$/.test(v.sha256)||blockers.includes('SCOPE_WIDENING_BLOCKED')!==(scope.indexOf(String(v.requestedScope))<scope.indexOf(String(v.declaredScope))))fail();break;
 }
 return {module,title:s.title,metrics,table,blockers:blockers.map(code=>({code:String(code),description:reasons[String(code)]})),releaseDecision:'HOLD' as const};
}
export function comparePlanningResults(module:string,baseline:unknown,current:unknown){
 const a=summarizePlanningResult(module,baseline),b=summarizePlanningResult(module,current);
 return {module,metrics:b.metrics.map((x,i)=>({label:x.label,baseline:a.metrics[i].value,current:x.value,changed:a.metrics[i].value!==x.value})),
  detailChanged:JSON.stringify(a.table)!==JSON.stringify(b.table),blockersChanged:JSON.stringify(a.blockers)!==JSON.stringify(b.blockers),releaseDecision:'HOLD' as const};
}
