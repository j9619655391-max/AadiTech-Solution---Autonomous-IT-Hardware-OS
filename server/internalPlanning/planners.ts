// Internal planning calculations only. Inputs are operator-supplied, not verified facts.
// No database mutation, provider, document issuance, message, bank or inventory action.
import {exact,text,ref,integer,flag,choice,date,daySpan,amount,rate,roundRate,money,array,unique,reject} from './validation';

function invoice(value:unknown){
 const v=exact(value,['lines','discount']);
 const lines=array(v.lines,1,40).map(raw=>{
  const x=exact(raw,['sku','quantity','unitPrice','gstRate']);
  return {sku:ref(x.sku),quantity:integer(x.quantity,1,1000),unit:amount(x.unitPrice),rate:rate(x.gstRate)};
 });
 unique(lines.map(x=>x.sku));
 const subtotal=lines.reduce((sum,x)=>sum+x.unit*BigInt(x.quantity),0n);
 const discount=amount(v.discount);if(discount>subtotal)reject('DISCOUNT_EXCEEDS_SUBTOTAL');
 // Allocate discount proportionally to taxable line values with exact residual on
 // the last positive line, avoiding negative allocation/rounding overflow.
 let allocated=0n,cumulative=0n,tax=0n;
 const result=lines.map(x=>{
  const gross=x.unit*BigInt(x.quantity);cumulative+=gross;
  const cumulativeDiscount=subtotal===0n?0n:discount*cumulative/subtotal;
  const lineDiscount=cumulativeDiscount-allocated;allocated=cumulativeDiscount;
  const taxable=gross-lineDiscount,estimatedTax=roundRate(taxable,x.rate);tax+=estimatedTax;
  return {sku:x.sku,quantity:x.quantity,gross:money(gross),discount:money(lineDiscount),taxable:money(taxable),estimatedTax:money(estimatedTax)};
 });
 return {lines:result,subtotal:money(subtotal),discount:money(discount),taxable:money(subtotal-discount),estimatedTax:money(tax),estimatedTotal:money(subtotal-discount+tax),blockers:['GST_HSN_AND_OFFICIAL_INVOICE_AUTHORITY_REQUIRED']};
}
function shipment(value:unknown){
 const v=exact(value,['orderReference','items','packages','destinationPostalCode']);
 const items=array(v.items,1,100).map(raw=>{const x=exact(raw,['sku','ordered','packed']);return {sku:ref(x.sku),ordered:integer(x.ordered,1,10000),packed:integer(x.packed,0,10000)};});
 unique(items.map(x=>x.sku));
 if(items.some(x=>x.packed>x.ordered))reject('OVERPACKED');
 const packages=integer(v.packages,0,10000),postal=text(v.destinationPostalCode,6);
 if(!/^[1-9][0-9]{5}$/.test(postal))reject('INVALID_POSTAL_CODE');
 const ordered=items.reduce((a,x)=>a+x.ordered,0),packed=items.reduce((a,x)=>a+x.packed,0);
 if((packed===0)!==(packages===0)||packages>packed)reject('PACKAGE_COUNT_CONFLICT');
 return {orderReference:ref(v.orderReference),ordered,packed,remaining:ordered-packed,packages,packingComplete:ordered===packed,blockers:['ORDER_TITLE_AND_CARRIER_AUTHORITY_REQUIRED']};
}
function payment(value:unknown){
 const v=exact(value,['invoiceReference','receiptReference','invoiceAmount','receivedAmount','currency']);
 const invoice=amount(v.invoiceAmount),received=amount(v.receivedAmount);
 if(invoice===0n)reject('ZERO_INVOICE');
 const currency=choice(v.currency,['INR'] as const);
 return {invoiceReference:ref(v.invoiceReference),receiptReference:ref(v.receiptReference),currency,invoiceAmount:money(invoice),receivedAmount:money(received),
  comparison:received===invoice?'EXACT':received<invoice?'SHORT':'EXCESS',unmatchedAmount:money(received>invoice?received-invoice:invoice-received),blockers:['BANK_SETTLEMENT_AND_LEDGER_AUTHORITY_REQUIRED']};
}
function warranty(value:unknown){
 const v=exact(value,['serialReference','declaredStart','declaredEnd','claimDate','purchaseEvidencePresent']);
 const start=date(v.declaredStart),end=date(v.declaredEnd),claim=date(v.claimDate),evidence=flag(v.purchaseEvidencePresent);
 if(end<start||daySpan(start,end)>3660)reject('INVALID_COVERAGE_INTERVAL');
 return {serialReference:ref(v.serialReference),declaredDateComparison:claim<start?'BEFORE_START':claim>end?'AFTER_END':'WITHIN_DECLARED_INTERVAL',
  purchaseEvidencePresent:evidence,blockers:[...(!evidence?['PURCHASE_EVIDENCE_MISSING']:[]),'OEM_ENTITLEMENT_AND_SERIAL_TITLE_REQUIRED']};
}
function portal(value:unknown){
 const v=exact(value,['tenantReference','requestedFields','recordKind','consentRecorded']);
 const fields=array(v.requestedFields,1,8).map(x=>choice(x,['displayReference','status','issuedDate','expiryDate','totalEstimate','publicDescription','quantity','supportReference'] as const));
 unique(fields);
 const kind=choice(v.recordKind,['QUOTE','ORDER','TICKET'] as const),consent=flag(v.consentRecorded);
 const allowed:Record<typeof kind,readonly string[]>={QUOTE:['displayReference','status','issuedDate','expiryDate','totalEstimate','publicDescription','quantity'],ORDER:['displayReference','status','issuedDate','publicDescription','quantity'],TICKET:['displayReference','status','publicDescription','supportReference']};
 if(fields.some(x=>!allowed[kind].includes(x)))reject('FIELD_NOT_ALLOWED_FOR_KIND');
 return {tenantReference:ref(v.tenantReference),recordKind:kind,proposedFields:fields,blockers:[...(!consent?['CONSENT_NOT_RECORDED']:[]),'TENANT_SCOPE_SSO_AND_ISSUED_RECORD_VERIFICATION_REQUIRED']};
}
function deal(value:unknown){
 const v=exact(value,['partnerReference','sku','requestedPrice','minimumPrice','startsOn','endsOn']);
 const requested=amount(v.requestedPrice),minimum=amount(v.minimumPrice),start=date(v.startsOn),end=date(v.endsOn);
 if(minimum===0n||requested===0n)reject('ZERO_PRICE');
 if(end<start||daySpan(start,end)>90)reject('INVALID_PROTECTION_INTERVAL');
 return {partnerReference:ref(v.partnerReference),sku:ref(v.sku),requestedPrice:money(requested),minimumPrice:money(minimum),priceComparison:requested<minimum?'BELOW_DECLARED_FLOOR':'AT_OR_ABOVE_DECLARED_FLOOR',days:daySpan(start,end)+1,blockers:['PARTNER_LEGAL_AND_PRICE_AUTHORITY_REQUIRED']};
}
function commission(value:unknown){
 const v=exact(value,['partnerReference','collected','refunds','rate','cap']);
 const collected=amount(v.collected),refunds=amount(v.refunds),r=rate(v.rate),cap=amount(v.cap);
 if(refunds>collected)reject('REFUNDS_EXCEED_COLLECTION');
 const basis=collected-refunds,gross=roundRate(basis,r);
 return {partnerReference:ref(v.partnerReference),declaredNetCollections:money(basis),uncappedEstimate:money(gross),cappedEstimate:money(gross>cap?cap:gross),capApplied:gross>cap,blockers:['REVENUE_LEDGER_TAX_AND_PAYOUT_AUTHORITY_REQUIRED']};
}
function campaign(value:unknown){
 const v=exact(value,['channel','asOf','recipients']),channel=choice(v.channel,['EMAIL','WHATSAPP'] as const),asOf=date(v.asOf);
 const rows=array(v.recipients,1,100).map(raw=>{
  const x=exact(raw,['contactReference','consentChannel','consentedOn','expiresOn','optedOut']);
  const consentChannel=choice(x.consentChannel,['EMAIL','WHATSAPP'] as const),start=date(x.consentedOn),end=date(x.expiresOn),optedOut=flag(x.optedOut);
  if(end<start)reject('INVALID_CONSENT_INTERVAL');
  return {reference:ref(x.contactReference),screen:optedOut?'OPTED_OUT':consentChannel!==channel?'CHANNEL_MISMATCH':asOf<start?'NOT_YET_EFFECTIVE':asOf>end?'EXPIRED':'DECLARED_CONSENT_MATCH'};
 });
 unique(rows.map(x=>x.reference));
 return {channel,screenedCount:rows.length,declaredMatchCount:rows.filter(x=>x.screen==='DECLARED_CONSENT_MATCH').length,results:rows,blockers:['VERIFIED_CONSENT_APPROVED_PROVIDER_AND_HUMAN_REVIEW_REQUIRED']};
}
function agent(value:unknown){
 const v=exact(value,['action','targetReference','humanReviewRequested']),action=choice(v.action,['DRAFT','READ_SUMMARY','SEND','PAY','STOCK_POST','ISSUE_DOCUMENT','EXECUTE_COMMAND'] as const);
 return {action,targetReference:ref(v.targetReference),humanReviewRequested:flag(v.humanReviewRequested),classification:action==='DRAFT'||action==='READ_SUMMARY'?'DRAFT_REVIEW_ONLY':'EXTERNAL_ACTION_BLOCKED',blockers:['SCOPED_TOOL_AUTHORITY_AND_INDEPENDENT_APPROVAL_REQUIRED']};
}
function forecast(value:unknown){
 const v=exact(value,['observations','horizon']),horizon=integer(v.horizon,1,3);
 const rows=array(v.observations,3,24).map(raw=>{
  const x=exact(raw,['month','units']);
  const month=text(x.month,7);if(!/^20[0-9]{2}-(0[1-9]|1[0-2])$/.test(month))reject('INVALID_MONTH');
  const [y,m]=month.split('-').map(Number);return {month,index:y*12+m-1,units:integer(x.units,0,1000000)};
 });
 if(rows.some((x,i)=>i>0&&x.index!==rows[i-1].index+1))reject('NONCONTIGUOUS_HISTORY');
 const last=rows.slice(-3),sum=last.reduce((a,x)=>a+x.units,0),estimate=Math.floor((sum+1)/3);
 return {observationCount:rows.length,method:'TRAILING_3_MONTH_MEAN_ROUNDED',horizon,scenarioUnitsPerMonth:estimate,scenarioTotalUnits:estimate*horizon,observedMinimum:Math.min(...rows.map(x=>x.units)),observedMaximum:Math.max(...rows.map(x=>x.units)),blockers:['VERIFIED_HISTORY_MODEL_VALIDATION_AND_HUMAN_REVIEW_REQUIRED']};
}
function workflow(value:unknown){
 const v=exact(value,['jobReference','attempt','maxAttempts','lastResult','idempotencyReference','baseDelaySeconds']);
 const attempt=integer(v.attempt,1,10),max=integer(v.maxAttempts,1,10),base=integer(v.baseDelaySeconds,1,300);
 if(attempt>max)reject('ATTEMPT_LIMIT_CONFLICT');
 const last=choice(v.lastResult,['TRANSIENT_FAILURE','PERMANENT_FAILURE','SUCCESS','UNKNOWN_COMMIT'] as const);
 const retry=last==='TRANSIENT_FAILURE'&&attempt<max;
 return {jobReference:ref(v.jobReference),idempotencyReference:ref(v.idempotencyReference),classification:retry?'REVIEW_RETRY':last==='UNKNOWN_COMMIT'?'RECONCILE_BEFORE_RETRY':'NO_RETRY',scenarioDelaySeconds:retry?Math.min(3600,base*2**(attempt-1)):null,blockers:['DURABLE_QUEUE_AND_AUTHORIZED_WORKER_REQUIRED']};
}
function knowledge(value:unknown){
 const v=exact(value,['documentReference','sha256','rights','scope','requestedScope','containsPersonalData']);
 const hash=text(v.sha256,64);if(!/^[0-9a-f]{64}$/.test(hash))reject('INVALID_DIGEST');
 const rights=choice(v.rights,['DECLARED_OWNED','DECLARED_LICENSED','UNKNOWN','PROHIBITED'] as const),scope=choice(v.scope,['PUBLIC','INTERNAL','RESTRICTED'] as const),requested=choice(v.requestedScope,['PUBLIC','INTERNAL','RESTRICTED'] as const),personal=flag(v.containsPersonalData);
 const order=['PUBLIC','INTERNAL','RESTRICTED'];
 const blockers=['SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED'];
 if(rights==='UNKNOWN'||rights==='PROHIBITED')blockers.push('RIGHTS_NOT_ESTABLISHED');
 if(order.indexOf(requested)<order.indexOf(scope))blockers.push('SCOPE_WIDENING_BLOCKED');
 if(personal)blockers.push('PERSONAL_DATA_REVIEW_REQUIRED');
 return {documentReference:ref(v.documentReference),sha256:hash,declaredScope:scope,requestedScope:requested,blockers};
}
const planners={M05:invoice,M13:shipment,M14:payment,M15:warranty,M18:portal,M19:deal,M20:commission,M21:campaign,M22:agent,M23:forecast,M24:workflow,M25:knowledge};
export const GU_MODULES=Object.freeze(Object.keys(planners));
export function evaluateInternalPlan(module:unknown,payload:unknown){
 if(typeof module!=='string'||!Object.prototype.hasOwnProperty.call(planners,module))reject('UNSUPPORTED_MODULE');
 const result=planners[module as keyof typeof planners](payload);
 return {...result,module,evidenceStatus:'OPERATOR_SUPPLIED_UNVERIFIED' as const,releaseDecision:'HOLD' as const,
  productionReleaseAuthorized:false as const,externalExecutionEnabled:false as const,requiresHumanReview:true as const};
}
