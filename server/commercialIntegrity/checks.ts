import {calculateLine,evaluateRevision,paise,rupees} from '../quotes/money';

// Read-only internal scope checks. The records and review signers are
// applicant-managed MySQL evidence, not actual corporate verification,
// authenticated supplier quotes, genuine external WORM or release approval.
const baseline=Object.freeze([
 'CUSTOMER_LEGAL_IDENTITY_NOT_INDEPENDENTLY_VERIFIED',
 'PRODUCT_VENDOR_PRICE_HSN_GST_NOT_EXTERNALLY_ATTESTED',
 'AUTHENTICATED_THIRD_PARTY_CONTRACT_NOT_PROVIDED',
 'PRODUCTION_DELIVERY_STOCK_FINANCE_POSTING_BLOCKED'
]);
const str=(x:unknown):string=>typeof x==='string'?x:String(x??'');
const obj=(x:unknown):Record<string,unknown>|null=>{
 if(x&&typeof x==='object'&&!Array.isArray(x))return x as Record<string,unknown>;
 if(typeof x!=='string'||x.length>50000)return null;
 try{const v=JSON.parse(x);return v&&typeof v==='object'&&!Array.isArray(v)?v:null;}
 catch{return null;}
};
const num=(x:unknown):number=>Number(x);
const flag=(codes:Set<string>,c:string,fail:boolean)=>{if(fail)codes.add(c);};

export function inspectInternalQuoteScope(args:{
 draft:Record<string,any>,lines:Record<string,any>[],
 revision?:Record<string,any>|null,decision?:Record<string,any>|null,
 preparation?:Record<string,any>|null
}){
 const {draft,lines,revision=null,decision=null,preparation=null}=args;
 const problems=new Set<string>(),snapshots:any[]=[];
 let total=0n,tax=0n,cost=0n,revisionNumber=0;
 try{
  if(str(draft.status)!=='DRAFT'||str(draft.currency)!=='INR'||
     !!draft.customer_deleted_at)problems.add('DRAFT_CUSTOMER_OR_CURRENCY_INVALID');
  if(!Array.isArray(lines)||lines.length<1||lines.length>40)
   problems.add('MISSING_OR_EXCESS_QUOTE_LINES');
  const seen=new Set<string>();
  for(let i=0;i<lines.length;i++){
   const x=lines[i],product=str(x.product_id);
   if(seen.has(product)||num(x.position)!==i+1||!product||
     !str(x.sku_snapshot).trim()||!str(x.hsn_snapshot).trim())
    problems.add('DUPLICATE_OR_UNBOUNDED_QUOTE_LINE');
   seen.add(product);
   const q=num(x.quantity),line=calculateLine(str(x.unit_price),q,str(x.gst_rate));
   const c=paise(str(x.unit_cost))*BigInt(q);
   if(rupees(line.subtotal)!==str(x.line_subtotal)||
      rupees(line.tax)!==str(x.line_tax_estimate))
    problems.add('QUOTE_LINE_SNAPSHOT_MONEY_CHANGED');
   total+=line.subtotal;tax+=line.tax;cost+=c;
   snapshots.push({productId:product,sku:str(x.sku_snapshot),
    name:str(x.name_snapshot),hsn:str(x.hsn_snapshot),
    quantity:q,unitCost:str(x.unit_cost),
    unitPrice:str(x.unit_price),gstRate:str(x.gst_rate)});
  }
  if(total===0n||rupees(total)!==str(draft.subtotal)||
     rupees(tax)!==str(draft.tax_estimate)||
     rupees(total+tax)!==str(draft.total_estimate))
   problems.add('QUOTE_TOTAL_SNAPSHOT_CHANGED');
  if(revision){
   revisionNumber=num(revision.revision_number);
   if(!Number.isSafeInteger(revisionNumber)||revisionNumber<1)
    problems.add('INVALID_CURRENT_REVISION');
   const current=obj(revision.line_snapshot);
   const parsed=current===null?(
    Array.isArray(revision.line_snapshot)?revision.line_snapshot:
    typeof revision.line_snapshot==='string'?
      JSON.parse(revision.line_snapshot):null):null;
   if(!Array.isArray(parsed)||parsed.length!==snapshots.length)
    problems.add('REVISION_LINE_SCOPE_MISMATCH');
   else{
    const byId=new Map(snapshots.map(x=>[x.productId,x]));
    const seenRevision=new Set<string>();
    for(const r of parsed){
     const id=str(r.productId),saved=byId.get(id);
     if(!saved||seenRevision.has(id)||
       !Number.isSafeInteger(r.quantity)||r.quantity<1||r.quantity>1000||
       saved.sku!==str(r.sku)||saved.name!==str(r.name)||
       saved.hsn!==str(r.hsn)||saved.unitCost!==str(r.unitCost)||
       saved.unitPrice!==str(r.unitPrice)||saved.gstRate!==str(r.gstRate))
      problems.add('REVISION_LINE_SCOPE_MISMATCH');
     seenRevision.add(id);
    }
    if(!problems.has('REVISION_LINE_SCOPE_MISMATCH')){
     const v=evaluateRevision(parsed.map((r:any)=>({
      productId:r.productId,sku:r.sku,name:r.name,hsn:r.hsn,
      quantity:r.quantity,unitCost:r.unitCost,
      unitPrice:r.unitPrice,gstRate:r.gstRate
     })),0);
     if(str(revision.subtotal)!==v.subtotal||
       str(revision.tax_estimate)!==v.taxEstimate||
       str(revision.total_estimate)!==v.totalEstimate||
       num(revision.gross_margin_bps)!==v.grossMarginBps)
      problems.add('REVISION_MONEY_OR_MARGIN_CHANGED');
    }
   }
  }
  if(decision){
   if(num(decision.revision_number)!==revisionNumber||
     !['APPROVED_INTERNAL','REJECTED_INTERNAL'].includes(str(decision.decision))||
     str(decision.reviewer_role)!=='REVIEWER'||
     str(decision.owner_user_id)===str(draft.created_by)||
     str(decision.subtotal)!==str(revision?revision.subtotal:draft.subtotal))
    problems.add('QUOTE_REVIEW_ACTOR_REVISION_OR_AMOUNT_INVALID');
   // A signed customer approval cannot be inferred from internal reviewer.
   if(decision.decision==='APPROVED_INTERNAL'&&
      num(decision.gross_margin_bps)<num(decision.minimum_margin_bps)&&
      !Boolean(decision.override_requested))
    problems.add('QUOTE_BELOW_POLICY_OVERRIDE_MISSING');
  }
  if(preparation){
   const p=preparation,contents=obj(p.snapshot_json);
   if(!decision||decision.decision!=='APPROVED_INTERNAL'||
     str(p.status)!=='HELD'||str(p.dispatch_state)!=='DISABLED'||
     str(p.event_type)!=='QUOTE_RELEASE_PREPARATION_HELD'||
     str(p.snapshot_sha256)!==str(p.payload_sha256)||
     !/^[0-9a-f]{64}$/.test(str(p.snapshot_sha256))||
     num(p.revision_number)!==revisionNumber||
     str(p.internal_review_id)!==str(decision.id)||
     str(p.prepared_by)!==str(draft.created_by)||
     !contents||contents.format!=='aaditech-internal-release-hold-v1'||
     str(contents.quoteId)!==str(draft.id)||
     num(contents.revision)!==revisionNumber||
     str(contents.customerId)!==str(draft.customer_id)||
     str(contents.reviewId)!==str(decision.id)||
     str(contents.subtotal)!==str(revision?revision.subtotal:draft.subtotal)||
     str(contents.taxEstimate)!==str(revision?revision.tax_estimate:draft.tax_estimate)||
     str(contents.totalEstimate)!==str(revision?revision.total_estimate:draft.total_estimate)||
     !Array.isArray(contents.items)||contents.items.length!==snapshots.length)
    problems.add('QUOTE_HELD_OUTBOX_SCOPE_OR_DISPATCH_INVALID');
  }
 }catch{
  problems.add('QUOTE_UNPARSABLE_OR_MALFORMED_STORED_EVIDENCE');
 }
 const localScopeConsistent=problems.size===0;
 return Object.freeze({kind:'QUOTE',recordId:str(draft.id),
  currentRevision:revisionNumber,localScopeConsistent,
  draftOnly:true,hasInternalReview:!!decision,
  hasDisabledHeldPreparation:!!preparation,
  applicantPriceEvidenceExternallyVerified:false,
  legalCustomerIdentityIndependentlyVerified:false,
  actualInvoiceOrCustomerDispatch:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',
  anomalyCodes:Object.freeze([...problems].sort()),
  externalBlockerCodes:baseline});
}
export function inspectInternalProcurementScope(args:{
 request:Record<string,any>,lines:Record<string,any>[],
 decision?:Record<string,any>|null,hold?:Record<string,any>|null
}){
 const {request:r,lines,decision=null,hold=null}=args;
 const problems=new Set<string>();let total=0n;
 try{
  if(!['PENDING','APPROVED_INTERNAL','REJECTED_INTERNAL'].includes(str(r.status)))
   problems.add('PROCUREMENT_REQUEST_STATE_INVALID');
  if(!Array.isArray(lines)||lines.length<1||lines.length>25)
   problems.add('PROCUREMENT_LINES_INCOMPLETE');
  const seen=new Set<string>();
  for(let i=0;i<lines.length;i++){
   const x=lines[i],id=str(x.product_id),q=num(x.quantity);
   if(!id||seen.has(id)||num(x.position)!==i+1||
      !str(x.sku_snapshot).trim()||
      !Number.isSafeInteger(q)||q<1||q>1000)
    problems.add('PROCUREMENT_LINE_SCOPE_INVALID');
   seen.add(id);
   const cost=paise(str(x.quoted_unit_cost))*BigInt(q);
   if(cost<=0n||str(x.line_subtotal)!==rupees(cost))
    problems.add('PROCUREMENT_QUOTED_COST_SNAPSHOT_CHANGED');
   total+=cost;
  }
  if(total<=0n||str(r.subtotal)!==rupees(total))
   problems.add('PROCUREMENT_TOTAL_MISMATCH');
  if(!str(r.quote_evidence_ref).trim())
   problems.add('MISSING_SUPPLIER_QUOTE_REFERENCE');
  if(decision){
   if(!['APPROVED_INTERNAL','REJECTED_INTERNAL'].includes(str(decision.decision))||
     str(r.status)!==str(decision.decision)||
     str(decision.reviewer_role)!=='REVIEWER'||
     str(decision.reviewer_id)===str(r.created_by)||
     (decision.decision==='APPROVED_INTERNAL'&&!Boolean(decision.evidence_attested))||
     (decision.decision==='APPROVED_INTERNAL'&&
      (str(r.supplier_status)!=='REVIEWED_INTERNAL'||
       str(r.supplier_reviewed_by)===str(r.created_by)||
       str(r.supplier_reviewer_role)!=='REVIEWER')))
    problems.add('PROCUREMENT_REVIEW_OR_SUPPLIER_CUSTODY_INVALID');
  }else if(str(r.status)!=='PENDING')
   problems.add('PROCUREMENT_DECISION_MISSING');
  if(hold){
   const h=hold,snapshot=obj(h.snapshot_json);
   if(!decision||decision.decision!=='APPROVED_INTERNAL'||
     str(h.decision_id)!==str(decision.id)||
     str(h.prepared_by)!==str(r.created_by)||
     str(h.status)!=='HELD'||str(h.dispatch_state)!=='DISABLED'||
     !/^[0-9a-f]{64}$/.test(str(h.snapshot_sha256))||
     !snapshot||snapshot.format!=='aaditech-internal-po-hold-v1'||
     str(snapshot.requestId)!==str(r.id)||
     str(snapshot.supplierId)!==str(r.supplier_id)||
     str(snapshot.siteId)!==str(r.site_id)||
     str(snapshot.supplierQuoteEvidenceRef)!==str(r.quote_evidence_ref)||
     str(snapshot.subtotal)!==str(r.subtotal)||
     str(snapshot.reviewId)!==str(decision.id)||
     !Array.isArray(snapshot.lines)||snapshot.lines.length!==lines.length)
    problems.add('PROCUREMENT_HELD_SNAPSHOT_OR_DISPATCH_INVALID');
  }
 }catch{problems.add('PROCUREMENT_MALFORMED_STORED_EVIDENCE');}
 return Object.freeze({kind:'PROCUREMENT',recordId:str(r.id),
  localScopeConsistent:problems.size===0,hasInternalReview:!!decision,
  hasDisabledHeldPurchaseOrder:!!hold,
  applicantSupplierQuoteExternallyAuthenticated:false,
  supplierCorporateIdentityIndependentlyVerified:false,
  actualSupplierPurchaseOrderIssued:false,
  stockPosted:false,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD',
  anomalyCodes:Object.freeze([...problems].sort()),
  externalBlockerCodes:baseline});
}
