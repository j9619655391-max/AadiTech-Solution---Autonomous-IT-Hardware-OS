import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectInternalQuoteScope,inspectInternalProcurementScope}
 from '../server/commercialIntegrity/checks';

const actor='11111111-1111-4111-8111-111111111111',
 reviewer='22222222-2222-4222-8222-222222222222',
 customer='33333333-3333-4333-8333-333333333333',
 product='44444444-4444-4444-8444-444444444444',
 quote='55555555-5555-4555-8555-555555555555',
 request='66666666-6666-4666-8666-666666666666',
 supplier='77777777-7777-4777-8777-777777777777',
 site='88888888-8888-4888-8888-888888888888',
 sha='a'.repeat(64);
function sampleQuote(){
 const draft={id:quote,created_by:actor,customer_id:customer,customer_deleted_at:null,
  status:'DRAFT',currency:'INR',lead_id:null,subtotal:'200.00',tax_estimate:'36.00',total_estimate:'236.00'};
 const lines=[{product_id:product,position:1,sku_snapshot:'Q-SRV-1',
  name_snapshot:'Test Server',hsn_snapshot:'8471',quantity:2,
  unit_price:'100.00',unit_cost:'50.00',gst_rate:'18.00',
  line_subtotal:'200.00',line_tax_estimate:'36.00'}];
 const decision={id:reviewer,revision_number:0,decision:'APPROVED_INTERNAL',
  owner_user_id:reviewer,reviewer_role:'REVIEWER',
  gross_margin_bps:5000,minimum_margin_bps:1500,subtotal:'200.00',
  override_requested:0};
 const preparation={status:'HELD',dispatch_state:'DISABLED',
  event_type:'QUOTE_RELEASE_PREPARATION_HELD',snapshot_sha256:sha,payload_sha256:sha,
  revision_number:0,internal_review_id:reviewer,prepared_by:actor,
  snapshot_json:{
   format:'aaditech-internal-release-hold-v1',quoteId:quote,revision:0,
   customerId:customer,leadId:null,currency:'INR',reviewId:reviewer,subtotal:'200.00',
   taxEstimate:'36.00',totalEstimate:'236.00',items:lines.map(({position,...x})=>({...x}))
  }};
 return {draft,lines,decision,preparation};
}
function sampleProcurement(){
 const requisition={id:request,created_by:actor,supplier_id:supplier,site_id:site,
  supplier_status:'REVIEWED_INTERNAL',supplier_code:'SUP-1',supplier_name:'Test Supplier',supplier_reviewed_by:reviewer,
  supplier_reviewer_role:'REVIEWER',quote_evidence_ref:'EXTERNAL-UNVERIFIED-CANDIDATE',
  subtotal:'300.00',status:'APPROVED_INTERNAL'};
 const lines=[{product_id:product,position:1,sku_snapshot:'Q-SRV-1',
  name_snapshot:'Test Server',quantity:2,quoted_unit_cost:'150.00',line_subtotal:'300.00'}];
 const decision={id:reviewer,decision:'APPROVED_INTERNAL',reviewer_id:reviewer,
  reviewer_role:'REVIEWER',evidence_attested:1};
 const hold={id:'held',decision_id:reviewer,prepared_by:actor,
  status:'HELD',dispatch_state:'DISABLED',snapshot_sha256:sha,
  snapshot_json:{format:'aaditech-internal-po-hold-v1',
   requestId:request,supplierId:supplier,supplierCode:'SUP-1',supplierName:'Test Supplier',siteId:site,
   supplierQuoteEvidenceRef:requisition.quote_evidence_ref,subtotal:'300.00',
   reviewId:reviewer,lines:[{
    productId:product,sku:'Q-SRV-1',name:'Test Server',
    quantity:2,quotedUnitCost:'150.00',lineSubtotal:'300.00'
   }]
  }};
 return {request:requisition,lines,decision,hold};
}
test('internal quote mathematical and review hold consistency does not authorize issuance',()=>{
 const r=inspectInternalQuoteScope(sampleQuote());
 assert.equal(r.localScopeConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.hasInternalReview,true);
 assert.equal(r.hasDisabledHeldPreparation,true);
 assert.equal(r.applicantPriceEvidenceExternallyVerified,false);
 assert.equal(r.legalCustomerIdentityIndependentlyVerified,false);
 assert.equal(r.actualInvoiceOrCustomerDispatch,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.ok(r.externalBlockerCodes.length>0);
});
test('altered quote money, margin, wrong reviewer, fake outbox state or forged line all fail closed',()=>{
 for(const field of ['draft','lines','decision','preparation'] as const){
  const x=sampleQuote();
  if(field==='draft')x.draft.total_estimate='236.01';
  if(field==='lines')x.lines[0].unit_price='999.00';
  if(field==='decision')x.decision.owner_user_id=actor;
  if(field==='preparation')x.preparation.dispatch_state='ENABLED';
  const r=inspectInternalQuoteScope(x);
  assert.equal(r.localScopeConsistent,false,field);
  assert.equal(r.productionReleaseAuthorized,false);
 }
 const m=sampleQuote();
 m.decision.gross_margin_bps=9999;
 assert.ok(inspectInternalQuoteScope(m).anomalyCodes.includes('QUOTE_REVIEW_MARGIN_SNAPSHOT_CHANGED'));
 const n=sampleQuote();
 n.preparation.snapshot_json.items[0].quantity=999;
 assert.ok(inspectInternalQuoteScope(n).anomalyCodes.includes('QUOTE_HELD_OUTBOX_LINE_BINDING_CHANGED'));
});
test('unreviewed internal quote draft may be mathematically consistent but never external',()=>{
 const x=sampleQuote(),r=inspectInternalQuoteScope({
  draft:x.draft,lines:x.lines,decision:null,preparation:null
 });
 assert.equal(r.localScopeConsistent,true);
 assert.equal(r.hasInternalReview,false);
 assert.equal(r.actualInvoiceOrCustomerDispatch,false);
});
test('held internal purchase order is not supplier-issued, stock-posted, legally authenticated',()=>{
 const r=inspectInternalProcurementScope(sampleProcurement());
 assert.equal(r.localScopeConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.hasInternalReview,true);
 assert.equal(r.hasDisabledHeldPurchaseOrder,true);
 assert.equal(r.applicantSupplierQuoteExternallyAuthenticated,false);
 assert.equal(r.supplierCorporateIdentityIndependentlyVerified,false);
 assert.equal(r.actualSupplierPurchaseOrderIssued,false);
 assert.equal(r.stockPosted,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('claimed supplier price manipulation, same-person review, forged hold or wrong price evidence refuses',()=>{
 for(const field of ['money','reviewer','source','dispatch','heldLine']){
  const x=sampleProcurement();
  if(field==='money')x.lines[0].line_subtotal='9.00';
  if(field==='reviewer')x.decision.reviewer_id=actor;
  if(field==='source')x.request.quote_evidence_ref='ALTERED-EVIDENCE-REF';
  if(field==='dispatch')x.hold.dispatch_state='ENABLED';
  if(field==='heldLine')x.hold.snapshot_json.lines[0].quotedUnitCost='999.00';
  const r=inspectInternalProcurementScope(x);
  assert.equal(r.localScopeConsistent,false,field);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('malformed or unauthorized number fields fail without releasing orders',()=>{
 const x=sampleQuote();
 x.lines[0].unit_price='1e99';
 const a=inspectInternalQuoteScope(x);
 assert.equal(a.localScopeConsistent,false);
 assert.equal(a.releaseDecision,'HOLD');
 const p=sampleProcurement();
 p.lines[0].quantity=-1;
 const b=inspectInternalProcurementScope(p);
 assert.equal(b.localScopeConsistent,false);
 assert.equal(b.productionReleaseAuthorized,false);
});

test('Phase 1BJ: held quote rejects metadata and previously ignored product/tax fields',()=>{
 const cases:[string,(x:ReturnType<typeof sampleQuote>)=>void][]=[
  ['hsn',x=>{x.preparation.snapshot_json.items[0].hsn_snapshot='9999';}],
  ['tax',x=>{x.preparation.snapshot_json.items[0].line_tax_estimate='0.00';}],
  ['sku',x=>{x.preparation.snapshot_json.items[0].sku_snapshot='SWAPPED';}],
  ['name',x=>{x.preparation.snapshot_json.items[0].name_snapshot='Replacement';}],
  ['gst',x=>{x.preparation.snapshot_json.items[0].gst_rate='0.00';}],
  ['currency',x=>{x.preparation.snapshot_json.currency='USD';}],
  ['lead',x=>{x.preparation.snapshot_json.leadId=customer;}],
  ['recipient',x=>{(x.preparation.snapshot_json as any).recipientEmail='unauthorized@example.invalid';}],
  ['item shadow field',x=>{(x.preparation.snapshot_json.items[0] as any).dispatchEnabled=true;}]
 ];
 for(const [name,tamper] of cases){
  const x=sampleQuote();tamper(x);
  const result=inspectInternalQuoteScope(x);
  assert.equal(result.localScopeConsistent,false,name);
  assert.equal(result.releaseDecision,'HOLD');
 }
});
test('Phase 1BJ: held revision cannot silently change tax or HSN but accepts matching revision',()=>{
 const x=sampleQuote();
 const revisionLine={productId:product,sku:'Q-SRV-1',name:'Test Server',
  hsn:'8471',quantity:2,unitCost:'50.00',unitPrice:'100.00',gstRate:'18.00',
  lineSubtotal:'200.00',lineTaxEstimate:'36.00'};
 const revision={revision_number:1,line_snapshot:[revisionLine],
  subtotal:'200.00',tax_estimate:'36.00',total_estimate:'236.00',
  gross_margin_bps:5000};
 x.decision.revision_number=1;
 x.preparation.revision_number=1;
 x.preparation.snapshot_json.revision=1;
 x.preparation.snapshot_json.items=[{...revisionLine} as any] as any;
 assert.equal(inspectInternalQuoteScope({...x,revision}).localScopeConsistent,true);
 (x.preparation.snapshot_json.items[0] as any).hsn='0000';
 assert.ok(inspectInternalQuoteScope({...x,revision}).anomalyCodes.includes(
  'QUOTE_HELD_OUTBOX_LINE_BINDING_CHANGED'));
});
test('Phase 1BJ: held PO rejects supplier-label changes and shadow dispatch metadata',()=>{
 for(const tamper of [
  (x:ReturnType<typeof sampleProcurement>)=>{x.hold.snapshot_json.supplierCode='ANOTHER';},
  (x:ReturnType<typeof sampleProcurement>)=>{x.hold.snapshot_json.supplierName='Impersonator';},
  (x:ReturnType<typeof sampleProcurement>)=>{(x.hold.snapshot_json as any).recipient='forged';},
  (x:ReturnType<typeof sampleProcurement>)=>{(x.hold.snapshot_json.lines[0] as any).dispatchEnabled=true;}
 ]){
  const x=sampleProcurement();tamper(x);
  const r=inspectInternalProcurementScope(x);
  assert.equal(r.localScopeConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.releaseDecision,'HOLD');
 }
});
