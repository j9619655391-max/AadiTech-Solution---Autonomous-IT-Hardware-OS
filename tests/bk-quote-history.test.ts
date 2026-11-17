import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspectInternalQuoteHistory} from '../server/commercialIntegrity/quoteHistory';

const actor='11111111-1111-4111-8111-111111111111';
const reviewer='22222222-2222-4222-8222-222222222222';
const id='33333333-3333-4333-8333-333333333333';
const customer='44444444-4444-4444-8444-444444444444';
const product='55555555-5555-4555-8555-555555555555';
const copy=<T>(x:T):T=>JSON.parse(JSON.stringify(x));
function fixture(){
 const draft={id,created_by:actor,customer_id:customer,lead_id:null,
  customer_deleted_at:null,status:'DRAFT',currency:'INR',
  subtotal:'100.00',tax_estimate:'18.00',total_estimate:'118.00'};
 const lines=[{product_id:product,position:1,sku_snapshot:'OEM-SRV',
  name_snapshot:'Server',hsn_snapshot:'8471',quantity:1,
  unit_cost:'50.00',unit_price:'100.00',gst_rate:'18.00',
  line_subtotal:'100.00',line_tax_estimate:'18.00'}];
 const decision={id:reviewer,quote_id:id,revision_number:0,
  owner_user_id:reviewer,reviewer_role:'REVIEWER',
  decision:'APPROVED_INTERNAL',reason:'Internal test approval only',
  override_requested:0,gross_margin_bps:5000,
  minimum_margin_bps:1500,subtotal:'100.00'};
 const snapshot={
  format:'aaditech-internal-release-hold-v1',
  quoteId:id,revision:0,customerId:customer,leadId:null,
  reviewId:reviewer,currency:'INR',subtotal:'100.00',
  taxEstimate:'18.00',totalEstimate:'118.00',
  items:lines.map(({position,...row})=>row)
 };
 const digest=createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');
 const hold={id:'66666666-6666-4666-8666-666666666666',
  quote_id:id,revision_number:0,internal_review_id:reviewer,
  prepared_by:actor,snapshot_sha256:digest,payload_sha256:digest,
  status:'HELD',dispatch_state:'DISABLED',
  event_type:'QUOTE_RELEASE_PREPARATION_HELD',
  outbox_count:1,outbox_id:'77777777-7777-4777-8777-777777777777',
  snapshot_json:snapshot};
 return {draft,lines,revisions:[] as any[],decisions:[decision] as any[],
  preparations:[hold] as any[]};
}
function revision(number=1){
 return {id:'88888888-8888-4888-8888-888888888888',
  quote_id:id,revision_number:number,actor_id:actor,reason:'Internal quantity update',
  subtotal:'200.00',tax_estimate:'36.00',total_estimate:'236.00',
  gross_margin_bps:5000,review_status:'DRAFT_OK',
  line_snapshot:[{productId:product,sku:'OEM-SRV',name:'Server',hsn:'8471',
   quantity:2,unitCost:'50.00',unitPrice:'100.00',gstRate:'18.00',
   lineSubtotal:'200.00',lineTaxEstimate:'36.00'}]};
}
test('BK: exact old held draft and digest are consistent without granting external authority',()=>{
 const result=inspectInternalQuoteHistory(fixture());
 assert.equal(result.historyConsistent,true,result.historyAnomalyCodes.join(','));
 assert.equal(result.inspectedLatestRevision,0);
 assert.equal(result.inspectedReviewCount,1);
 assert.equal(result.inspectedHeldCount,1);
 assert.equal(result.independentHistoricalAnchorVerified,false);
 assert.equal(result.independentRollbackProofVerified,false);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.releaseDecision,'HOLD');
});
test('BK: older approved hold must stay valid after later unreviewed draft revision',()=>{
 const x=fixture();x.revisions.push(revision());
 const good=inspectInternalQuoteHistory(x);
 assert.equal(good.historyConsistent,true,good.historyAnomalyCodes.join(','));
 const y=copy(x);
 y.preparations[0].snapshot_json.items[0].hsn_snapshot='FORGED';
 const result=inspectInternalQuoteHistory(y);
 assert.equal(result.historyConsistent,false);
 assert.ok(result.historyAnomalyCodes.includes('HISTORY_HELD_SCOPE_INVALID'));
 assert.equal(result.releaseDecision,'HOLD');
});
test('BK: sparse, duplicate or unauthorized historical revision and review lineage fails closed',()=>{
 const gap=fixture();gap.revisions.push(revision(3));
 assert.ok(inspectInternalQuoteHistory(gap).historyAnomalyCodes.includes(
  'HISTORY_REVISION_SEQUENCE_GAP_OR_FORK'));
 const badAuthor=fixture();badAuthor.revisions.push(revision());badAuthor.revisions[0].actor_id=reviewer;
 assert.ok(inspectInternalQuoteHistory(badAuthor).historyAnomalyCodes.includes(
  'HISTORY_REVISION_AUTHOR_OR_STATE_INVALID'));
 const duplicateReview=fixture();duplicateReview.decisions.push({...duplicateReview.decisions[0],id:actor});
 assert.ok(inspectInternalQuoteHistory(duplicateReview).historyAnomalyCodes.includes(
  'HISTORY_ORPHAN_OR_DUPLICATE_REVIEW'));
 const orphanReview=fixture();orphanReview.decisions[0].revision_number=9;
 assert.ok(inspectInternalQuoteHistory(orphanReview).historyAnomalyCodes.includes(
  'HISTORY_ORPHAN_OR_DUPLICATE_REVIEW'));
});
test('BK: old hold missing/out-of-policy review, missing outbox and replayed hold are rejected',()=>{
 const absent=fixture();absent.decisions=[];
 assert.ok(inspectInternalQuoteHistory(absent).historyAnomalyCodes.includes(
  'HISTORY_HOLD_WITHOUT_APPROVED_REVIEW'));
 const outbox=fixture();outbox.preparations[0].outbox_count=0;
 assert.ok(inspectInternalQuoteHistory(outbox).historyAnomalyCodes.includes(
  'HISTORY_OUTBOX_MISSING_OR_DUPLICATED'));
 const duplicate=fixture();duplicate.preparations.push({...duplicate.preparations[0]});
 assert.ok(inspectInternalQuoteHistory(duplicate).historyAnomalyCodes.includes(
  'HISTORY_ORPHAN_OR_DUPLICATE_HOLD'));
 const policy=fixture();policy.decisions[0].minimum_margin_bps=6000;
 assert.ok(inspectInternalQuoteHistory(policy).historyAnomalyCodes.includes(
  'HISTORY_REVIEW_POLICY_OR_REASON_INVALID'));
});
test('BK: changed local digest, revision tax math and injected extra revision keys reject',()=>{
 const hash=fixture();hash.preparations[0].snapshot_sha256='b'.repeat(64);
 assert.ok(inspectInternalQuoteHistory(hash).historyAnomalyCodes.includes(
  'HISTORY_HELD_DIGEST_SOURCE_MISMATCH'));
 const tax=fixture();tax.revisions.push(revision());
 tax.revisions[0].line_snapshot[0].lineTaxEstimate='0.01';
 assert.ok(inspectInternalQuoteHistory(tax).historyAnomalyCodes.includes(
  'HISTORY_REVISION_LINE_MONEY_CHANGED'));
 const injection=fixture();injection.revisions.push(revision());
 injection.revisions[0].line_snapshot[0].dispatchEnabled=true;
 assert.ok(inspectInternalQuoteHistory(injection).historyAnomalyCodes.includes(
  'HISTORY_REVISION_LINE_MALFORMED'));
});
test('BK: incomplete bounded inspection refuses authority and consistency',()=>{
 const x=fixture();const outcome=inspectInternalQuoteHistory({...x,truncated:true});
 assert.equal(outcome.historyInspectionComplete,false);
 assert.equal(outcome.historyConsistent,false);
 assert.ok(outcome.historyAnomalyCodes.includes('HISTORY_INSPECTION_BOUND_EXCEEDED'));
 assert.equal(outcome.productionReleaseAuthorized,false);
});
