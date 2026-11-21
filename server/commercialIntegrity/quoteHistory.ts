import {createHash} from 'node:crypto';
import {calculateLine,rupees} from '../quotes/money';
import {inspectInternalQuoteScope} from './checks';

// Historical readback is a bounded, INTERNAL MySQL reconciliation only.
// Neither local SHA-256 values nor database rows are a trusted external
// monotonic timestamp, signed authority, provider WORM or production GO.
const LIMIT=1000;
const string=(x:unknown)=>String(x??'');
const number=(x:unknown)=>Number(x);
const revisionFields=['productId','sku','name','hsn','quantity','unitCost',
 'unitPrice','gstRate','lineSubtotal','lineTaxEstimate'];
const initialFields=['product_id','sku_snapshot','name_snapshot','hsn_snapshot',
 'quantity','unit_cost','unit_price','gst_rate','line_subtotal','line_tax_estimate'];
function record(x:unknown):Record<string,any>|null{
 if(x&&typeof x==='object'&&!Array.isArray(x))return x as Record<string,any>;
 return null;
}
function array(x:unknown):unknown[]|null{
 if(Array.isArray(x))return x;
 if(typeof x!=='string'||x.length>1000000)return null;
 try{const v=JSON.parse(x);return Array.isArray(v)?v:null;}catch{return null;}
}
function exact(o:Record<string,any>,keys:string[]){
 return Object.keys(o).sort().join('|')===keys.slice().sort().join('|');
}
function canonicalLine(row:Record<string,any>,revision:boolean){
 if(revision)return {
  productId:row.productId,sku:row.sku,name:row.name,hsn:row.hsn,
  quantity:row.quantity,unitCost:row.unitCost,unitPrice:row.unitPrice,
  gstRate:row.gstRate,lineSubtotal:row.lineSubtotal,
  lineTaxEstimate:row.lineTaxEstimate
 };
 return {
  product_id:row.product_id,sku_snapshot:row.sku_snapshot,
  name_snapshot:row.name_snapshot,hsn_snapshot:row.hsn_snapshot,
  quantity:row.quantity,unit_cost:row.unit_cost,unit_price:row.unit_price,
  gst_rate:row.gst_rate,line_subtotal:row.line_subtotal,
  line_tax_estimate:row.line_tax_estimate
 };
}
function expectedHoldDigest(draft:Record<string,any>,
 lines:Record<string,any>[],revision:Record<string,any>|null,
 review:Record<string,any>){
 const rows=revision?array(revision.line_snapshot):lines;
 if(!rows||rows.length<1||rows.length>40)throw Error('Unusable lines');
 const snapshot={
  format:'aaditech-internal-release-hold-v1',
  quoteId:string(draft.id),revision:revision?number(revision.revision_number):0,
  customerId:string(draft.customer_id),
  leadId:draft.lead_id?string(draft.lead_id):null,
  reviewId:string(review.id),currency:'INR',
  subtotal:string(revision?revision.subtotal:draft.subtotal),
  taxEstimate:string(revision?revision.tax_estimate:draft.tax_estimate),
  totalEstimate:string(revision?revision.total_estimate:draft.total_estimate),
  items:rows.map(item=>canonicalLine(item as Record<string,any>,!!revision))
 };
 // Rebuild the original writer's deterministic field order; JSON column
 // normalization is not a stable byte-for-byte representation of that writer.
 return createHash('sha256').update(JSON.stringify(snapshot)).digest('hex');
}
export function inspectInternalQuoteHistory(args:{
 draft:Record<string,any>,lines:Record<string,any>[],
 revisions:Record<string,any>[],decisions:Record<string,any>[],
 preparations:Record<string,any>[],truncated?:boolean
}){
 const {draft,lines,revisions,decisions,preparations,truncated=false}=args;
 const anomalies=new Set<string>();
 const numeric=(v:unknown)=>Number.isSafeInteger(number(v))&&number(v)>=0;
 if(truncated||revisions.length>LIMIT||decisions.length>LIMIT+1||
    preparations.length>LIMIT+1)
  anomalies.add('HISTORY_INSPECTION_BOUND_EXCEEDED');
 const inspectedRevisions=revisions.slice(0,LIMIT);
 const seenVersions=new Set<number>();
 let prev=0;
 for(const rev of inspectedRevisions){
  const v=number(rev.revision_number);
  if(!numeric(rev.revision_number)||v<1||seenVersions.has(v)||v!==prev+1)
   anomalies.add('HISTORY_REVISION_SEQUENCE_GAP_OR_FORK');
  if(string(rev.quote_id)!==string(draft.id)||
     string(rev.actor_id)!==string(draft.created_by)||
     !string(rev.reason).trim()||string(rev.reason).length>500||
     !['DRAFT_OK','MARGIN_REVIEW_REQUIRED'].includes(string(rev.review_status)))
   anomalies.add('HISTORY_REVISION_AUTHOR_OR_STATE_INVALID');
  const linesOfRevision=array(rev.line_snapshot);
  if(!linesOfRevision||linesOfRevision.length<1||linesOfRevision.length>40)
   anomalies.add('HISTORY_REVISION_LINE_MALFORMED');
  else for(const raw of linesOfRevision){
   const line=record(raw);
   if(!line||!exact(line,revisionFields)){
    anomalies.add('HISTORY_REVISION_LINE_MALFORMED');continue;
   }
   try{
    const computed=calculateLine(string(line.unitPrice),line.quantity,string(line.gstRate));
    if(rupees(computed.subtotal)!==string(line.lineSubtotal)||
       rupees(computed.tax)!==string(line.lineTaxEstimate))
     anomalies.add('HISTORY_REVISION_LINE_MONEY_CHANGED');
   }catch{anomalies.add('HISTORY_REVISION_LINE_MONEY_CHANGED');}
  }
  seenVersions.add(v);prev=v;
 }
 const maxRevision=inspectedRevisions.length?
  number(inspectedRevisions[inspectedRevisions.length-1].revision_number):0;
 const versions=new Map<number,Record<string,any>>();
 for(const rev of inspectedRevisions)if(numeric(rev.revision_number)&&
     number(rev.revision_number)>0)versions.set(number(rev.revision_number),rev);
 const byReview=new Map<number,Record<string,any>>();
 for(const review of decisions){
  const v=number(review.revision_number);
  if(!numeric(review.revision_number)||v>maxRevision||byReview.has(v)||
     (v!==0&&!versions.has(v))||
     string(review.quote_id)!==string(draft.id)){
   anomalies.add('HISTORY_ORPHAN_OR_DUPLICATE_REVIEW');continue;
  }
  byReview.set(v,review);
  const reason=string(review.reason).trim();
  if(reason.length<5||reason.length>1000||
     (string(review.decision)==='APPROVED_INTERNAL'&&
      number(review.gross_margin_bps)<number(review.minimum_margin_bps)&&
      (!Boolean(review.override_requested)||reason.length<20)))
   anomalies.add('HISTORY_REVIEW_POLICY_OR_REASON_INVALID');
 }
 const byHold=new Map<number,Record<string,any>>();
 const seenHoldIds=new Set<string>();
 for(const hold of preparations){
  const v=number(hold.revision_number),id=string(hold.id);
  if(!numeric(hold.revision_number)||v>maxRevision||
     (v!==0&&!versions.has(v))||byHold.has(v)||
     !id||seenHoldIds.has(id)||string(hold.quote_id)!==string(draft.id)){
   anomalies.add('HISTORY_ORPHAN_OR_DUPLICATE_HOLD');continue;
  }
  seenHoldIds.add(id);byHold.set(v,hold);
  if(number(hold.outbox_count)!==1||!string(hold.outbox_id))
   anomalies.add('HISTORY_OUTBOX_MISSING_OR_DUPLICATED');
 }
 // Include original draft (revision 0), even if it has no review or hold.
 // Every previously held revision remains checked after later revisions.
 for(let v=0;v<=maxRevision&&v<=LIMIT;v++){
  const rev=v===0?null:versions.get(v)??null;
  if(v>0&&!rev){anomalies.add('HISTORY_REVISION_SEQUENCE_GAP_OR_FORK');continue;}
  const decision=byReview.get(v)??null,hold=byHold.get(v)??null;
  const scope=inspectInternalQuoteScope({draft,lines,
   revision:rev,decision,preparation:hold});
  if(!scope.localScopeConsistent){
   if(scope.anomalyCodes.some(code=>code.startsWith('REVISION_')))
    anomalies.add('HISTORY_REVISION_SCOPE_INVALID');
   if(scope.anomalyCodes.some(code=>code.startsWith('QUOTE_REVIEW_')||
      code==='QUOTE_BELOW_POLICY_OVERRIDE_MISSING'))
    anomalies.add('HISTORY_REVIEW_SCOPE_INVALID');
   if(scope.anomalyCodes.some(code=>code.startsWith('QUOTE_HELD_')))
    anomalies.add('HISTORY_HELD_SCOPE_INVALID');
   if(scope.anomalyCodes.some(code=>!code.startsWith('REVISION_')&&
      !code.startsWith('QUOTE_REVIEW_')&&
      !code.startsWith('QUOTE_HELD_')&&
      code!=='QUOTE_BELOW_POLICY_OVERRIDE_MISSING'))
    anomalies.add('HISTORY_SOURCE_QUOTE_SCOPE_INVALID');
  }
  if(hold){
   if(!decision||decision.decision!=='APPROVED_INTERNAL'){
    anomalies.add('HISTORY_HOLD_WITHOUT_APPROVED_REVIEW');continue;
   }
   try{
    const computed=expectedHoldDigest(draft,lines,rev,decision);
    if(string(hold.snapshot_sha256)!==computed||
       string(hold.payload_sha256)!==computed)
     anomalies.add('HISTORY_HELD_DIGEST_SOURCE_MISMATCH');
   }catch{anomalies.add('HISTORY_HELD_DIGEST_SOURCE_MISMATCH');}
  }
 }
 return Object.freeze({
  historyInspectionComplete:!truncated&&revisions.length<=LIMIT&&
   decisions.length<=LIMIT+1&&preparations.length<=LIMIT+1,
  historyConsistent:anomalies.size===0,
  inspectedRevisionCount:inspectedRevisions.length,
  inspectedReviewCount:decisions.length,
  inspectedHeldCount:preparations.length,
  inspectedLatestRevision:maxRevision,
  historyAnomalyCodes:Object.freeze([...anomalies].sort()),
  independentHistoricalAnchorVerified:false,
  independentRollbackProofVerified:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
