import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {buildLocalQuoteHistoryCommitment,canonicalCandidateWitnessBody,
 candidateWitnessReceiptDigest,verifyCandidateQuoteWitnessChain,
 type CandidateWitnessBody,type CandidateWitnessReceipt,type CandidatePinnedKey}
 from '../server/commercialIntegrity/quoteAnchors';

const quote='11111111-1111-4111-8111-111111111111';
const actor='22222222-2222-4222-8222-222222222222';
const customer='33333333-3333-4333-8333-333333333333';
const product='44444444-4444-4444-8444-444444444444';
const clone=<T>(x:T):T=>JSON.parse(JSON.stringify(x));
function source(){
 const draft={id:quote,created_by:actor,customer_id:customer,lead_id:null,
  customer_deleted_at:null,status:'DRAFT',currency:'INR',
  subtotal:'200.00',tax_estimate:'36.00',total_estimate:'236.00'};
 const lines=[{id:'55555555-5555-4555-8555-555555555555',
  quote_id:quote,position:1,product_id:product,sku_snapshot:'OEM-1',
  name_snapshot:'Server',hsn_snapshot:'8471',quantity:2,
  unit_cost:'50.00',unit_price:'100.00',gst_rate:'18.00',
  line_subtotal:'200.00',line_tax_estimate:'36.00'}];
 return {draft,lines,revisions:[] as any[],decisions:[] as any[],
  preparations:[] as any[]};
}
function populated(){
 const s=source();
 const review={id:'66666666-6666-4666-8666-666666666666',
  quote_id:quote,revision_number:0,owner_user_id:'77777777-7777-4777-8777-777777777777',
  reviewer_role:'REVIEWER',decision:'APPROVED_INTERNAL',reason:'Internal review only',
  override_requested:0,gross_margin_bps:5000,minimum_margin_bps:1500,subtotal:'200.00'};
 s.decisions.push(review);
 s.preparations.push({id:'88888888-8888-4888-8888-888888888888',quote_id:quote,
  revision_number:0,internal_review_id:review.id,prepared_by:actor,
  snapshot_sha256:'a'.repeat(64),snapshot_json:{
   format:'aaditech-internal-release-hold-v1',quoteId:quote,revision:0,
   customerId:customer,leadId:null,reviewId:review.id,currency:'INR',
   subtotal:'200.00',taxEstimate:'36.00',totalEstimate:'236.00',
   items:s.lines.map(({id,quote_id,position,...item})=>({...item}))
  },status:'HELD',outbox_id:'99999999-9999-4999-8999-999999999999',
  outbox_count:1,event_type:'QUOTE_RELEASE_PREPARATION_HELD',
  dispatch_state:'DISABLED',payload_sha256:'a'.repeat(64)});
 return s;
}
function credentials(keyId:string){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pin:CandidatePinnedKey={keyId,publicKeySpkiPem:publicKey.export({
  type:'spki',format:'pem'}).toString(),status:'ACTIVE',
  validFrom:'2026-11-16T00:00:00.000Z',validUntil:'2026-12-01T00:00:00.000Z'};
 return {pin,privateKey};
}
function make(body:CandidateWitnessBody,privateKey:ReturnType<typeof credentials>['privateKey']){
 const signatureBase64=sign(null,Buffer.from(canonicalCandidateWitnessBody(body)),
  privateKey).toString('base64');
 return {body,signatureBase64};
}
function start(commitment:string,keyId='fixture-key'){
 return {format:'aaditech-quote-history-witness-v1' as const,
  quoteId:quote,sequence:1,revisionNumber:0,
  sourceCommitmentSha256:commitment,
  previousReceiptSha256:null,witnessedAt:'2026-11-17T11:00:00.000Z',
  keyId};
}
test('BL: canonical local digest is deterministic and rejects altered held outbox, money and review records',()=>{
 const s=populated();
 const first=buildLocalQuoteHistoryCommitment(s);
 assert.match(first.sourceCommitmentSha256,/^[0-9a-f]{64}$/);
 assert.equal(first.productionReleaseAuthorized,false);
 assert.equal(first.independentlyPublished,false);
 assert.equal(first.releaseDecision,'HOLD');
 const again=clone(s);
 again.preparations[0].snapshot_json=JSON.stringify(again.preparations[0].snapshot_json);
 assert.equal(buildLocalQuoteHistoryCommitment(again).sourceCommitmentSha256,
  first.sourceCommitmentSha256);
 for(const change of [
  (x:ReturnType<typeof populated>)=>{x.preparations[0].dispatch_state='ENABLED';},
  (x:ReturnType<typeof populated>)=>{x.preparations[0].snapshot_json.items[0].hsn_snapshot='0000';},
  (x:ReturnType<typeof populated>)=>{x.preparations[0].outbox_count=0;},
  (x:ReturnType<typeof populated>)=>{x.decisions[0].owner_user_id=actor;},
  (x:ReturnType<typeof populated>)=>{x.lines[0].line_tax_estimate='0.01';}
 ]){
  const altered=clone(s);change(altered);
  assert.notEqual(buildLocalQuoteHistoryCommitment(altered).sourceCommitmentSha256,
   first.sourceCommitmentSha256);
 }
});
test('BL: changing quoted history after locally captured commitment changes source digest',()=>{
 const s=source(),first=buildLocalQuoteHistoryCommitment(s);
 s.revisions.push({id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',quote_id:quote,
  revision_number:1,actor_id:actor,reason:'Change quantity',subtotal:'300.00',
  tax_estimate:'54.00',total_estimate:'354.00',gross_margin_bps:5000,
  review_status:'DRAFT_OK',line_snapshot:[{productId:product,sku:'OEM-1',
   name:'Server',hsn:'8471',quantity:3,unitCost:'50.00',unitPrice:'100.00',
   gstRate:'18.00',lineSubtotal:'300.00',lineTaxEstimate:'54.00'}]});
 const one=buildLocalQuoteHistoryCommitment(s);
 assert.notEqual(one.sourceCommitmentSha256,first.sourceCommitmentSha256);
 const modified=clone(s);
 modified.revisions[0].line_snapshot=JSON.stringify(modified.revisions[0].line_snapshot);
 assert.equal(buildLocalQuoteHistoryCommitment(modified).sourceCommitmentSha256,
  one.sourceCommitmentSha256);
 modified.revisions[0].line_snapshot='invalid-json';
 assert.throws(()=>buildLocalQuoteHistoryCommitment(modified));
});
test('BL: valid offline synthetic Ed25519 receipt chain is cryptographic candidate only',()=>{
 const digest0=buildLocalQuoteHistoryCommitment(source()).sourceCommitmentSha256;
 const digest1=buildLocalQuoteHistoryCommitment(populated()).sourceCommitmentSha256;
 const a=credentials('fixture-key'),b=credentials('rotated-key');
 const first=make(start(digest0),a.privateKey);
 const secondBody:CandidateWitnessBody={...start(digest1,'rotated-key'),
  sequence:2,revisionNumber:0,
  previousReceiptSha256:candidateWitnessReceiptDigest(first),
  witnessedAt:'2026-11-17T11:01:00.000Z'};
 const second=make(secondBody,b.privateKey);
 const result=verifyCandidateQuoteWitnessChain({
  quoteId:quote,expectedSourceCommitmentSha256:digest1,
  receipts:[first,second],pinnedKeys:[a.pin,b.pin]});
 assert.equal(result.candidateWitnessChainConsistent,true,
  result.witnessAnomalyCodes.join(','));
 assert.match(result.candidateWitnessHeadSha256!,/^[0-9a-f]{64}$/);
 assert.equal(result.independentWitnessAuthorityAuthenticated,false);
 assert.equal(result.independentWitnessRevocationAuthenticated,false);
 assert.equal(result.independentlyPublishedHeadVerified,false);
 assert.equal(result.independentRollbackProofVerified,false);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.releaseDecision,'HOLD');
});
test('BL: revoked/unknown pin, unpinned replacement and bad signature fail closed',()=>{
 const digest=buildLocalQuoteHistoryCommitment(source()).sourceCommitmentSha256;
 const a=credentials('fixture-key'),receipt=make(start(digest),a.privateKey);
 for(const keys of [
  [] as CandidatePinnedKey[],
  [{...a.pin,status:'REVOKED' as const}],
  [{...a.pin,status:'UNKNOWN' as const}],
  [credentials('fixture-key').pin],
  [{...a.pin,validUntil:'2026-11-17T10:59:59.000Z'}],
  [a.pin,a.pin]
 ]){
  const outcome=verifyCandidateQuoteWitnessChain({quoteId:quote,
   expectedSourceCommitmentSha256:digest,receipts:[receipt],pinnedKeys:keys});
  assert.equal(outcome.candidateWitnessChainConsistent,false,JSON.stringify(keys.map(k=>k.status)));
  assert.equal(outcome.productionReleaseAuthorized,false);
 }
 const tampered=clone(receipt);tampered.body.revisionNumber=5;
 assert.ok(verifyCandidateQuoteWitnessChain({quoteId:quote,
  expectedSourceCommitmentSha256:digest,receipts:[tampered],
  pinnedKeys:[a.pin]}).witnessAnomalyCodes.includes('WITNESS_SIGNATURE_INVALID'));
});
test('BL: truncated, replayed, stale, shadow, wrong-source and cross-quote receipts fail closed',()=>{
 const digest=buildLocalQuoteHistoryCommitment(source()).sourceCommitmentSha256;
 const a=credentials('fixture-key'),first=make(start(digest),a.privateKey);
 const second=make({...start(digest),sequence:2,
  previousReceiptSha256:candidateWitnessReceiptDigest(first),
  witnessedAt:'2026-11-17T11:01:00.000Z'},a.privateKey);
 const good={quoteId:quote,expectedSourceCommitmentSha256:digest,
  receipts:[first,second],pinnedKeys:[a.pin]};
 assert.equal(verifyCandidateQuoteWitnessChain(good).candidateWitnessChainConsistent,true);
 for(const receipts of [
  [first,first],
  [first,make({...second.body,previousReceiptSha256:'f'.repeat(64)},a.privateKey)],
  [first,make({...second.body,witnessedAt:first.body.witnessedAt},a.privateKey)],
  [first,make({...second.body,revisionNumber:-1},a.privateKey)],
  [first,{...second,body:{...second.body,recipient:'outbound@example.invalid'}} as any],
  [first,{...second,body:{...second.body,quoteId:customer}}]
 ]){
  const result=verifyCandidateQuoteWitnessChain({...good,receipts});
  assert.equal(result.candidateWitnessChainConsistent,false);
  assert.equal(result.productionReleaseAuthorized,false);
 }
 const stale=verifyCandidateQuoteWitnessChain({...good,
  expectedSourceCommitmentSha256:'f'.repeat(64)});
 assert.ok(stale.witnessAnomalyCodes.includes('WITNESS_SOURCE_HEAD_MISMATCH'));
 const missing=verifyCandidateQuoteWitnessChain({...good,receipts:[]});
 assert.ok(missing.witnessAnomalyCodes.includes('WITNESS_EVIDENCE_ABSENT'));
 const malformed=verifyCandidateQuoteWitnessChain({...good,receipts:[null as any]});
 assert.equal(malformed.candidateWitnessChainConsistent,false);
});
test('BL: upper-bounded sources and witness chains never become external release authorization',()=>{
 const s=source();const many=Array(1001).fill(null).map((_,i)=>({
  id:String(i),quote_id:quote,revision_number:i+1}));
 assert.throws(()=>buildLocalQuoteHistoryCommitment({...s,revisions:many}));
 const d=buildLocalQuoteHistoryCommitment(s).sourceCommitmentSha256;
 const a=credentials('fixture-key'),r=make(start(d),a.privateKey);
 const out=verifyCandidateQuoteWitnessChain({quoteId:quote,
  expectedSourceCommitmentSha256:d,receipts:Array(33).fill(r),pinnedKeys:[a.pin]});
 assert.equal(out.candidateWitnessChainConsistent,false);
 assert.ok(out.witnessAnomalyCodes.includes('WITNESS_SEQUENCE_BOUND_EXCEEDED'));
 assert.equal(out.productionReleaseBlocked,true);
});
