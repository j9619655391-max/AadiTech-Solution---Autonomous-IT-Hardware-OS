import {createHash,createPublicKey,verify} from 'node:crypto';

// Phase 1BL: INTERNAL source snapshot commitment and offline candidate-witness
// verification. No private keys, external network, trust-pin enrollment,
// authority import, witness publication or customer dispatch occur here.
// The caller must obtain external pins, revocation and published heads through
// independently approved channels. A cryptographically valid synthetic packet
// is NEVER independent provider evidence or production authorization.
type Row=Record<string,any>;
export type QuoteCommitmentSource={
 draft:Row,lines:Row[],revisions:Row[],decisions:Row[],preparations:Row[]
};
const hex=/^[0-9a-f]{64}$/;
const keyId=/^[a-zA-Z0-9._:-]{1,96}$/;
const fields=(o:Row,expected:string[])=>Object.keys(o).sort().join('|')===
 expected.slice().sort().join('|');
const sha=(x:string)=>createHash('sha256').update(x,'utf8').digest('hex');
const str=(x:unknown)=>String(x??'');
function parsedJson(x:unknown):unknown{
 if(typeof x!=='string')return x;
 if(x.length>1000000)throw Error('JSON source bound exceeded');
 return JSON.parse(x);
}
function normalize(x:unknown):unknown{
 if(x===null)return null;
 if(x instanceof Date){
  if(!Number.isFinite(x.getTime()))throw Error('Invalid source time');
  return x.toISOString();
 }
 if(typeof x==='string'){
  if(x.length>1000000)throw Error('Source value exceeds bound');
  return x;
 }
 if(typeof x==='number'){
  if(!Number.isFinite(x))throw Error('Non-finite source number');
  return x;
 }
 if(typeof x==='boolean')return x;
 if(Array.isArray(x)){
  if(x.length>1002)throw Error('Source array exceeds bound');
  return x.map(normalize);
 }
 if(x&&typeof x==='object'){
  const r=x as Row,keys=Object.keys(r).sort();
  if(keys.length>80||keys.some(k=>k==='__proto__'||k==='constructor'||
     k==='prototype'))throw Error('Invalid source shape');
  const result:Row={};
  for(const k of keys){
   if(r[k]===undefined)throw Error('Undefined source value');
   result[k]=normalize(r[k]);
  }
  return result;
 }
 throw Error('Unsupported source value');
}
const select=(row:Row,keys:string[])=>{
 const out:Row={};
 for(const k of keys){
  if(!(k in row))throw Error('Missing source field '+k);
  out[k]=row[k];
 }
 return out;
};
const draftFields=['id','created_by','customer_id','lead_id','status','currency',
 'subtotal','tax_estimate','total_estimate','customer_deleted_at'];
const lineFields=['id','quote_id','position','product_id','sku_snapshot',
 'name_snapshot','hsn_snapshot','quantity','unit_cost','unit_price','gst_rate',
 'line_subtotal','line_tax_estimate'];
const revisionFields=['id','quote_id','revision_number','actor_id','reason',
 'subtotal','tax_estimate','total_estimate','gross_margin_bps','review_status','line_snapshot'];
const decisionFields=['id','quote_id','revision_number','owner_user_id',
 'reviewer_role','decision','reason','override_requested','gross_margin_bps',
 'minimum_margin_bps','subtotal'];
const preparationFields=['id','quote_id','revision_number','internal_review_id',
 'prepared_by','snapshot_sha256','snapshot_json','status','outbox_id',
 'outbox_count','event_type','dispatch_state','payload_sha256'];
const project=(r:Row,keys:string[],jsonFields:string[]=[])=>{
 const row=select(r,keys);
 for(const k of jsonFields)row[k]=parsedJson(row[k]);
 return normalize(row);
};
export function buildLocalQuoteHistoryCommitment(source:QuoteCommitmentSource){
 const {draft,lines,revisions,decisions,preparations}=source;
 if(!Array.isArray(lines)||lines.length<1||lines.length>40||
    !Array.isArray(revisions)||revisions.length>1000||
    !Array.isArray(decisions)||decisions.length>1001||
    !Array.isArray(preparations)||preparations.length>1001)
  throw Error('Quote commitment source not bounded');
 const versions=new Set<number>();
 for(const r of revisions){
  const version=Number(r.revision_number);
  if(!Number.isSafeInteger(version)||version<1||versions.has(version))
   throw Error('Duplicate or invalid commitment revision');
  versions.add(version);
 }
 // Explicit source-field projection excludes server query ordering and
 // MySQL JSON serialization details; all business-critical held values and
 // the outbox state remain in the commitment.
 const body={
  format:'aaditech-quote-history-source-v1',
  quoteId:str(draft.id),
  draft:project(draft,draftFields),
  lines:lines.map(r=>project(r,lineFields)),
  revisions:revisions.map(r=>project(r,revisionFields,['line_snapshot']))
   .sort((a:any,b:any)=>a.revision_number-b.revision_number),
  decisions:decisions.map(r=>project(r,decisionFields))
   .sort((a:any,b:any)=>a.revision_number-b.revision_number),
  preparations:preparations.map(r=>project(r,preparationFields,['snapshot_json']))
   .sort((a:any,b:any)=>a.revision_number-b.revision_number)
 };
 const material=JSON.stringify(normalize(body));
 const sourceCommitmentSha256=sha('aaditech/quote/history/source/v1\n'+material);
 return Object.freeze({
  commitmentFormat:'aaditech-quote-history-source-v1',
  quoteId:str(draft.id),sourceCommitmentSha256,
  revisionCount:revisions.length,reviewCount:decisions.length,
  holdCount:preparations.length,
  independentlyPublished:false,
  independentRollbackProofVerified:false,
  productionReleaseAuthorized:false,releaseDecision:'HOLD'
 });
}
export type CandidateWitnessBody={
 format:'aaditech-quote-history-witness-v1',quoteId:string,sequence:number,
 revisionNumber:number,sourceCommitmentSha256:string,
 previousReceiptSha256:string|null,witnessedAt:string,keyId:string
};
export type CandidateWitnessReceipt={body:CandidateWitnessBody,signatureBase64:string};
export type CandidatePinnedKey={
 keyId:string,publicKeySpkiPem:string,status:'ACTIVE'|'REVOKED'|'UNKNOWN',
 validFrom:string,validUntil:string
};
const witnessFields=['format','quoteId','sequence','revisionNumber',
 'sourceCommitmentSha256','previousReceiptSha256','witnessedAt','keyId'];
const utc=(x:unknown):number|null=>{
 if(typeof x!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x))return null;
 const ms=Date.parse(x);
 return Number.isFinite(ms)&&new Date(ms).toISOString()===x?ms:null;
};
export function canonicalCandidateWitnessBody(body:CandidateWitnessBody){
 return JSON.stringify(normalize(body));
}
export function candidateWitnessReceiptDigest(receipt:CandidateWitnessReceipt){
 return sha('aaditech/quote/history/receipt/v1\n'+
  JSON.stringify(normalize(receipt)));
}
export function verifyCandidateQuoteWitnessChain(args:{
 quoteId:string,expectedSourceCommitmentSha256:string,
 receipts:CandidateWitnessReceipt[],pinnedKeys:CandidatePinnedKey[]
}){
 const errors=new Set<string>();
 const {quoteId,expectedSourceCommitmentSha256,receipts,pinnedKeys}=args;
 const pins=new Map<string,CandidatePinnedKey>();
 for(const key of pinnedKeys){
  if(!key||!keyId.test(str(key.keyId))||pins.has(key.keyId)||
     !['ACTIVE','REVOKED','UNKNOWN'].includes(key.status)||
     utc(key.validFrom)===null||utc(key.validUntil)===null||
     (utc(key.validFrom) as number)>=(utc(key.validUntil) as number)){
   errors.add('WITNESS_PINSET_AMBIGUOUS_OR_INVALID');continue;
  }
  pins.set(key.keyId,key);
 }
 if(!hex.test(expectedSourceCommitmentSha256))
  errors.add('WITNESS_SOURCE_COMMITMENT_INVALID');
 if(!Array.isArray(receipts)||receipts.length===0)
  errors.add('WITNESS_EVIDENCE_ABSENT');
 if(!Array.isArray(receipts)||receipts.length>32)
  errors.add('WITNESS_SEQUENCE_BOUND_EXCEEDED');
 let previousReceipt:string|null=null,previousTime=-1,previousRevision=-1;
 const safeReceipts=Array.isArray(receipts)?receipts.slice(0,32):[];
 for(let i=0;i<safeReceipts.length;i++){
  const r=safeReceipts[i],b=r?.body;
  if(!r||typeof r!=='object'||Array.isArray(r)||
     !b||typeof b!=='object'||Array.isArray(b)||
     !fields(r as Row,['body','signatureBase64'])||
     !fields(b as Row,witnessFields)||
     b.format!=='aaditech-quote-history-witness-v1'||
     b.quoteId!==quoteId||
     !Number.isSafeInteger(b.sequence)||b.sequence!==i+1||
     !Number.isSafeInteger(b.revisionNumber)||b.revisionNumber<0||
     b.revisionNumber<previousRevision||
     !hex.test(str(b.sourceCommitmentSha256))||
     b.previousReceiptSha256!==previousReceipt||
     !keyId.test(str(b.keyId))){
   errors.add('WITNESS_PAYLOAD_SEQUENCE_OR_PARENT_INVALID');continue;
  }
  const time=utc(b.witnessedAt);
  if(time===null||time<=previousTime)
   errors.add('WITNESS_TIMESTAMP_ORDER_INVALID');
  const pin=pins.get(b.keyId);
  if(!pin||pin.status!=='ACTIVE')
   errors.add('WITNESS_KEY_NOT_ACTIVE_OR_PINNED');
  else if(time===null||(utc(pin.validFrom) as number)>time||
      (utc(pin.validUntil) as number)<time)
   errors.add('WITNESS_PIN_VALIDITY_WINDOW_INVALID');
  try{
   if(typeof r.signatureBase64!=='string'||r.signatureBase64.length>128||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(r.signatureBase64))
    throw Error('Malformed signature');
   const signature=Buffer.from(r.signatureBase64,'base64');
   if(signature.length!==64||signature.toString('base64')!==r.signatureBase64)
    throw Error('Noncanonical signature');
   if(!pin)throw Error('No trusted pin');
   const pub=createPublicKey(pin.publicKeySpkiPem);
   if(pub.asymmetricKeyType!=='ed25519'||
      !verify(null,Buffer.from(canonicalCandidateWitnessBody(b)),pub,signature))
    throw Error('Unverified signature');
  }catch{errors.add('WITNESS_SIGNATURE_INVALID');}
  try{previousReceipt=candidateWitnessReceiptDigest(r);}
  catch{errors.add('WITNESS_RECEIPT_MALFORMED');}
  if(time!==null)previousTime=time;
  previousRevision=b.revisionNumber;
 }
 if(safeReceipts.length&&safeReceipts.at(-1)?.body?.sourceCommitmentSha256!==
    expectedSourceCommitmentSha256)
  errors.add('WITNESS_SOURCE_HEAD_MISMATCH');
 return Object.freeze({
  candidateWitnessChainConsistent:errors.size===0,
  candidateWitnessCount:safeReceipts.length,
  candidateWitnessHeadSha256:errors.size===0?previousReceipt:null,
  witnessAnomalyCodes:Object.freeze([...errors].sort()),
  independentWitnessAuthorityAuthenticated:false,
  independentWitnessRevocationAuthenticated:false,
  independentlyPublishedHeadVerified:false,
  independentRollbackProofVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
