import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
import {sha} from '../dispatch/validation';
import {verifyDeepFrozenSnapshot,type ReleaseLine} from '../stockFoundation/validation';
export {ChainInputError,ChainConflictError,verifyDeepFrozenSnapshot};
function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainInputError('Exact journal JSON object required');
 const v=raw as Record<string,unknown>;
 if(Object.keys(v).sort().join('|')!==keys.slice().sort().join('|'))
  throw new ChainInputError('Unexpected or missing journal fields');
 return v;
}
export function validateProposal(raw:unknown){
 const v=exact(raw,['releaseIntentId']);
 if(!inventoryId(v.releaseIntentId))throw new ChainInputError('Valid HELD release intent required');
 return {releaseIntentId:v.releaseIntentId as string};
}
export function validateReview(raw:unknown){
 const v=exact(raw,['decision','reason','evidenceRef','balancingInspected']);
 if(v.decision!=='REVIEWED_HELD'&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Independent internal journal review decision required');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed journal review reason required');
 if(typeof v.balancingInspected!=='boolean'||(v.decision==='REVIEWED_HELD'&&!v.balancingInspected))
  throw new ChainInputError('Internal balance attestation required for HELD review');
 return {decision:v.decision as 'REVIEWED_HELD'|'REJECTED_INTERNAL',
  reason:v.reason.trim(),evidenceRef:chainEvidence(v.evidenceRef),
  balancingInspected:v.balancingInspected};
}
export type JournalLeg={
 productId:string;siteId:string;accountCode:'QUARANTINE_EVIDENCE'|'RELEASE_CANDIDATE_EVIDENCE';
 side:'DEBIT'|'CREDIT';quantity:number;
 trackingMode:'SERIAL'|'LOT';lotCode:string|null;serialNumbers:string[]};
export function canonicalLegs(lines:ReleaseLine[],siteId:string):JournalLeg[]{
 if(!inventoryId(siteId)||lines.length<1||lines.length>25)
  throw new ChainConflictError('Valid isolated site and SKU lines required');
 const seen=new Set<string>(),serials=new Set<string>(),result:JournalLeg[]=[];
 for(const line of [...lines].sort((a,b)=>a.productId.localeCompare(b.productId))){
  if(!inventoryId(line.productId)||seen.has(line.productId)||
   !Number.isSafeInteger(line.quantity)||line.quantity<1||line.quantity>1000)
   throw new ChainConflictError('Invalid/duplicated SKU evidence');
  seen.add(line.productId);
  if(line.trackingMode==='SERIAL'){
   if(line.lotCode!==null||line.serialNumbers.length!==line.quantity)
    throw new ChainConflictError('Serialized evidence count mismatch');
   for(const serial of line.serialNumbers){
    if(typeof serial!=='string'||!/^[A-Z0-9][A-Z0-9_-]{5,79}$/.test(serial)||
     serials.has(line.productId+':'+serial))
     throw new ChainConflictError('Duplicate/untrusted serial identity');
    serials.add(line.productId+':'+serial);
   }
  }else if(line.trackingMode==='LOT'){
   if(typeof line.lotCode!=='string'||!/^[A-Z0-9][A-Z0-9_-]{3,79}$/.test(line.lotCode)||
     line.serialNumbers.length!==0)throw new ChainConflictError('Invalid lot tracking');
  }else throw new ChainConflictError('Unsupported tracking mode');
  const base={productId:line.productId,siteId,quantity:line.quantity,
   trackingMode:line.trackingMode,lotCode:line.lotCode,serialNumbers:[...line.serialNumbers].sort()};
  result.push({...base,accountCode:'QUARANTINE_EVIDENCE',side:'CREDIT'});
  result.push({...base,accountCode:'RELEASE_CANDIDATE_EVIDENCE',side:'DEBIT'});
 }
 return result.sort((a,b)=>a.productId.localeCompare(b.productId)||
  a.accountCode.localeCompare(b.accountCode));
}
export function journalManifest(input:{
 releaseIntentId:string;releaseSha256:string;siteId:string;lines:ReleaseLine[]}){
 const legs=canonicalLegs(input.lines,input.siteId);
 return {format:'aaditech-inventory-unposted-journal-v1',
  releaseIntentId:input.releaseIntentId,releaseSha256:input.releaseSha256,siteId:input.siteId,
  legs,postingState:'DISABLED',journalPosted:false,
  supplierPoVerified:false,authenticatedAcknowledgment:false,officialGrnVerified:false,
  warehouseReleaseAuthorized:false,availableToSell:null} as const;
}
export function journalDigest(snapshot:ReturnType<typeof journalManifest>){return sha(JSON.stringify(snapshot));}
export function balanceJournal(legs:JournalLeg[]){
 if(!legs.length||legs.length%2!==0)throw new ChainConflictError('Journal legs must be paired');
 const perSku=new Map<string,{credit:number;debit:number;quarantine:number;candidate:number}>();
 for(const leg of legs){
  if(!Number.isSafeInteger(leg.quantity)||leg.quantity<=0)
   throw new ChainConflictError('Positive integer quantities required');
  const row=perSku.get(leg.productId)??{credit:0,debit:0,quarantine:0,candidate:0};
  if(leg.side==='CREDIT'&&leg.accountCode==='QUARANTINE_EVIDENCE'){
   row.credit+=leg.quantity;row.quarantine++;
  }else if(leg.side==='DEBIT'&&leg.accountCode==='RELEASE_CANDIDATE_EVIDENCE'){
   row.debit+=leg.quantity;row.candidate++;
  }else throw new ChainConflictError('Invalid journal account/side pairing');
  perSku.set(leg.productId,row);
 }
 for(const row of perSku.values())
  if(row.credit!==row.debit||row.quarantine!==1||row.candidate!==1)
   throw new ChainConflictError('Per-SKU evidence journal must have two exactly balanced legs');
 return {skuCount:perSku.size,legCount:legs.length,
  evidenceUnits:[...perSku.values()].reduce((sum,x)=>sum+x.credit,0),
  postedUnits:0,allocatedUnits:0,postingState:'DISABLED' as const};
}
export function legDigest(leg:JournalLeg){return sha(JSON.stringify(leg));}
export function journalHoldSnapshot(journalId:string,manifestSha256:string,reviewId:string){
 return {format:'aaditech-inventory-journal-review-HELD-v1',journalId,
  manifestSha256,reviewId,postingState:'DISABLED',stockPosted:false,
  availableToSell:null};
}
