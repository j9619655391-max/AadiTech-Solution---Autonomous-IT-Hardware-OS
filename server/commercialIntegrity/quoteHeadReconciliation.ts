import {createHash,createPublicKey,verify} from 'node:crypto';
import type {CandidatePinnedKey} from './quoteAnchors';

// Phase 1BN candidate-only evidence reconciliation. An applicant-supplied
// Ed25519 signature and public key never establish external witness authority.
// All outcomes HOLD; no network, signing key, provider secret or real DR.
const SHA=/^[0-9a-f]{64}$/;
const ID=/^[a-zA-Z0-9._:-]{1,96}$/;
const RFC3339=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SOURCE_KEYS=['format','quoteId','sourceId','keyId','sequence',
 'receiptSha256','sourceSha256','publishedAt','observedAt',
 'revocationEpoch','revokedKeyIds','revocationThisUpdate','revocationNextUpdate'];
const ROLLOVER_KEYS=['format','quoteId','oldKeyId','newKeyId',
 'receiptSha256','effectiveAt','reason'];
const exact=(x:unknown,keys:string[]):x is Record<string,any>=>!!x&&
 typeof x==='object'&&!Array.isArray(x)&&
 Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const timestamp=(v:unknown):number|null=>{
 if(typeof v!=='string'||!RFC3339.test(v))return null;
 const n=Date.parse(v);return Number.isFinite(n)&&new Date(n).toISOString()===v?n:null;
};
function canonical(x:unknown):unknown{
 if(x===null||typeof x==='string'||typeof x==='boolean')return x;
 if(typeof x==='number'&&Number.isFinite(x))return x;
 if(Array.isArray(x)){if(x.length>32)throw Error('BN excessive candidate evidence');return x.map(canonical);}
 if(x&&typeof x==='object'){
  const r=x as Record<string,unknown>,keys=Object.keys(r).sort();
  if(keys.length>20||keys.some(k=>['__proto__','constructor','prototype'].includes(k)))
   throw Error('BN invalid candidate evidence object');
  const output:Record<string,unknown>={};
  for(const k of keys)output[k]=canonical(r[k]);
  return output;
 }
 throw Error('BN invalid candidate evidence scalar');
}
const encoded=(x:unknown)=>JSON.stringify(canonical(x));
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
function verifyDetached(body:unknown,signature:unknown,pin:CandidatePinnedKey){
 try{
  if(typeof signature!=='string'||!/^[A-Za-z0-9+/]+={0,2}$/.test(signature)||
     signature.length!==88)return false;
  const sig=Buffer.from(signature,'base64');
  if(sig.length!==64||sig.toString('base64')!==signature)return false;
  const pub=createPublicKey(pin.publicKeySpkiPem);
  if(pub.asymmetricKeyType!=='ed25519')return false;
  return verify(null,Buffer.from(encoded(body)),pub,sig);
 }catch{return false;}
}
function activePin(p:CandidatePinnedKey|undefined,at:number|null){
 if(!p||p.status!=='ACTIVE'||at===null)return false;
 const from=timestamp(p.validFrom),until=timestamp(p.validUntil);
 return from!==null&&until!==null&&from<=at&&at<until;
}
export type CandidateHeadObservationBody={
 format:'aaditech-quote-head-observation-v1';quoteId:string;sourceId:string;
 keyId:string;sequence:number;receiptSha256:string;sourceSha256:string;
 publishedAt:string;observedAt:string;revocationEpoch:number;
 revokedKeyIds:string[];revocationThisUpdate:string;revocationNextUpdate:string
};
export type CandidateHeadObservation={
 body:CandidateHeadObservationBody;signatureBase64:string
};
export type CandidateKeyRolloverBody={
 format:'aaditech-quote-key-rollover-v1';quoteId:string;
 oldKeyId:string;newKeyId:string;receiptSha256:string;
 effectiveAt:string;reason:string
};
export type CandidateKeyRollover={body:CandidateKeyRolloverBody;
 oldSignatureBase64:string;newSignatureBase64:string};
export function canonicalCandidateQuoteObservation(body:CandidateHeadObservationBody){
 return encoded(body);
}
export function canonicalCandidateQuoteRollover(body:CandidateKeyRolloverBody){
 return encoded(body);
}
export function candidateQuoteReconciliationDigest(args:{
 observations:CandidateHeadObservation[],rollover?:CandidateKeyRollover|null,
 recoverySnapshot?:{sequence:number,receiptSha256:string,sourceSha256:string}|null
}){
 return hash('aaditech/quote/head-reconciliation/v1\n'+encoded({
  observations:args.observations,rollover:args.rollover??null,
  recoverySnapshot:args.recoverySnapshot??null
 }));
}
export function candidateQuotePinsetDigest(keys:CandidatePinnedKey[]){
 if(!Array.isArray(keys)||keys.length<2||keys.length>8)
  throw Error('BN candidate witness pinset size invalid');
 const records=keys.map(k=>{
  if(!k||!ID.test(String(k.keyId))||
     !['ACTIVE','REVOKED','UNKNOWN'].includes(k.status)||
     timestamp(k.validFrom)===null||timestamp(k.validUntil)===null)
   throw Error('BN malformed candidate witness pin');
  const pub=createPublicKey(k.publicKeySpkiPem);
  if(pub.asymmetricKeyType!=='ed25519')throw Error('BN non Ed25519 candidate pin');
  return {keyId:k.keyId,spkiSha256:createHash('sha256')
   .update(pub.export({type:'spki',format:'der'})).digest('hex'),
   validFrom:k.validFrom,validUntil:k.validUntil,status:k.status};
 }).sort((a,b)=>a.keyId.localeCompare(b.keyId));
 if(new Set(records.map(k=>k.keyId)).size!==records.length)
  throw Error('BN duplicate candidate pin identities');
 return hash('aaditech/quote/reconciliation-pinset/v1\n'+encoded(records));
}
export function assessCandidateQuoteHeadReconciliation(args:{
 quoteId:string,checkpointSequence:number,checkpointReceiptSha256:string,
 checkpointSourceSha256:string,observations:CandidateHeadObservation[],
 pinnedKeys:CandidatePinnedKey[],now:Date,
 rollover?:CandidateKeyRollover|null,
 recoverySnapshot?:{sequence:number,receiptSha256:string,sourceSha256:string}|null
}){
 const errors=new Set<string>();
 const {quoteId,checkpointSequence,checkpointReceiptSha256,
  checkpointSourceSha256,observations,pinnedKeys,now,rollover=null,
  recoverySnapshot=null}=args;
 const nowMs=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(nowMs))errors.add('BN_CLOCK_INVALID');
 if(!Number.isSafeInteger(checkpointSequence)||checkpointSequence<1||
    !SHA.test(String(checkpointReceiptSha256))||
    !SHA.test(String(checkpointSourceSha256)))
  errors.add('BN_LOCAL_HEAD_INVALID');
 const pins=new Map<string,CandidatePinnedKey>();
 try{candidateQuotePinsetDigest(pinnedKeys);}catch{errors.add('BN_PINSET_INVALID');}
 if(Array.isArray(pinnedKeys))for(const pin of pinnedKeys)
  if(pin&&typeof pin.keyId==='string'&&!pins.has(pin.keyId))
   pins.set(pin.keyId,pin);
 if(!Array.isArray(observations)||observations.length!==2)
  errors.add('BN_TWO_INDEPENDENT_CANDIDATE_SOURCES_REQUIRED');
 const obs=Array.isArray(observations)?observations.slice(0,2):[];
 const sourceIds=new Set<string>(),signerIds=new Set<string>();
 let first:CandidateHeadObservationBody|null=null;
 for(const item of obs){
  const body=item?.body;
  if(!exact(item,['body','signatureBase64'])||!exact(body,SOURCE_KEYS)||
     body.format!=='aaditech-quote-head-observation-v1'||body.quoteId!==quoteId||
     !ID.test(String(body.sourceId))||!ID.test(String(body.keyId))||
     !Number.isSafeInteger(body.sequence)||body.sequence<1||
     !SHA.test(String(body.receiptSha256))||!SHA.test(String(body.sourceSha256))||
     !Number.isSafeInteger(body.revocationEpoch)||body.revocationEpoch<1||
     !Array.isArray(body.revokedKeyIds)||body.revokedKeyIds.length>8||
     body.revokedKeyIds.some(k=>typeof k!=='string'||!ID.test(k))||
     new Set(body.revokedKeyIds).size!==body.revokedKeyIds.length||
     [...body.revokedKeyIds].sort().join('|')!==body.revokedKeyIds.join('|')){
   errors.add('BN_OBSERVATION_SHAPE_INVALID');continue;
  }
  if(sourceIds.has(body.sourceId)||signerIds.has(body.keyId))
   errors.add('BN_WITNESS_SOURCE_OR_SIGNER_NOT_SEPARATE');
  sourceIds.add(body.sourceId);signerIds.add(body.keyId);
  const published=timestamp(body.publishedAt),observed=timestamp(body.observedAt);
  const revFrom=timestamp(body.revocationThisUpdate);
  const revUntil=timestamp(body.revocationNextUpdate);
  if(published===null||observed===null||!Number.isFinite(nowMs)||
     published>observed||observed>nowMs+60000||
     nowMs-observed>15*60000||nowMs-published>30*60000)
   errors.add('BN_PUBLISHED_HEAD_STALE_OR_FUTURE');
  if(revFrom===null||revUntil===null||!Number.isFinite(nowMs)||
     revFrom>nowMs+60000||revUntil<=nowMs||
     revUntil<=revFrom||nowMs-revFrom>60*60000)
   errors.add('BN_REVOCATION_PROOF_STALE_OR_UNDATED');
  const signer=pins.get(body.keyId);
  if(!activePin(signer,observed)||!signer||
     body.revokedKeyIds.includes(body.keyId))
   errors.add('BN_WITNESS_KEY_REVOKED_OR_UNPINNED');
  if(!signer||!verifyDetached(body,item.signatureBase64,signer))
   errors.add('BN_OBSERVATION_SIGNATURE_INVALID');
  if(body.sequence!==checkpointSequence||
     body.receiptSha256!==checkpointReceiptSha256||
     body.sourceSha256!==checkpointSourceSha256)
   errors.add(body.sequence<checkpointSequence?
    'BN_HEAD_ROLLBACK':body.sequence>checkpointSequence?
    'BN_LOCAL_HEAD_BEHIND':'BN_HEAD_FORK_OR_SOURCE_MISMATCH');
  if(first&&(body.sequence!==first.sequence||
     body.receiptSha256!==first.receiptSha256||
     body.sourceSha256!==first.sourceSha256||
     body.revocationEpoch!==first.revocationEpoch||
     body.revocationThisUpdate!==first.revocationThisUpdate||
     body.revocationNextUpdate!==first.revocationNextUpdate||
     body.revokedKeyIds.join('|')!==first.revokedKeyIds.join('|')))
   errors.add('BN_CROSS_SOURCE_HEAD_OR_REVOCATION_CONFLICT');
  if(!first)first=body;
 }
 if(rollover!==null){
  const b=rollover.body;
  if(!exact(rollover,['body','oldSignatureBase64','newSignatureBase64'])||
     !exact(b,ROLLOVER_KEYS)||b.format!=='aaditech-quote-key-rollover-v1'||
     b.quoteId!==quoteId||!ID.test(String(b.oldKeyId))||
     !ID.test(String(b.newKeyId))||b.oldKeyId===b.newKeyId||
     b.receiptSha256!==checkpointReceiptSha256||
     typeof b.reason!=='string'||b.reason.trim().length<16||b.reason.length>400)
   errors.add('BN_ROLLOVER_PAYLOAD_INVALID');
  else{
   const when=timestamp(b.effectiveAt);
   if(when===null||!Number.isFinite(nowMs)||when>nowMs+60000||
      nowMs-when>24*60*60000)
    errors.add('BN_ROLLOVER_TIME_INVALID');
   const old=pins.get(b.oldKeyId),next=pins.get(b.newKeyId);
   if(!activePin(old,when)||!activePin(next,when)||
      obs.some(o=>o?.body?.revokedKeyIds?.includes(b.oldKeyId)||
       o?.body?.revokedKeyIds?.includes(b.newKeyId)))
    errors.add('BN_ROLLOVER_KEY_INACTIVE_OR_REVOKED');
   if(!old||!next||
      !verifyDetached(b,rollover.oldSignatureBase64,old)||
      !verifyDetached(b,rollover.newSignatureBase64,next))
    errors.add('BN_ROLLOVER_DUAL_SIGNATURE_INVALID');
  }
 }
 if(recoverySnapshot!==null){
  const r=recoverySnapshot;
  if(!exact(r,['sequence','receiptSha256','sourceSha256'])||
     !Number.isSafeInteger(r.sequence)||r.sequence<0||
     !SHA.test(String(r.receiptSha256))||!SHA.test(String(r.sourceSha256)))
   errors.add('BN_DR_REHEARSAL_SNAPSHOT_INVALID');
  else if(r.sequence<checkpointSequence)
   errors.add('BN_DR_REHEARSAL_ROLLBACK_DETECTED');
  else if(r.sequence>checkpointSequence||r.receiptSha256!==checkpointReceiptSha256||
          r.sourceSha256!==checkpointSourceSha256)
   errors.add('BN_DR_REHEARSAL_HEAD_MISMATCH');
 }
 const codes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateReconciliationConsistent:codes.length===0,
  candidateReconciliationAnomalyCodes:codes,
  candidateObservationCount:obs.length,
  candidateRevocationEpoch:first?.revocationEpoch??null,
  candidateRolloverSignaturesConsistent:rollover!==null&&
   !codes.some(x=>x.startsWith('BN_ROLLOVER_')),
  candidateDrRehearsalInspected:recoverySnapshot!==null,
  candidateEvidenceOnly:true,
  independentlyPublishedHeadVerified:false,
  authenticatedWitnessAuthorityVerified:false,
  authenticatedRevocationAuthorityVerified:false,
  realEncryptedDrRecoveryWitnessed:false,
  independentRollbackProofVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD' as const
 });
}
