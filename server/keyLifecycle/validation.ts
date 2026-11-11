import {randomBytes,verify as verifySignature,createHash} from 'node:crypto';
import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
import {strictBase64} from '../proofFoundation/validation';
export {ChainInputError,ChainConflictError};
function exact(raw:unknown,keys:string[]){
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainInputError('Exact lifecycle JSON body required');
 const v=raw as Record<string,unknown>;
 if(Object.keys(v).sort().join('|')!==keys.slice().sort().join('|'))
  throw new ChainInputError('Unexpected/missing key lifecycle fields');
 return v;
}
function validId(raw:unknown){
 if(!inventoryId(raw))throw new ChainInputError('Valid candidate/key/rotation UUID required');
 return raw as string;
}
export function reasonEvidence(raw:unknown){
 const v=exact(raw,['reason','evidenceRef']);
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Written reason between 12–1000 characters required');
 return {reason:v.reason.trim(),evidenceRef:chainEvidence(v.evidenceRef)};
}
export function keyIdBody(raw:unknown){
 const v=exact(raw,['keyId']);
 return {keyId:validId(v.keyId)};
}
export function challengeResponse(raw:unknown){
 const v=exact(raw,['challengeId','nonceB64','signatureB64']);
 return {challengeId:validId(v.challengeId),
  nonceB64:strictBase64(v.nonceB64,32).toString('base64'),
  signatureB64:strictBase64(v.signatureB64,64).toString('base64')};
}
export function reviewBody(raw:unknown){
 const v=exact(raw,['decision','reason','evidenceRef','possessionInspected']);
 const a=reasonEvidence({reason:v.reason,evidenceRef:v.evidenceRef});
 if(v.decision!=='REVIEWED_UNTRUSTED'&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('External trust decisions not supported');
 if(typeof v.possessionInspected!=='boolean'||
   (v.decision==='REVIEWED_UNTRUSTED'&&!v.possessionInspected))
  throw new ChainInputError('Positive internal review requires inspected proof');
 return {...a,decision:v.decision as 'REVIEWED_UNTRUSTED'|'REJECTED_INTERNAL',
  possessionInspected:v.possessionInspected};
}
export function rotationBody(raw:unknown){
 const v=exact(raw,['oldKeyId','newKeyId','reason','evidenceRef']);
 const a=reasonEvidence({reason:v.reason,evidenceRef:v.evidenceRef});
 const oldKeyId=validId(v.oldKeyId),newKeyId=validId(v.newKeyId);
 if(oldKeyId===newKeyId)throw new ChainInputError('Rotation requires distinct key fingerprints');
 return {...a,oldKeyId,newKeyId};
}
export function nonce(){return randomBytes(32).toString('base64');}
export function possessionMessage(input:{
 challengeId:string;keyId:string;keyFingerprint:string;
 partyKind:'SUPPLIER'|'WAREHOUSE';partyId:string;nonceB64:string}){
 strictBase64(input.nonceB64,32);
 return {format:'aaditech-offline-key-possession-v1',
  challengeId:input.challengeId,keyId:input.keyId,keyFingerprint:input.keyFingerprint,
  partyKind:input.partyKind,partyId:input.partyId,nonceB64:input.nonceB64,
  identityAuthenticated:false,officialGrnAuthenticated:false,stockPosting:'DISABLED'};
}
export function sha256(raw:string){return createHash('sha256').update(raw).digest('hex');}
export function verifyPossession(key:import('node:crypto').KeyObject,
 message:ReturnType<typeof possessionMessage>,signatureB64:string){
 const sig=strictBase64(signatureB64,64);
 return verifySignature(null,Buffer.from(JSON.stringify(message),'utf8'),key,sig);
}
export function sourceKeyStatusIsBlocked(status:string){
 return status==='REVOKED_INTERNAL'||status==='ROTATION_PENDING';
}
