import {createHash,createPublicKey,verify as verifySignature,type KeyObject} from 'node:crypto';
import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
import {verifyDeepFrozenSnapshot} from '../stockFoundation/validation';
import {sha} from '../dispatch/validation';
export {ChainInputError,ChainConflictError,verifyDeepFrozenSnapshot};
export type ProofKind='PO_ISSUANCE_ASSERTION'|'SUPPLIER_ACK_ASSERTION'|'WAREHOUSE_GRN_ASSERTION';
export type PartyKind='SUPPLIER'|'WAREHOUSE';
function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))throw new ChainInputError('Exact JSON object required');
 const v=raw as Record<string,unknown>;
 if(Object.keys(v).sort().join('|')!==keys.slice().sort().join('|'))
  throw new ChainInputError('Unsupported or missing signed proof fields');
 return v;
}
export function strictBase64(raw:unknown,length:number):Buffer{
 if(typeof raw!=='string'||raw.length>512||!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))
  throw new ChainInputError('Canonical base64 evidence required');
 const bytes=Buffer.from(raw,'base64');
 if(bytes.length!==length||bytes.toString('base64')!==raw)
  throw new ChainInputError('Invalid canonical base64 length or padding');
 return bytes;
}
const ed25519SpkiHeader='302a300506032b6570032100';
export function candidatePublicKey(raw:unknown):{publicKey:KeyObject;fingerprint:string;spkiB64:string}{
 const bytes=strictBase64(raw,44);
 if(bytes.subarray(0,12).toString('hex')!==ed25519SpkiHeader)
  throw new ChainInputError('Only Ed25519 X.509 SPKI DER accepted');
 let publicKey:KeyObject;
 try{publicKey=createPublicKey({key:bytes,format:'der',type:'spki'});}
 catch{throw new ChainInputError('Invalid Ed25519 public key');}
 if(publicKey.asymmetricKeyType!=='ed25519')throw new ChainInputError('Only Ed25519 accepted');
 return {publicKey,fingerprint:createHash('sha256').update(bytes).digest('hex'),
  spkiB64:bytes.toString('base64')};
}
export function validateKey(raw:unknown){
 const v=exact(raw,['partyKind','partyId','publicKeySpkiB64','evidenceRef']);
 if((v.partyKind!=='SUPPLIER'&&v.partyKind!=='WAREHOUSE')||!inventoryId(v.partyId))
  throw new ChainInputError('Valid supplier or warehouse candidate required');
 return {partyKind:v.partyKind as PartyKind,partyId:v.partyId as string,
  evidenceRef:chainEvidence(v.evidenceRef),...candidatePublicKey(v.publicKeySpkiB64)};
}
function review(raw:unknown,allowed:readonly string[],positive:string){
 const v=exact(raw,['decision','reason','evidenceRef','documentInspected']);
 if(typeof v.decision!=='string'||!allowed.includes(v.decision))
  throw new ChainInputError('Only internal review decisions permitted');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Detailed review reason required');
 if(typeof v.documentInspected!=='boolean'||(v.decision===positive&&!v.documentInspected))
  throw new ChainInputError('Internal review requires explicit document inspection');
 return {decision:v.decision,reason:v.reason.trim(),
  evidenceRef:chainEvidence(v.evidenceRef),documentInspected:v.documentInspected};
}
export function validateKeyReview(raw:unknown){
 return review(raw,['REVIEWED_UNTRUSTED','REJECTED_INTERNAL'],'REVIEWED_UNTRUSTED');
}
export function validateClaimReview(raw:unknown){
 return review(raw,['REVIEWED_CRYPTO_ONLY','REJECTED_INTERNAL'],'REVIEWED_CRYPTO_ONLY');
}
export function validateClaim(raw:unknown){
 const v=exact(raw,['keyId','kind','sourceId','reference','documentSha256',
  'issuedAt','signatureB64']);
 if(!inventoryId(v.keyId)||!inventoryId(v.sourceId)||
  !['PO_ISSUANCE_ASSERTION','SUPPLIER_ACK_ASSERTION','WAREHOUSE_GRN_ASSERTION'].includes(String(v.kind)))
  throw new ChainInputError('Valid key and source identifiers required');
 if(typeof v.reference!=='string'||!/^[A-Z0-9][A-Z0-9_-]{7,79}$/.test(v.reference))
  throw new ChainInputError('Offline assertion reference 8–80 uppercase characters required');
 if(typeof v.documentSha256!=='string'||!/^[0-9a-f]{64}$/.test(v.documentSha256))
  throw new ChainInputError('Lowercase offline document SHA-256 required');
 if(typeof v.issuedAt!=='string'||!/^20\d\d-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.000Z$/.test(v.issuedAt)||
  !Number.isFinite(Date.parse(v.issuedAt))||
  new Date(v.issuedAt).toISOString()!==v.issuedAt)
  throw new ChainInputError('Canonical UTC timestamp with .000Z required');
 strictBase64(v.signatureB64,64);
 return {keyId:v.keyId as string,kind:v.kind as ProofKind,sourceId:v.sourceId as string,
  reference:v.reference as string,documentSha256:v.documentSha256 as string,
  issuedAt:v.issuedAt as string,signatureB64:v.signatureB64 as string};
}
export function validateTemplate(raw:unknown){
 const v=exact(raw,['keyId','kind','sourceId','reference','documentSha256','issuedAt']);
 const placeholder=Buffer.alloc(64).toString('base64');
 const {signatureB64,...input}=validateClaim({...v,signatureB64:placeholder});
 return input;
}
export function signedMessage(input:{
 kind:ProofKind;sourceId:string;sourceSha256:string;partyId:string;
 reference:string;documentSha256:string;issuedAt:string}){
 return {format:'aaditech-self-registered-offline-proof-v1',
  kind:input.kind,sourceId:input.sourceId,sourceSha256:input.sourceSha256,
  partyId:input.partyId,reference:input.reference,
  documentSha256:input.documentSha256,issuedAt:input.issuedAt,
  externalIdentityVerified:false,officialGrnAuthorized:false,stockPostingState:'DISABLED'};
}
export function verifyDetachedSignature(key:KeyObject,message:ReturnType<typeof signedMessage>,
 signatureB64:string){
 const sig=strictBase64(signatureB64,64);
 return verifySignature(null,Buffer.from(JSON.stringify(message),'utf8'),key,sig);
}
export function proofHoldSnapshot(claimId:string,messageSha256:string,reviewId:string){
 return {format:'aaditech-offline-signature-internal-HELD-v1',claimId,messageSha256,
  reviewId,partyIdentity:'UNVERIFIED',externalPoIssued:false,
  supplierAcknowledgmentAuthenticated:false,officialGrnVerified:false,
  stockPostingState:'DISABLED',availableToSell:null};
}
export function messageDigest(message:ReturnType<typeof signedMessage>){return sha(JSON.stringify(message));}
