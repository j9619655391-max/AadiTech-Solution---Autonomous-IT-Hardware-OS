import {verify as cryptoVerify,type KeyObject} from 'node:crypto';
import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
import {candidatePublicKey,strictBase64} from '../proofFoundation/validation';
import {sha} from '../dispatch/validation';
export {ChainInputError,ChainConflictError};
export type Party='SUPPLIER'|'WAREHOUSE';
export type Purpose='SUPPLIER_ACK'|'WAREHOUSE_GRN';
export type Decision='REVIEWED_HELD'|'REVIEWED_CRYPTO_HELD'|'REJECTED_INTERNAL';
export function exact(raw:unknown,keys:string[]):Record<string,unknown>{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))
  throw new ChainInputError('Exact external proof object required');
 const v=raw as Record<string,unknown>;
 if(Object.keys(v).sort().join('|')!==[...keys].sort().join('|'))
  throw new ChainInputError('Missing or unsupported external-proof fields');
 return v;
}
function id(v:unknown):string{
 if(!inventoryId(v))throw new ChainInputError('Valid UUID required');
 return v as string;
}
export function organizationReference(v:unknown):string{
 if(typeof v!=='string'||!/^[A-Z0-9][A-Z0-9/-]{5,95}$/.test(v))
  throw new ChainInputError('Canonical uppercase organizational registration required');
 return v;
}
export function iso(v:unknown):string{
 if(typeof v!=='string'||!/^20\d{2}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/.test(v)||
  !Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)
  throw new ChainInputError('Canonical UTC ISO .000Z timestamp required');
 return v;
}
export function fingerprint(v:unknown):string{
 if(typeof v!=='string'||!/^[a-f0-9]{64}$/.test(v))
  throw new ChainInputError('Lowercase 64-digit key fingerprint required');
 return v;
}
export function validateIssuer(raw:unknown){
 const v=exact(raw,['partyKind','partyId','issuerSpkiB64','organizationRegistration','evidenceRef']);
 if(v.partyKind!=='SUPPLIER'&&v.partyKind!=='WAREHOUSE')
  throw new ChainInputError('Supplier or warehouse scope only');
 const parsed=candidatePublicKey(v.issuerSpkiB64);
 return {partyKind:v.partyKind as Party,partyId:id(v.partyId),
  organizationRegistration:organizationReference(v.organizationRegistration),
  evidenceRef:chainEvidence(v.evidenceRef),issuerSpkiB64:parsed.spkiB64,
  issuerFingerprint:parsed.fingerprint,publicKey:parsed.publicKey};
}
export function validateReview(raw:unknown,positive:'REVIEWED_HELD'|'REVIEWED_CRYPTO_HELD'){
 const v=exact(raw,['decision','reason','evidenceRef','evidenceInspected']);
 if(v.decision!==positive&&v.decision!=='REJECTED_INTERNAL')
  throw new ChainInputError('Only internal HELD or rejection permitted');
 if(typeof v.reason!=='string'||v.reason.trim().length<12||v.reason.trim().length>1000)
  throw new ChainInputError('Independent written review reason required');
 if(typeof v.evidenceInspected!=='boolean'||(v.decision===positive&&!v.evidenceInspected))
  throw new ChainInputError('Explicit evidence inspection mandatory');
 return {decision:v.decision as Decision,reason:v.reason.trim(),
  evidenceRef:chainEvidence(v.evidenceRef),evidenceInspected:v.evidenceInspected};
}
export function validateAuthority(raw:unknown){
 const v=exact(raw,['issuerId','keyId','purpose','validFrom','validUntil','signatureB64']);
 const purpose=v.purpose;
 if(purpose!=='SUPPLIER_ACK'&&purpose!=='WAREHOUSE_GRN')
  throw new ChainInputError('Unsupported authority purpose');
 const validFrom=iso(v.validFrom),validUntil=iso(v.validUntil);
 if(Date.parse(validUntil)<=Date.parse(validFrom)||
  Date.parse(validUntil)-Date.parse(validFrom)>90*86_400_000)
  throw new ChainInputError('Authority valid-until must be within 90 days');
 strictBase64(v.signatureB64,64);
 return {issuerId:id(v.issuerId),keyId:id(v.keyId),purpose:purpose as Purpose,
  validFrom,validUntil,signatureB64:v.signatureB64 as string};
}
export function validateAuthorityTemplate(raw:unknown){
 const v=exact(raw,['issuerId','keyId','purpose','validFrom','validUntil']);
 const sig=Buffer.alloc(64).toString('base64');
 const {signatureB64,...out}=validateAuthority({...v,signatureB64:sig});
 return out;
}
export function authorityMessage(input:{
 issuerId:string;issuerFingerprint:string;keyId:string;keyFingerprint:string;
 partyKind:Party;partyId:string;organizationRegistration:string;purpose:Purpose;
 validFrom:string;validUntil:string}){
 return {format:'aaditech-external-organization-candidate-v1',
  issuerId:input.issuerId,issuerFingerprint:input.issuerFingerprint,
  keyId:input.keyId,keyFingerprint:input.keyFingerprint,
  partyKind:input.partyKind,partyId:input.partyId,
  organizationRegistration:input.organizationRegistration,
  purpose:input.purpose,validFrom:input.validFrom,validUntil:input.validUntil,
  issuerExternallyAuthenticated:false,organizationAuthorityVerified:false,
  officialGrnVerified:false,stockPostingState:'DISABLED'};
}
export function validateRevocation(raw:unknown){
 const v=exact(raw,['issuerId','sequenceNumber','issuedAt','expiresAt',
  'revokedFingerprints','signatureB64']);
 const issuerId=id(v.issuerId);
 if(typeof v.sequenceNumber!=='number'||!Number.isSafeInteger(v.sequenceNumber)||
  v.sequenceNumber<1||v.sequenceNumber>1_000_000_000)
  throw new ChainInputError('Positive integer revocation sequence required');
 const issuedAt=iso(v.issuedAt),expiresAt=iso(v.expiresAt);
 if(Date.parse(expiresAt)<=Date.parse(issuedAt)||
  Date.parse(expiresAt)-Date.parse(issuedAt)>24*60*60_000)
  throw new ChainInputError('Revocation bundle validity must be within 24h');
 if(!Array.isArray(v.revokedFingerprints)||v.revokedFingerprints.length>128)
  throw new ChainInputError('Maximum 128 revoked fingerprints per bundle');
 const fp=(v.revokedFingerprints as unknown[]).map(fingerprint);
 if(fp.join('|')!==[...new Set(fp)].sort().join('|'))
  throw new ChainInputError('Revoked fingerprints must be unique and sorted');
 strictBase64(v.signatureB64,64);
 return {issuerId,sequenceNumber:v.sequenceNumber as number,issuedAt,expiresAt,
  revokedFingerprints:fp,signatureB64:v.signatureB64 as string};
}
export function revocationTemplate(raw:unknown){
 const v=exact(raw,['issuerId','sequenceNumber','issuedAt','expiresAt','revokedFingerprints']);
 const {signatureB64,...out}=validateRevocation({...v,signatureB64:Buffer.alloc(64).toString('base64')});
 return out;
}
export function revocationMessage(input:{
 issuerId:string;issuerFingerprint:string;partyKind:Party;partyId:string;
 sequenceNumber:number;issuedAt:string;expiresAt:string;revokedFingerprints:string[]}){
 return {format:'aaditech-candidate-signed-revocation-v1',
  issuerId:input.issuerId,issuerFingerprint:input.issuerFingerprint,
  partyKind:input.partyKind,partyId:input.partyId,
  sequenceNumber:input.sequenceNumber,issuedAt:input.issuedAt,
  expiresAt:input.expiresAt,revokedFingerprints:input.revokedFingerprints,
  publisherExternallyAuthenticated:false,
  externalTrustEstablished:false,stockPostingState:'DISABLED'};
}
export function digest(message:object){return sha(JSON.stringify(message));}
export function verifySigned(message:object,key:KeyObject,signature:string):boolean{
 return cryptoVerify(null,Buffer.from(JSON.stringify(message),'utf8'),key,strictBase64(signature,64));
}
