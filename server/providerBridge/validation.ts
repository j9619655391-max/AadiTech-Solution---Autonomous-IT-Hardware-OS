import {verify as cryptoVerify,createHash,type KeyObject} from 'node:crypto';
import {candidatePublicKey,strictBase64} from '../proofFoundation/validation';
import {iso,fingerprint,exact,validateReview} from '../externalTrust/validation';
import {inventoryId} from '../inventory/validation';
import {chainEvidence,ChainInputError,ChainConflictError} from '../evidenceChain/validation';
export {ChainInputError,ChainConflictError,exact};
export type Purpose='SUPPLIER_ACK'|'WAREHOUSE_GRN';
export function ensureId(v:unknown){
 if(!inventoryId(v))throw new ChainInputError('Valid UUID required');
 return v as string;
}
export function pinConfig(env:NodeJS.ProcessEnv){
 const code=env.PROVIDER_CODE,origin=env.PROVIDER_HTTPS_ORIGIN,
  spki=env.PROVIDER_ROOT_SPKI_B64,rootDigest=env.PROVIDER_ROOT_SHA256,
  tlsDigest=env.PROVIDER_TLS_SPKI_SHA256;
 if(!code||!origin||!spki||!rootDigest||!tlsDigest)
  throw new ChainConflictError('External provider root and TLS pins are not independently provisioned');
 if(!/^[A-Z][A-Z0-9_-]{4,63}$/.test(code))
  throw new ChainInputError('Invalid preprovisioned provider code');
 let parsed:URL;
 try{parsed=new URL(origin);}catch{throw new ChainInputError('Valid pinned HTTPS provider origin required');}
 if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.search||
   parsed.hash||parsed.pathname!=='/'||parsed.origin!==origin||
   !/^[a-z0-9.-]+$/.test(parsed.hostname)||parsed.hostname==='localhost'||
   parsed.hostname.endsWith('.localhost')||parsed.hostname.endsWith('.local')||
   /^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname)||
   parsed.hostname.includes('..')||parsed.port)
  throw new ChainInputError('Require canonical public DNS HTTPS origin, no credentials, IP or custom port');
 const pk=candidatePublicKey(spki),tls=fingerprint(tlsDigest),root=fingerprint(rootDigest);
 if(pk.fingerprint!==root)throw new ChainConflictError('Provider root SPKI does not match separately pinned SHA-256');
 return {providerCode:code,origin,spkiB64:pk.spkiB64,rootFingerprint:root,
  tlsFingerprint:tls,publicKey:pk.publicKey};
}
export type Pin=ReturnType<typeof pinConfig>&{id:string;provisionedBy:string;status:string};
export function sha(s:string){return createHash('sha256').update(s).digest('hex');}
export function digest(v:object){return sha(JSON.stringify(v));}
export function verify(v:object,key:KeyObject,signatureB64:string){
 return cryptoVerify(null,Buffer.from(JSON.stringify(v),'utf8'),key,strictBase64(signatureB64,64));
}
function signature(v:unknown){return strictBase64(v,64).toString('base64');}
export function validateReviewHeld(v:unknown,pos:'REVIEWED_HELD'|'REVIEWED_CRYPTO_HELD'){
 return validateReview(v,pos);
}
export function validateCredential(v:unknown){
 const raw=exact(v,['pinId','issuerId','purpose','validFrom','validUntil','signatureB64']);
 if(raw.purpose!=='SUPPLIER_ACK'&&raw.purpose!=='WAREHOUSE_GRN')
  throw new ChainInputError('Unsupported credential purpose');
 const validFrom=iso(raw.validFrom),validUntil=iso(raw.validUntil);
 if(Date.parse(validUntil)<=Date.parse(validFrom)||
  Date.parse(validUntil)-Date.parse(validFrom)>30*86_400_000)
  throw new ChainInputError('Root credential lifetime must be <=30 days');
 return {pinId:ensureId(raw.pinId),issuerId:ensureId(raw.issuerId),
  purpose:raw.purpose as Purpose,validFrom,validUntil,signatureB64:signature(raw.signatureB64)};
}
export function validateCredentialTemplate(v:unknown){
 const raw=exact(v,['pinId','issuerId','purpose','validFrom','validUntil']);
 const {signatureB64,...rest}=validateCredential({...raw,signatureB64:Buffer.alloc(64).toString('base64')});
 return rest;
}
export function credentialMessage(input:{
 pinId:string;providerCode:string;providerOrigin:string;rootFingerprint:string;
 issuerId:string;issuerFingerprint:string;partyKind:'SUPPLIER'|'WAREHOUSE';
 partyId:string;organizationRegistration:string;purpose:Purpose;validFrom:string;validUntil:string}){
 return {format:'aaditech-pinned-provider-organization-credential-v1',
  pinId:input.pinId,providerCode:input.providerCode,providerOrigin:input.providerOrigin,
  rootFingerprint:input.rootFingerprint,issuerId:input.issuerId,
  issuerFingerprint:input.issuerFingerprint,partyKind:input.partyKind,
  partyId:input.partyId,organizationRegistration:input.organizationRegistration,
  purpose:input.purpose,validFrom:input.validFrom,validUntil:input.validUntil,
  independentCorporateVerification:false,externallyAuthenticatedRoot:false,
  officialGrnVerified:false,stockPosting:'DISABLED'};
}
export function validateFeed(v:unknown){
 const raw=exact(v,['pinId','sequenceNumber','publishedAt','validUntil',
  'revokedFingerprints','signatureB64']);
 if(typeof raw.sequenceNumber!=='number'||!Number.isSafeInteger(raw.sequenceNumber)||
  raw.sequenceNumber<1||raw.sequenceNumber>1_000_000_000)
  throw new ChainInputError('Strict positive integer feed sequence required');
 const publishedAt=iso(raw.publishedAt),validUntil=iso(raw.validUntil);
 if(Date.parse(validUntil)<=Date.parse(publishedAt)||
  Date.parse(validUntil)-Date.parse(publishedAt)>24*3_600_000)
  throw new ChainInputError('Revocation feed TTL exceeds 24h or is backwards');
 if(!Array.isArray(raw.revokedFingerprints)||raw.revokedFingerprints.length>128)
  throw new ChainInputError('Maximum 128 revoked fingerprints');
 const values=(raw.revokedFingerprints as unknown[]).map(fingerprint);
 if(values.join('|')!==[...new Set(values)].sort().join('|'))
  throw new ChainInputError('Revoked list must be canonical, sorted and duplicate-free');
 return {pinId:ensureId(raw.pinId),sequenceNumber:raw.sequenceNumber as number,
  publishedAt,validUntil,revokedFingerprints:values,signatureB64:signature(raw.signatureB64)};
}
export function validateFeedTemplate(v:unknown){
 const raw=exact(v,['pinId','sequenceNumber','publishedAt','validUntil','revokedFingerprints']);
 const {signatureB64,...rest}=validateFeed({...raw,signatureB64:Buffer.alloc(64).toString('base64')});
 return rest;
}
export function feedMessage(input:{
 pinId:string;providerCode:string;providerOrigin:string;rootFingerprint:string;
 sequenceNumber:number;publishedAt:string;validUntil:string;revokedFingerprints:string[]}){
 return {format:'aaditech-pinned-provider-revocations-v1',
  pinId:input.pinId,providerCode:input.providerCode,providerOrigin:input.providerOrigin,
  rootFingerprint:input.rootFingerprint,sequenceNumber:input.sequenceNumber,
  publishedAt:input.publishedAt,validUntil:input.validUntil,
  transportExternallyAuthenticated:false,externalPublisherVerified:false,
  stockPosting:'DISABLED',revokedFingerprints:input.revokedFingerprints};
}
export function validateFreeze(v:unknown){
 const x=exact(v,['reason','evidenceRef']);
 if(typeof x.reason!=='string'||x.reason.trim().length<12||x.reason.trim().length>1000)
  throw new ChainInputError('Detailed compromise incident reason required');
 return {reason:x.reason.trim(),evidenceRef:chainEvidence(x.evidenceRef)};
}
