import {createHash,createPublicKey,verify} from 'node:crypto';

// BP: detached, caller-configured candidate signer pins only. Pins MUST come
// from an independently administered, approved enrollment source to become
// authoritative; this module cannot establish that fact or release a quote.
const SHA=/^[0-9a-f]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const ID=/^[a-zA-Z0-9._:-]{3,96}$/;
const UTC=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ROLES=['PUBLISHER','ISSUER','WORM','RECOVERY'] as const;
type Role=typeof ROLES[number];
type Row=Record<string,any>;
const exact=(x:unknown,keys:string[]):x is Row=>!!x&&typeof x==='object'&&
 !Array.isArray(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const date=(x:unknown):number|null=>{
 if(typeof x!=='string'||!UTC.test(x))return null;
 const ms=Date.parse(x);return Number.isFinite(ms)&&new Date(ms).toISOString()===x?ms:null;
};
function canonical(value:unknown,depth=0):unknown{
 if(depth>8)throw Error('BP evidence depth exceeded');
 if(value===null||typeof value==='string'||typeof value==='boolean')return value;
 if(typeof value==='number'&&Number.isFinite(value))return value;
 if(Array.isArray(value)){
  if(value.length>8)throw Error('BP evidence count exceeded');
  return value.map(x=>canonical(x,depth+1));
 }
 if(value&&typeof value==='object'){
  const o=value as Row,keys=Object.keys(o).sort();
  if(keys.length>25||keys.some(k=>['__proto__','constructor','prototype'].includes(k)))
   throw Error('BP evidence shape rejected');
  const r:Row={};
  for(const k of keys)r[k]=canonical(o[k],depth+1);
  return r;
 }
 throw Error('BP unsupported evidence scalar');
}
const encode=(value:unknown)=>JSON.stringify(canonical(value));
const sha=(domain:string,body:string)=>createHash('sha256')
 .update(domain+'\n'+body).digest('hex');
export type IntakeRole=Role;
export type IntakePinnedCandidateKey={
 role:Role,keyId:string,publicKeySpkiPem:string,
 validFrom:string,validUntil:string,status:'ACTIVE'|'REVOKED'|'UNKNOWN'
};
export type IntakeClaimBody={
 format:'aaditech-quote-evidence-intake-claim-v1';
 quoteId:string;challengeSha256:string;boDossierSha256:string;
 bmReceiptSha256:string;bnPacketSha256:string;
 signerRole:Role;signerKeyId:string;
 claimedSourceId:string;observedAt:string;
 publicationHeadSha256:string;
 revocationEpoch:number;revocationThisUpdate:string;revocationNextUpdate:string;
 crlSha256:string;ocspSha256:string;issuerChainSha256:string;
 retentionUntil:string;overwriteDenied:boolean;deleteDenied:boolean;
 restoredSequence:number;restoredReceiptSha256:string;
 restoredSourceSha256:string;drTranscriptSha256:string;
 rtoSeconds:number;rpoSeconds:number;
 evidenceState:'CANDIDATE_UNVERIFIED'
};
export type IntakeSignedClaim={body:IntakeClaimBody,signatureBase64:string};
export type IntakeCandidatePacket={
 format:'aaditech-quote-evidence-intake-v1';
 quoteId:string;challengeSha256:string;boDossierSha256:string;
 claims:IntakeSignedClaim[]
};
export type IntakeExpected={
 quoteId:string;boDossierSha256:string;bmReceiptSha256:string;
 bnPacketSha256:string;sourceSha256:string;bmSequence:number;
 minimumRevocationEpoch:number;
 boExists:boolean;boLocallyConsistent:boolean;
 boGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT'
};
const CLAIM_KEYS=['format','quoteId','challengeSha256','boDossierSha256',
 'bmReceiptSha256','bnPacketSha256','signerRole','signerKeyId',
 'claimedSourceId','observedAt','publicationHeadSha256','revocationEpoch',
 'revocationThisUpdate','revocationNextUpdate','crlSha256','ocspSha256',
 'issuerChainSha256','retentionUntil','overwriteDenied','deleteDenied',
 'restoredSequence','restoredReceiptSha256','restoredSourceSha256',
 'drTranscriptSha256','rtoSeconds','rpoSeconds','evidenceState'];
export function canonicalCandidateIntakeClaim(body:IntakeClaimBody){
 return encode(body);
}
export function candidateIntakePacketDigest(packet:IntakeCandidatePacket){
 return sha('aaditech/quote/evidence-intake/v1',encode(packet));
}
export function candidateIntakePinsetDigest(pins:IntakePinnedCandidateKey[]){
 if(!Array.isArray(pins)||pins.length!==4)throw Error('BP exactly four distinct candidate role pins required');
 const rows=pins.map(k=>{
  if(!k||!ROLES.includes(k.role)||!ID.test(String(k.keyId))||
   !['ACTIVE','REVOKED','UNKNOWN'].includes(k.status)||
   date(k.validFrom)===null||date(k.validUntil)===null||
   date(k.validFrom)!>=date(k.validUntil)!)
   throw Error('BP malformed candidate signing pin');
  const p=createPublicKey(k.publicKeySpkiPem);
  if(p.asymmetricKeyType!=='ed25519')throw Error('BP requires Ed25519 test/key pin');
  return {role:k.role,keyId:k.keyId,status:k.status,validFrom:k.validFrom,
   validUntil:k.validUntil,publicSpkiSha256:createHash('sha256')
    .update(p.export({format:'der',type:'spki'})).digest('hex')};
 }).sort((a,b)=>a.role.localeCompare(b.role));
 if(new Set(rows.map(x=>x.role)).size!==4||
    new Set(rows.map(x=>x.keyId)).size!==4||
    new Set(rows.map(x=>x.publicSpkiSha256)).size!==4)
  throw Error('BP repeated candidate signer role/key/material');
 return sha('aaditech/quote/evidence-intake/pins/v1',encode(rows));
}
function validateSignature(body:IntakeClaimBody,signature:unknown,pin:IntakePinnedCandidateKey){
 try{
  if(typeof signature!=='string'||signature.length!==88||
     !/^[A-Za-z0-9+/]+={0,2}$/.test(signature))return false;
  const bytes=Buffer.from(signature,'base64');
  if(bytes.length!==64||bytes.toString('base64')!==signature)return false;
  const key=createPublicKey(pin.publicKeySpkiPem);
  return key.asymmetricKeyType==='ed25519'&&verify(null,
   Buffer.from('aaditech/quote/evidence-intake/claim/v1\n'+encode(body)),
   key,bytes);
 }catch{return false;}
}
export function assessCandidateExternalIntake(args:{
 packet:IntakeCandidatePacket,expected:IntakeExpected,
 pinnedKeys:IntakePinnedCandidateKey[],
 expectedPinsetSha256:string,now:Date
}){
 const errors=new Set<string>(),{packet,expected,pinnedKeys,expectedPinsetSha256,now}=args;
 const at=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(at))errors.add('BP_CLOCK_INVALID');
 let pinsetSha256:string|null=null;
 try{pinsetSha256=candidateIntakePinsetDigest(pinnedKeys);}
 catch{errors.add('BP_PINSET_INVALID');}
 if(!SHA.test(String(expectedPinsetSha256))||pinsetSha256!==expectedPinsetSha256)
  errors.add('BP_CONFIGURED_PINSET_MISMATCH');
 if(!expected||!UUID.test(String(expected.quoteId))||
    ![expected.boDossierSha256,expected.bmReceiptSha256,
      expected.bnPacketSha256,expected.sourceSha256].every(x=>SHA.test(String(x)))||
    !Number.isSafeInteger(expected.bmSequence)||expected.bmSequence<1||
    !Number.isSafeInteger(expected.minimumRevocationEpoch)||
    expected.minimumRevocationEpoch<1||expected.boExists!==true||
    expected.boLocallyConsistent!==true||
    expected.boGovernanceState!=='HELD_UNVERIFIED')
  errors.add('BP_UPSTREAM_BO_NOT_READY');
 if(!exact(packet,['format','quoteId','challengeSha256','boDossierSha256','claims'])||
    packet.format!=='aaditech-quote-evidence-intake-v1'||
    !UUID.test(String(packet.quoteId))||
    !SHA.test(String(packet.challengeSha256))||
    !SHA.test(String(packet.boDossierSha256))||
    !Array.isArray(packet.claims)||packet.claims.length!==4)
  errors.add('BP_PACKET_SHAPE_INVALID');
 if(packet.quoteId!==expected?.quoteId||
    packet.boDossierSha256!==expected?.boDossierSha256)
  errors.add('BP_UPSTREAM_DOSSIER_CONFLICT');
 const byRole=new Map<Role,IntakeClaimBody>();
 const sources=new Set<string>(),keys=new Set<string>();
 const config=new Map<Role,IntakePinnedCandidateKey>();
 if(Array.isArray(pinnedKeys))for(const k of pinnedKeys)
  if(k&&!config.has(k.role))config.set(k.role,k);
 for(const item of Array.isArray(packet.claims)?packet.claims.slice(0,4):[]){
  const b=item?.body;
  if(!exact(item,['body','signatureBase64'])||!exact(b,CLAIM_KEYS)||
      b.format!=='aaditech-quote-evidence-intake-claim-v1'||
      !ROLES.includes(b.signerRole)||!ID.test(String(b.signerKeyId))||
      !ID.test(String(b.claimedSourceId))||
      !UUID.test(String(b.quoteId))||
      ![b.challengeSha256,b.boDossierSha256,b.bmReceiptSha256,
        b.bnPacketSha256,b.publicationHeadSha256,b.crlSha256,b.ocspSha256,
        b.issuerChainSha256,b.restoredReceiptSha256,b.restoredSourceSha256,
        b.drTranscriptSha256].every(v=>SHA.test(String(v)))||
      b.evidenceState!=='CANDIDATE_UNVERIFIED'||
      !Number.isSafeInteger(b.revocationEpoch)||b.revocationEpoch<1||
      !Number.isSafeInteger(b.restoredSequence)||b.restoredSequence<0||
      !Number.isSafeInteger(b.rtoSeconds)||b.rtoSeconds<0||b.rtoSeconds>86400||
      !Number.isSafeInteger(b.rpoSeconds)||b.rpoSeconds<0||b.rpoSeconds>86400||
      typeof b.overwriteDenied!=='boolean'||typeof b.deleteDenied!=='boolean'){
   errors.add('BP_CLAIM_SHAPE_INVALID');continue;
  }
  if(byRole.has(b.signerRole)||keys.has(b.signerKeyId)||
     sources.has(b.claimedSourceId))
   errors.add('BP_SIGNER_ROLE_SOURCE_COLLISION');
  byRole.set(b.signerRole,b);keys.add(b.signerKeyId);sources.add(b.claimedSourceId);
  if(b.quoteId!==expected?.quoteId||
     b.challengeSha256!==packet.challengeSha256||
     b.boDossierSha256!==expected?.boDossierSha256||
     b.bmReceiptSha256!==expected?.bmReceiptSha256||
     b.bnPacketSha256!==expected?.bnPacketSha256)
   errors.add('BP_CLAIM_CROSS_BINDING_INVALID');
  const pin=config.get(b.signerRole),when=date(b.observedAt);
  if(!pin||pin.keyId!==b.signerKeyId||
     pin.status!=='ACTIVE'||when===null||
     date(pin.validFrom)===null||date(pin.validUntil)===null||
     when<date(pin.validFrom)!||when>=date(pin.validUntil)!)
   errors.add('BP_SIGNER_UNENROLLED_REVOKED_OR_EXPIRED');
  if(!pin||!validateSignature(b,item.signatureBase64,pin))
   errors.add('BP_SIGNED_CANDIDATE_EVIDENCE_INVALID');
  if(when===null||!Number.isFinite(at)||when>at+60000||at-when>15*60000)
   errors.add('BP_OBSERVATION_STALE_OR_FUTURE');
  if(b.publicationHeadSha256!==expected?.bmReceiptSha256)
   errors.add('BP_OFF_PLATFORM_HEAD_MISMATCH');
  const rFrom=date(b.revocationThisUpdate),rUntil=date(b.revocationNextUpdate);
  if(b.revocationEpoch<expected?.minimumRevocationEpoch)
   errors.add('BP_REVOCATION_EPOCH_ROLLBACK');
  if(rFrom===null||rUntil===null||!Number.isFinite(at)||
     rFrom>at+60000||at-rFrom>3600000||rUntil<=at||rUntil<=rFrom)
   errors.add('BP_REVOCATION_WINDOW_INVALID');
  const expires=date(b.retentionUntil);
  if(expires===null||!Number.isFinite(at)||expires<=at+30*86400000)
   errors.add('BP_WORM_RETENTION_WINDOW_UNPROVEN');
  if(!b.overwriteDenied||!b.deleteDenied)
   errors.add('BP_WORM_DENIAL_CLAIM_MISSING');
  if(b.restoredSequence<expected?.bmSequence)
   errors.add('BP_RECOVERY_ROLLBACK');
  else if(b.restoredSequence!==expected?.bmSequence||
     b.restoredReceiptSha256!==expected?.bmReceiptSha256||
     b.restoredSourceSha256!==expected?.sourceSha256)
   errors.add('BP_RECOVERY_HEAD_MISMATCH');
 }
 if(byRole.size!==4||ROLES.some(role=>!byRole.has(role)))
  errors.add('BP_REQUIRED_SIGNER_ROLE_MISSING');
 const values=[...byRole.values()];
 if(values.length===4)for(const x of values.slice(1)){
  const first=values[0];
  if(x.publicationHeadSha256!==first.publicationHeadSha256||
     x.revocationEpoch!==first.revocationEpoch||
     x.revocationThisUpdate!==first.revocationThisUpdate||
     x.revocationNextUpdate!==first.revocationNextUpdate||
     x.crlSha256!==first.crlSha256||x.ocspSha256!==first.ocspSha256||
     x.issuerChainSha256!==first.issuerChainSha256||
     x.retentionUntil!==first.retentionUntil||
     x.overwriteDenied!==first.overwriteDenied||
     x.deleteDenied!==first.deleteDenied||
     x.restoredSequence!==first.restoredSequence||
     x.restoredReceiptSha256!==first.restoredReceiptSha256||
     x.restoredSourceSha256!==first.restoredSourceSha256||
     x.drTranscriptSha256!==first.drTranscriptSha256||
     x.rtoSeconds!==first.rtoSeconds||x.rpoSeconds!==first.rpoSeconds)
   errors.add('BP_CROSS_SOURCE_PUBLICATION_REVOCATION_WORM_DR_CONFLICT');
 }
 const codes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateIntakeConsistent:codes.length===0,
  candidateIntakeAnomalyCodes:codes,
  candidateIntakePacketSha256:codes.length===0?
   candidateIntakePacketDigest(packet):null,
  candidateIntakePinsetSha256:pinsetSha256,
  candidateOnly:true,
  authenticatedExternalKeyEnrollment:false,
  trustedIndependentHeadRetrieved:false,
  actualCrlOcspChainAuthenticated:false,
  independentWormObjectLockVerified:false,
  realWitnessedDrRecoveryVerified:false,
  issuerLegalAuthorityVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD' as const
 });
}
