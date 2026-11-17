import {createHash,createPublicKey,verify} from 'node:crypto';

// 1BQ: offline candidate registrar + transport/retrieval receipts. No real
// HTTP request, independently enrolled root, live CRL/OCSP or WORM/DR API.
const SHA=/^[0-9a-f]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ID=/^[a-zA-Z0-9._:-]{3,96}$/;
const DATE=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ROLES=['PRIMARY','SECONDARY'] as const;
type Role=typeof ROLES[number];
const exact=(v:unknown,keys:string[]):v is Record<string,any>=>
 !!v&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join('|')===keys.slice().sort().join('|');
const stamp=(v:unknown):number|null=>{
 if(typeof v!=='string'||!DATE.test(v))return null;
 const ms=Date.parse(v);return Number.isFinite(ms)&&new Date(ms).toISOString()===v?ms:null;
};
function canonical(value:unknown,depth=0):unknown{
 if(depth>6)throw Error('BQ excessive evidence nesting');
 if(value===null||typeof value==='string'||typeof value==='boolean')return value;
 if(typeof value==='number'&&Number.isFinite(value))return value;
 if(Array.isArray(value)){
  if(value.length>4)throw Error('BQ excessive array');
  return value.map(x=>canonical(x,depth+1));
 }
 if(value&&typeof value==='object'){
  const raw=value as Record<string,unknown>,keys=Object.keys(raw).sort();
  if(keys.length>32||keys.some(x=>['__proto__','constructor','prototype'].includes(x)))
   throw Error('BQ invalid evidence object');
  const output:Record<string,unknown>={};
  for(const key of keys)output[key]=canonical(raw[key],depth+1);
  return output;
 }
 throw Error('BQ unsupported evidence scalar');
}
const serialized=(v:unknown)=>JSON.stringify(canonical(v));
const digest=(domain:string,value:unknown)=>createHash('sha256')
 .update(domain+'\n'+serialized(value)).digest('hex');
const validOrigin=(value:unknown)=>{
 if(typeof value!=='string'||value.length>240)return false;
 try{
  const u=new URL(value);
  return u.protocol==='https:'&&u.hostname.length>3&&
   !u.username&&!u.password&&!u.search&&!u.hash&&
   u.pathname==='/'&&u.port===''&&u.origin+'/'===value&&
   !/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)&&
   u.hostname!=='localhost'&&!u.hostname.endsWith('.localhost')&&
   !u.hostname.endsWith('.local');
 }catch{return false;}
};
function signature(body:unknown,signatureBase64:unknown,spkiPem:string,domain:string){
 try{
  if(typeof signatureBase64!=='string'||signatureBase64.length!==88||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64))return false;
  const bytes=Buffer.from(signatureBase64,'base64');
  if(bytes.length!==64||bytes.toString('base64')!==signatureBase64)return false;
  const publicKey=createPublicKey(spkiPem);
  return publicKey.asymmetricKeyType==='ed25519'&&
   verify(null,Buffer.from(domain+'\n'+serialized(body)),publicKey,bytes);
 }catch{return false;}
}
const publicDigest=(pem:string)=>{
 const key=createPublicKey(pem);
 if(key.asymmetricKeyType!=='ed25519')throw Error('BQ non Ed25519 candidate pin');
 return createHash('sha256').update(
  key.export({type:'spki',format:'der'})).digest('hex');
};
export type CandidateRegistrarPin={keyId:string,publicKeySpkiPem:string,
 status:'ACTIVE'|'REVOKED'|'UNKNOWN',validFrom:string,validUntil:string};
export type CandidateCollectorPin={role:Role,keyId:string,
 publicKeySpkiPem:string,status:'ACTIVE'|'REVOKED'|'UNKNOWN',
 validFrom:string,validUntil:string};
export type CandidateEndpointConfig={role:Role,origin:string,tlsSpkiSha256:string};
export type CandidateEnrollmentManifest={
 format:'aaditech-quote-registrar-manifest-v1';quoteId:string;providerId:string;
 registrarKeyId:string;collectorPinsetSha256:string;endpointConfigSha256:string;
 policySha256:string;epoch:number;issuedAt:string;expiresAt:string;
 state:'OFFLINE_CANDIDATE_ONLY'
};
export type CandidateRemoteCapture={
 format:'aaditech-quote-remote-capture-v1';quoteId:string;role:Role;
 collectorKeyId:string;manifestSha256:string;challengeSha256:string;
 origin:string;tlsSpkiSha256:string;retrievedAt:string;
 transportMode:'REPLAY_CAPTURE_ONLY';httpStatus:200;
 redirectCount:0;contentType:'application/vnd.aaditech.checkpoint+json';
 remoteSequence:number;remoteReceiptSha256:string;remoteSourceSha256:string;
 revocationEpoch:number;crlSha256:string;ocspSha256:string;issuerChainSha256:string;
 wormDeleteDenied:boolean;wormOverwriteDenied:boolean;wormRetentionUntil:string;
 drRestoredSequence:number;drRestoredReceiptSha256:string;drRestoredSourceSha256:string;
 drTranscriptSha256:string
};
export type CandidateRemotePacket={
 format:'aaditech-quote-remote-evidence-v1';quoteId:string;
 challengeSha256:string;bpPacketSha256:string;
 manifest:CandidateEnrollmentManifest;manifestSignatureBase64:string;
 captures:{body:CandidateRemoteCapture,signatureBase64:string}[]
};
export type CandidateRemoteExpected={
 quoteId:string;bpPacketSha256:string;bmReceiptSha256:string;
 sourceSha256:string;bmSequence:number;minRevocationEpoch:number;
 bpLocallyConsistent:boolean;bpGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT';
 bpExists:boolean
};
const MANIFEST_FIELDS=['format','quoteId','providerId','registrarKeyId',
 'collectorPinsetSha256','endpointConfigSha256','policySha256','epoch',
 'issuedAt','expiresAt','state'];
const CAPTURE_FIELDS=['format','quoteId','role','collectorKeyId','manifestSha256',
 'challengeSha256','origin','tlsSpkiSha256','retrievedAt','transportMode',
 'httpStatus','redirectCount','contentType','remoteSequence','remoteReceiptSha256',
 'remoteSourceSha256','revocationEpoch','crlSha256','ocspSha256','issuerChainSha256',
 'wormDeleteDenied','wormOverwriteDenied','wormRetentionUntil','drRestoredSequence',
 'drRestoredReceiptSha256','drRestoredSourceSha256','drTranscriptSha256'];
export const canonicalCandidateRegistrarManifest=(manifest:CandidateEnrollmentManifest)=>
 serialized(manifest);
export const canonicalCandidateRemoteCapture=(capture:CandidateRemoteCapture)=>
 serialized(capture);
export const candidateRegistrarManifestDigest=(manifest:CandidateEnrollmentManifest)=>
 digest('aaditech/quote/registrar-manifest/v1',manifest);
export const candidateRemotePacketDigest=(packet:CandidateRemotePacket)=>
 digest('aaditech/quote/remote-evidence/v1',packet);
export function candidateCollectorPinsetDigest(pins:CandidateCollectorPin[]){
 if(!Array.isArray(pins)||pins.length!==2)throw Error('BQ requires exactly two pinned collectors');
 const rows=pins.map(x=>{
  if(!x||!ROLES.includes(x.role)||!ID.test(String(x.keyId))||
    !['ACTIVE','REVOKED','UNKNOWN'].includes(x.status)||
    stamp(x.validFrom)===null||stamp(x.validUntil)===null||
    stamp(x.validFrom)!>=stamp(x.validUntil)!)
   throw Error('BQ malformed collector pin');
  return {role:x.role,keyId:x.keyId,status:x.status,
   validFrom:x.validFrom,validUntil:x.validUntil,spkiSha256:publicDigest(x.publicKeySpkiPem)};
 }).sort((a,b)=>a.role.localeCompare(b.role));
 if(new Set(rows.map(x=>x.role)).size!==2||
   new Set(rows.map(x=>x.keyId)).size!==2||
   new Set(rows.map(x=>x.spkiSha256)).size!==2)
  throw Error('BQ two collector keys must have separate provenance');
 return digest('aaditech/quote/collector-pins/v1',rows);
}
export function candidateEndpointConfigDigest(config:CandidateEndpointConfig[]){
 if(!Array.isArray(config)||config.length!==2)throw Error('BQ exactly two configured endpoints required');
 const rows=config.map(c=>{
  if(!c||!ROLES.includes(c.role)||!validOrigin(c.origin)||
     !SHA.test(String(c.tlsSpkiSha256)))throw Error('BQ invalid endpoint allowlist/TLS pin');
  return {role:c.role,origin:c.origin,tlsSpkiSha256:c.tlsSpkiSha256};
 }).sort((a,b)=>a.role.localeCompare(b.role));
 if(new Set(rows.map(x=>x.role)).size!==2||
    new Set(rows.map(x=>x.origin)).size!==2||
    new Set(rows.map(x=>x.tlsSpkiSha256)).size!==2)
  throw Error('BQ endpoint origins and TLS pins must be distinct');
 return digest('aaditech/quote/endpoints/v1',rows);
}
export function candidateRegistrarPinDigest(pin:CandidateRegistrarPin){
 if(!pin||!ID.test(String(pin.keyId))||
    !['ACTIVE','REVOKED','UNKNOWN'].includes(pin.status)||
    stamp(pin.validFrom)===null||stamp(pin.validUntil)===null||
    stamp(pin.validFrom)!>=stamp(pin.validUntil)!)
  throw Error('BQ malformed registrar pin');
 return digest('aaditech/quote/registrar-pin/v1',{
  keyId:pin.keyId,status:pin.status,validFrom:pin.validFrom,
  validUntil:pin.validUntil,spkiSha256:publicDigest(pin.publicKeySpkiPem)});
}
export function assessCandidateRemoteEvidence(args:{
 packet:CandidateRemotePacket,expected:CandidateRemoteExpected;
 registrarPin:CandidateRegistrarPin;collectorPins:CandidateCollectorPin[];
 endpoints:CandidateEndpointConfig[];expectedRegistrarPinSha256:string;
 expectedCollectorPinsetSha256:string;expectedEndpointConfigSha256:string;
 now:Date
}){
 const errors=new Set<string>();
 const {packet:p,expected:e,registrarPin,collectorPins,endpoints,now}=args;
 const at=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(at))errors.add('BQ_CLOCK_INVALID');
 let rootSha='',pinsSha='',endpointsSha='';
 try{rootSha=candidateRegistrarPinDigest(registrarPin);}catch{errors.add('BQ_REGISTRAR_PIN_INVALID');}
 try{pinsSha=candidateCollectorPinsetDigest(collectorPins);}catch{errors.add('BQ_COLLECTOR_PINS_INVALID');}
 try{endpointsSha=candidateEndpointConfigDigest(endpoints);}catch{errors.add('BQ_ENDPOINTS_INVALID');}
 if(!SHA.test(args.expectedRegistrarPinSha256)||rootSha!==args.expectedRegistrarPinSha256||
    !SHA.test(args.expectedCollectorPinsetSha256)||pinsSha!==args.expectedCollectorPinsetSha256||
    !SHA.test(args.expectedEndpointConfigSha256)||endpointsSha!==args.expectedEndpointConfigSha256)
  errors.add('BQ_OPERATOR_CONFIG_PIN_MISMATCH');
 if(!e||!UUID.test(String(e.quoteId))||
   ![e.bpPacketSha256,e.bmReceiptSha256,e.sourceSha256].every(x=>SHA.test(String(x)))||
   !Number.isSafeInteger(e.bmSequence)||e.bmSequence<1||
   !Number.isSafeInteger(e.minRevocationEpoch)||e.minRevocationEpoch<1||
   e.bpExists!==true||e.bpLocallyConsistent!==true||
   e.bpGovernanceState!=='HELD_UNVERIFIED')
  errors.add('BQ_BP_PREDECESSOR_NOT_HELD');
 if(!exact(p,['format','quoteId','challengeSha256','bpPacketSha256',
    'manifest','manifestSignatureBase64','captures'])||
    p.format!=='aaditech-quote-remote-evidence-v1'||
    !UUID.test(String(p.quoteId))||!SHA.test(String(p.challengeSha256))||
    !SHA.test(String(p.bpPacketSha256))||
    !Array.isArray(p.captures)||p.captures.length!==2)
  errors.add('BQ_PACKET_INVALID');
 if(p.quoteId!==e?.quoteId||p.bpPacketSha256!==e?.bpPacketSha256)
  errors.add('BQ_BP_HEAD_OR_QUOTE_MISMATCH');
 const m=p.manifest;
 if(!exact(m,MANIFEST_FIELDS)||
    m.format!=='aaditech-quote-registrar-manifest-v1'||
    !ID.test(String(m.providerId))||!ID.test(String(m.registrarKeyId))||
    ![m.collectorPinsetSha256,m.endpointConfigSha256,m.policySha256]
     .every(x=>SHA.test(String(x)))||
    !Number.isSafeInteger(m.epoch)||m.epoch<1||
    m.state!=='OFFLINE_CANDIDATE_ONLY')
  errors.add('BQ_MANIFEST_SHAPE_OR_AUTHORITY_CLAIM_INVALID');
 if(m.quoteId!==e?.quoteId||m.registrarKeyId!==registrarPin.keyId||
    m.collectorPinsetSha256!==pinsSha||m.endpointConfigSha256!==endpointsSha)
  errors.add('BQ_MANIFEST_SCOPE_OR_PINSET_MISMATCH');
 const issued=stamp(m.issuedAt),expires=stamp(m.expiresAt);
 if(issued===null||expires===null||!Number.isFinite(at)||
    issued>at+60000||at-issued>15*60000||
    expires<=at||expires<=issued)
  errors.add('BQ_MANIFEST_STALE_OR_FUTURE');
 if(registrarPin.status!=='ACTIVE'||issued===null||
    issued<stamp(registrarPin.validFrom)!||issued>=stamp(registrarPin.validUntil)!)
  errors.add('BQ_REGISTRAR_NOT_ACTIVE');
 if(!signature(m,p.manifestSignatureBase64,registrarPin.publicKeySpkiPem,
     'aaditech/quote/registrar-manifest/v1'))
  errors.add('BQ_MANIFEST_SIGNATURE_INVALID');
 const manifestHash=candidateRegistrarManifestDigest(m);
 const seenSources=new Set<string>(),seenKeys=new Set<string>(),seenRoles=new Set<string>();
 let first:CandidateRemoteCapture|null=null;
 const configs=new Map((Array.isArray(endpoints)?endpoints:[]).map(x=>[x.role,x]));
 const pins=new Map((Array.isArray(collectorPins)?collectorPins:[]).map(x=>[x.role,x]));
 const captures=Array.isArray(p.captures)?p.captures.slice(0,2):[];
 for(const item of captures){
  const b=item?.body;
  if(!exact(item,['body','signatureBase64'])||!exact(b,CAPTURE_FIELDS)||
     b.format!=='aaditech-quote-remote-capture-v1'||
     !ROLES.includes(b.role)||!ID.test(String(b.collectorKeyId))||
     ![b.manifestSha256,b.challengeSha256,b.remoteReceiptSha256,
       b.remoteSourceSha256,b.crlSha256,b.ocspSha256,b.issuerChainSha256,
       b.drRestoredReceiptSha256,b.drRestoredSourceSha256,b.drTranscriptSha256]
      .every(x=>SHA.test(String(x)))||
     !Number.isSafeInteger(b.remoteSequence)||b.remoteSequence<1||
     !Number.isSafeInteger(b.revocationEpoch)||b.revocationEpoch<1||
     !Number.isSafeInteger(b.drRestoredSequence)||b.drRestoredSequence<0||
     typeof b.wormDeleteDenied!=='boolean'||
     typeof b.wormOverwriteDenied!=='boolean'||
     b.transportMode!=='REPLAY_CAPTURE_ONLY'||b.httpStatus!==200||
     b.redirectCount!==0||
     b.contentType!=='application/vnd.aaditech.checkpoint+json')
   {errors.add('BQ_CAPTURE_SHAPE_OR_NETWORK_PROOF_INVALID');continue;}
  if(seenRoles.has(b.role)||seenKeys.has(b.collectorKeyId)){
   errors.add('BQ_DUPLICATE_COLLECTOR_ROLE_OR_KEY');
  }
  seenRoles.add(b.role);seenKeys.add(b.collectorKeyId);
  const pin=pins.get(b.role),cfg=configs.get(b.role);
  if(!pin||pin.keyId!==b.collectorKeyId||pin.status!=='ACTIVE')
   errors.add('BQ_COLLECTOR_NOT_ENROLLED_OR_REVOKED');
  const retrieved=stamp(b.retrievedAt),pFrom=pin?stamp(pin.validFrom):null,
   pUntil=pin?stamp(pin.validUntil):null;
  if(retrieved===null||pFrom===null||pUntil===null||
    retrieved<pFrom||retrieved>=pUntil||!Number.isFinite(at)||
    retrieved>at+60000||at-retrieved>15*60000)
   errors.add('BQ_CAPTURE_STALE_OR_SIGNER_EXPIRED');
  if(!cfg||!validOrigin(b.origin)||b.origin!==cfg.origin||
    b.tlsSpkiSha256!==cfg.tlsSpkiSha256)
   errors.add('BQ_ENDPOINT_OR_TLS_PIN_SUBSTITUTED');
  if(b.manifestSha256!==manifestHash||
     b.challengeSha256!==p.challengeSha256||b.quoteId!==e?.quoteId)
   errors.add('BQ_CHALLENGE_OR_MANIFEST_BINDING_MISMATCH');
  if(!pin||!signature(b,item.signatureBase64,pin.publicKeySpkiPem,
      'aaditech/quote/remote-capture/v1'))
   errors.add('BQ_CAPTURE_SIGNATURE_INVALID');
  if(b.remoteSequence<e?.bmSequence)
   errors.add('BQ_REMOTE_HEAD_ROLLBACK');
  else if(b.remoteSequence>e?.bmSequence||
     b.remoteReceiptSha256!==e?.bmReceiptSha256||
     b.remoteSourceSha256!==e?.sourceSha256)
   errors.add('BQ_REMOTE_HEAD_FORK_OR_LOCAL_LAG');
  if(b.revocationEpoch<e?.minRevocationEpoch)
   errors.add('BQ_REVOCATION_EPOCH_ROLLBACK');
  if(!b.wormDeleteDenied||!b.wormOverwriteDenied||
    stamp(b.wormRetentionUntil)===null||
    stamp(b.wormRetentionUntil)!<=at+30*86400000)
   errors.add('BQ_WORM_CANDIDATE_DENIAL_MISSING_OR_EXPIRED');
  if(b.drRestoredSequence<e?.bmSequence)
   errors.add('BQ_RECOVERY_ROLLBACK');
  else if(b.drRestoredSequence!==e?.bmSequence||
    b.drRestoredReceiptSha256!==e?.bmReceiptSha256||
    b.drRestoredSourceSha256!==e?.sourceSha256)
   errors.add('BQ_RECOVERY_DRIFT');
  if(first&&(b.remoteSequence!==first.remoteSequence||
      b.remoteReceiptSha256!==first.remoteReceiptSha256||
      b.remoteSourceSha256!==first.remoteSourceSha256||
      b.revocationEpoch!==first.revocationEpoch||
      b.crlSha256!==first.crlSha256||b.ocspSha256!==first.ocspSha256||
      b.issuerChainSha256!==first.issuerChainSha256||
      b.wormDeleteDenied!==first.wormDeleteDenied||
      b.wormOverwriteDenied!==first.wormOverwriteDenied||
      b.wormRetentionUntil!==first.wormRetentionUntil||
      b.drRestoredSequence!==first.drRestoredSequence||
      b.drRestoredReceiptSha256!==first.drRestoredReceiptSha256||
      b.drRestoredSourceSha256!==first.drRestoredSourceSha256||
      b.drTranscriptSha256!==first.drTranscriptSha256))
   errors.add('BQ_TWO_SOURCE_REMOTE_REVOCATION_WORM_DR_CONFLICT');
  if(!first)first=b;
 }
 if(seenRoles.size!==2||ROLES.some(role=>!seenRoles.has(role)))
  errors.add('BQ_SECOND_INDEPENDENT_CANDIDATE_COLLECTOR_MISSING');
 const codes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateRemoteEvidenceConsistent:codes.length===0,
  candidateRemoteEvidenceAnomalyCodes:codes,
  candidateRemotePacketSha256:codes.length===0?candidateRemotePacketDigest(p):null,
  candidateRegistrarPinSha256:rootSha,
  candidateCollectorPinsetSha256:pinsSha,
  candidateEndpointConfigSha256:endpointsSha,
  candidateOnly:true,
  authenticatedRegistrarEnrollment:false,authenticatedIssuerChain:false,
  liveRemoteCheckpointRetrieved:false,actualTlsSessionVerified:false,
  liveSignedCrlOcspValidated:false,independentWormVerified:false,
  realDrRecoveryWitnessed:false,productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD' as const
 });
}
