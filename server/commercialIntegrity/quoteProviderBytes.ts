import {createHash,createVerify,X509Certificate} from 'node:crypto';
import {candidateRemotePacketDigest,type CandidateRemotePacket} from './quoteRemoteEvidence';

// Phase 1BR: pinned-root, byte-level OFFLINE provider response preflight.
// A syntactically and cryptographically valid candidate X.509 chain does NOT
// establish eMudhra/CCA authorization or real provider control. CRL/OCSP
// blobs are byte-bound, NOT issuer-signature/nonce/responder authenticated.
const SHA=/^[0-9a-f]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const domain='aaditech/quote/provider-checkpoint-bytes/v1\n';
const fields=(v:unknown,keys:string[]):v is Record<string,any>=>
 !!v&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join('|')===keys.slice().sort().join('|');
const time=(v:unknown)=>{
 if(typeof v!=='string'||!ISO.test(v))return null;
 const t=Date.parse(v);
 return Number.isFinite(t)&&new Date(t).toISOString()===v?t:null;
};
const sha=(bytes:Buffer|string)=>createHash('sha256').update(bytes).digest('hex');
const hex=(x:unknown)=>typeof x==='string'&&SHA.test(x);
function decode(value:unknown,max:number):Buffer|null{
 if(typeof value!=='string'||value.length>Math.ceil(max/3)*4+4||
    value.length<4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
  return null;
 const bytes=Buffer.from(value,'base64');
 return bytes.length>0&&bytes.length<=max&&bytes.toString('base64')===value?bytes:null;
}
function derSequence(bytes:Buffer|null){
 if(!bytes||bytes.length<8||bytes[0]!==0x30)return false;
 const b=bytes[1];
 if(b<128)return b+2===bytes.length;
 const n=b&0x7f;
 if(n<1||n>3||bytes.length<2+n||bytes[2]===0)return false;
 let length=0;
 for(let i=0;i<n;i++)length=length*256+bytes[2+i];
 return length>=128&&length+2+n===bytes.length;
}
const urlHost=(url:string):string|null=>{
 try{
  const x=new URL(url);
  if(x.protocol!=='https:'||x.username||x.password||x.search||
     x.hash||x.pathname!=='/'||x.port!==''||x.origin+'/'!==url||
     x.hostname==='localhost'||x.hostname.endsWith('.local')||
     /^\d{1,3}(\.\d{1,3}){3}$/.test(x.hostname))return null;
  return x.hostname;
 }catch{return null;}
};
export type CandidateCheckpointBytes={
 format:'aaditech-quote-provider-checkpoint-v1';
 quoteId:string;challengeSha256:string;bqPacketSha256:string;
 bmReceiptSha256:string;sourceSha256:string;sequence:number;
 revocationEpoch:number;issuedAt:string;expiresAt:string;
 crlSha256:string;ocspSha256:string;
 wormReceiptSha256:string;drTranscriptSha256:string;
 evidenceState:'OFFLINE_CANDIDATE_ONLY'
};
export type CandidateWormBytes={
 format:'aaditech-quote-worm-candidate-v1';
 quoteId:string;objectId:string;retentionUntil:string;
 deniedOverwrite:boolean;deniedDelete:boolean;state:'SIMULATED_ONLY'
};
export type CandidateDrBytes={
 format:'aaditech-quote-dr-candidate-v1';
 quoteId:string;sequence:number;bmReceiptSha256:string;sourceSha256:string;
 restoredAt:string;operatorId:string;witnessId:string;
 rtoSeconds:number;rpoSeconds:number;state:'SIMULATED_ONLY'
};
export type CandidateProviderBytePacket={
 format:'aaditech-quote-provider-byte-evidence-v1';
 quoteId:string;bqPacketSha256:string;challengeSha256:string;
 checkpointUtf8Base64:string;checkpointSignatureBase64:string;
 leafCertificatePem:string;
 crlDerBase64:string;ocspDerBase64:string;
 wormReceiptUtf8Base64:string;drTranscriptUtf8Base64:string
};
export type CandidateByteExpected={
 quoteId:string;bqPacketSha256:string;bmReceiptSha256:string;
 sourceSha256:string;sequence:number;revocationEpoch:number;
 bqExists:boolean;bqLocallyConsistent:boolean;
 bqGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT'
};
const CK=['format','quoteId','challengeSha256','bqPacketSha256','bmReceiptSha256',
 'sourceSha256','sequence','revocationEpoch','issuedAt','expiresAt','crlSha256',
 'ocspSha256','wormReceiptSha256','drTranscriptSha256','evidenceState'];
const WORM=['format','quoteId','objectId','retentionUntil','deniedOverwrite','deniedDelete','state'];
const DR=['format','quoteId','sequence','bmReceiptSha256','sourceSha256','restoredAt',
 'operatorId','witnessId','rtoSeconds','rpoSeconds','state'];
export function candidateBytePacketDigest(p:CandidateProviderBytePacket){
 return sha('aaditech/quote/provider-byte-packet/v1\n'+JSON.stringify(p));
}
export function candidateRootCertificateDigest(rootPem:string){
 const cert=new X509Certificate(rootPem);
 return sha(cert.raw);
}
export function assessCandidateProviderBytes(args:{
 packet:CandidateProviderBytePacket;expected:CandidateByteExpected;
 bqPacket:CandidateRemotePacket;rootCertificatePem:string;
 expectedRootCertSha256:string;expectedProviderOrigin:string;now:Date
}){
 const {packet:p,expected:e,bqPacket:bq,rootCertificatePem,now}=args;
 const errors=new Set<string>(),at=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(at))errors.add('BR_CLOCK_INVALID');
 if(!e||!UUID.test(String(e.quoteId))||
    ![e.bqPacketSha256,e.bmReceiptSha256,e.sourceSha256].every(hex)||
    !Number.isSafeInteger(e.sequence)||e.sequence<1||
    !Number.isSafeInteger(e.revocationEpoch)||e.revocationEpoch<1||
    !e.bqExists||!e.bqLocallyConsistent||e.bqGovernanceState!=='HELD_UNVERIFIED')
  errors.add('BR_BQ_UPSTREAM_NOT_READY');
 if(!fields(p,['format','quoteId','bqPacketSha256','challengeSha256',
    'checkpointUtf8Base64','checkpointSignatureBase64','leafCertificatePem',
    'crlDerBase64','ocspDerBase64','wormReceiptUtf8Base64','drTranscriptUtf8Base64'])||
    p.format!=='aaditech-quote-provider-byte-evidence-v1'||
    !UUID.test(String(p.quoteId))||!hex(p.bqPacketSha256)||
    !hex(p.challengeSha256))
  errors.add('BR_PACKET_SHAPE_INVALID');
 let bqHash='';
 try{bqHash=candidateRemotePacketDigest(bq);}
 catch{errors.add('BR_BQ_PACKET_INVALID');}
 if(p.quoteId!==e?.quoteId||p.bqPacketSha256!==e?.bqPacketSha256||
    bqHash!==e?.bqPacketSha256||
    p.challengeSha256!==bq?.challengeSha256||
    bq?.quoteId!==e?.quoteId||!Array.isArray(bq?.captures)||
    bq.captures.length!==2)
  errors.add('BR_BQ_PACKET_DIGEST_OR_CHALLENGE_MISMATCH');
 const a=bq?.captures?.[0]?.body,b=bq?.captures?.[1]?.body;
 if(!a||!b||a.role===b.role||a.remoteReceiptSha256!==b.remoteReceiptSha256||
    a.remoteSourceSha256!==b.remoteSourceSha256||
    a.crlSha256!==b.crlSha256||a.ocspSha256!==b.ocspSha256||
    a.revocationEpoch!==b.revocationEpoch||
    a.remoteSequence!==b.remoteSequence||
    a.drTranscriptSha256!==b.drTranscriptSha256||
    a.wormDeleteDenied!==b.wormDeleteDenied||
    a.wormOverwriteDenied!==b.wormOverwriteDenied)
  errors.add('BR_PREVIOUS_COLLECTORS_DISAGREE');
 const checkBytes=decode(p.checkpointUtf8Base64,4096);
 const signature=decode(p.checkpointSignatureBase64,8192);
 const crl=decode(p.crlDerBase64,65536),ocsp=decode(p.ocspDerBase64,65536);
 const wormBytes=decode(p.wormReceiptUtf8Base64,4096),
  drBytes=decode(p.drTranscriptUtf8Base64,4096);
 if(!checkBytes||!signature||!wormBytes||!drBytes||!derSequence(crl)||
    !derSequence(ocsp))
  errors.add('BR_BYTES_INVALID_NONCANONICAL_OR_DER_BOUND');
 const parse=(bytes:Buffer|null):Record<string,any>=>{
  if(!bytes)return {};
  try{
   const s=bytes.toString('utf8');
   if(!Buffer.from(s,'utf8').equals(bytes))return {};
   const v=JSON.parse(s);
   return v&&typeof v==='object'&&!Array.isArray(v)&&
    JSON.stringify(v)===s?v:{};
  }catch{return {};}
 };
 const c=parse(checkBytes),w=parse(wormBytes),d=parse(drBytes);
 if(!fields(c,CK)||c.format!=='aaditech-quote-provider-checkpoint-v1'||
    c.evidenceState!=='OFFLINE_CANDIDATE_ONLY'||
    !Number.isSafeInteger(c.sequence)||c.sequence<1||
    !Number.isSafeInteger(c.revocationEpoch)||c.revocationEpoch<1||
    ![c.challengeSha256,c.bqPacketSha256,c.bmReceiptSha256,
      c.sourceSha256,c.crlSha256,c.ocspSha256,c.wormReceiptSha256,
      c.drTranscriptSha256].every(hex))
  errors.add('BR_CHECKPOINT_BODY_INVALID');
 if(c.quoteId!==e?.quoteId||c.challengeSha256!==p.challengeSha256||
    c.bqPacketSha256!==e?.bqPacketSha256||
    c.bmReceiptSha256!==e?.bmReceiptSha256||
    c.sourceSha256!==e?.sourceSha256||
    c.sequence!==e?.sequence||c.revocationEpoch!==e?.revocationEpoch||
    c.sequence!==a?.remoteSequence||
    c.bmReceiptSha256!==a?.remoteReceiptSha256||
    c.sourceSha256!==a?.remoteSourceSha256||
    c.revocationEpoch!==a?.revocationEpoch)
  errors.add('BR_CHECKPOINT_REMOTE_HEAD_ROLLBACK_OR_FORK');
 const issued=time(c.issuedAt),expires=time(c.expiresAt);
 if(issued===null||expires===null||!Number.isFinite(at)||
    issued>at+60000||at-issued>15*60000||expires<=at||
    expires<=issued)errors.add('BR_SIGNED_CHECKPOINT_STALE_OR_FUTURE');
 if(!fields(w,WORM)||w.format!=='aaditech-quote-worm-candidate-v1'||
    w.state!=='SIMULATED_ONLY'||typeof w.objectId!=='string'||
    !/^[a-zA-Z0-9._:-]{3,96}$/.test(w.objectId)||
    w.deniedOverwrite!==true||w.deniedDelete!==true||
    w.quoteId!==e?.quoteId||
    w.retentionUntil!==a?.wormRetentionUntil||
    a?.wormOverwriteDenied!==true||a?.wormDeleteDenied!==true||
    time(w.retentionUntil)===null||time(w.retentionUntil)!<=at+30*86400000)
  errors.add('BR_WORM_CAPTURE_CONFLICT_OR_UNPROVEN');
 if(!fields(d,DR)||d.format!=='aaditech-quote-dr-candidate-v1'||
    d.state!=='SIMULATED_ONLY'||d.quoteId!==e?.quoteId||
    !Number.isSafeInteger(d.sequence)||d.sequence<0||
    d.sequence!==e?.sequence||d.sequence!==a?.drRestoredSequence||
    d.bmReceiptSha256!==e?.bmReceiptSha256||
    d.bmReceiptSha256!==a?.drRestoredReceiptSha256||
    d.sourceSha256!==e?.sourceSha256||
    d.sourceSha256!==a?.drRestoredSourceSha256||
    typeof d.operatorId!=='string'||typeof d.witnessId!=='string'||
    !/^[a-zA-Z0-9._:-]{3,96}$/.test(d.operatorId)||
    !/^[a-zA-Z0-9._:-]{3,96}$/.test(d.witnessId)||
    d.operatorId===d.witnessId||
    !Number.isSafeInteger(d.rtoSeconds)||d.rtoSeconds<0||
    d.rtoSeconds>86400||!Number.isSafeInteger(d.rpoSeconds)||
    d.rpoSeconds<0||d.rpoSeconds>86400||
    time(d.restoredAt)===null||time(d.restoredAt)!>at+60000||
    at-time(d.restoredAt)!>86400000)
  errors.add('BR_DR_RESTORED_HEAD_OR_WITNESS_CLAIM_CONFLICT');
 if(!crl||!ocsp||!wormBytes||!drBytes||
    sha(crl)!==c.crlSha256||sha(ocsp)!==c.ocspSha256||
    sha(wormBytes)!==c.wormReceiptSha256||
    sha(drBytes)!==c.drTranscriptSha256||
    c.crlSha256!==a?.crlSha256||c.ocspSha256!==a?.ocspSha256||
    c.drTranscriptSha256!==a?.drTranscriptSha256)
  errors.add('BR_RAW_BYTES_VERSUS_BQ_CAPTURE_HASH_MISMATCH');
 let rootHash:string|null=null;
 const host=urlHost(args.expectedProviderOrigin);
 try{
  const root=new X509Certificate(rootCertificatePem);
  const leaf=new X509Certificate(p.leafCertificatePem);
  rootHash=sha(root.raw);
  if(!hex(args.expectedRootCertSha256)||
     rootHash!==args.expectedRootCertSha256||!root.ca||
     leaf.ca||!host||!leaf.checkHost(host,{subject:'default'})||
     !leaf.checkIssued(root)||!leaf.verify(root.publicKey)||
     !root.verify(root.publicKey))
   errors.add('BR_ROOT_OR_LEAF_CERT_CHAIN_INVALID');
  const notBefore=Math.max(Date.parse(root.validFrom),Date.parse(leaf.validFrom)),
   notAfter=Math.min(Date.parse(root.validTo),Date.parse(leaf.validTo));
  if(!Number.isFinite(notBefore)||!Number.isFinite(notAfter)||
     !Number.isFinite(at)||at<notBefore||at>notAfter)
   errors.add('BR_CERTIFICATE_OUTSIDE_VALIDITY');
  if(!checkBytes||!signature||!createVerify('RSA-SHA256')
    .update(Buffer.concat([Buffer.from(domain),checkBytes])).verify(leaf.publicKey,signature))
   errors.add('BR_SIGNED_CHECKPOINT_BYTES_INVALID');
 }catch{errors.add('BR_CERTIFICATE_PARSE_OR_SIGNATURE_FAILED');}
 const codes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateBytePreflightConsistent:codes.length===0,
  candidateBytePreflightAnomalyCodes:codes,
  candidateBytePacketSha256:codes.length===0?candidateBytePacketDigest(p):null,
  candidateRootCertificateSha256:rootHash,
  byteHashAndOfflineCertificateSignatureChecked:codes.length===0,
  enrolledExternalRootAuthenticated:false,
  liveTlsProviderSessionVerified:false,
  authorizedIssuerPolicyAndCertificatePathVerified:false,
  signedCrlOcspAndResponderAuthorized:false,
  independentWormObjectLockVerified:false,
  realEncryptedDrRestorationWitnessed:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD' as const
 });
}
