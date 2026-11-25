import {createHash,createVerify,X509Certificate} from 'node:crypto';
import {candidateBytePacketDigest,candidateRootCertificateDigest,
 type CandidateProviderBytePacket} from './quoteProviderBytes';
import {derRead,derTop,derChildren,derExact,derRaw,derValue,derOid,
 derInteger,derNumber,derBits,derTime,derAlg,derExtensions,derCertParts,
 derIssuerHash,type DerNode} from './quoteSignedDer';

// 1BS restrictive *issuer-direct* offline CRL/OCSP subset. NO live transport,
// trusted RCAI/CCA/eMudhra issuer enrollment, full RFC 5280 policy/path
// processing, delegated responders, independent Object Lock or production grant.
const SHA=/^[0-9a-f]{64}$/;
const SHA256RSA='1.2.840.113549.1.1.11';
const BASIC_OCSP='1.3.6.1.5.5.7.48.1.1';
const NONCE='1.3.6.1.5.5.7.48.1.2';
const CRL_NUMBER='2.5.29.20';
const SHA1='1.3.14.3.2.26',SHA256='2.16.840.1.101.3.4.2.1';
const digest=(input:Buffer|string)=>createHash('sha256').update(input).digest('hex');
const decode=(text:string,max:number):Buffer=>{
 if(typeof text!=='string'||text.length>Math.ceil(max/3)*4+4||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
  throw Error('BS_NONCANONICAL_BASE64');
 const bytes=Buffer.from(text,'base64');
 if(!bytes.length||bytes.length>max||bytes.toString('base64')!==text)
  throw Error('BS_NONCANONICAL_BASE64');
 return bytes;
};
function verifyRsaSha256(tbs:DerNode,outerAlg:DerNode,signature:DerNode,
 publicKey:X509Certificate['publicKey'],innerAlg?:DerNode){
 if(derAlg(outerAlg)!==SHA256RSA||
    (innerAlg&&derAlg(innerAlg)!==SHA256RSA))
  throw Error('BS_UNSUPPORTED_SIGNATURE_ALGORITHM');
 const signed=derBits(signature);
 if(signed.length<128||signed.length>512||
    !createVerify('RSA-SHA256').update(derRaw(tbs)).verify(publicKey,signed))
  throw Error('BS_ISSUER_SIGNATURE_INVALID');
}
function freshness(thisUpdate:number,nextUpdate:number,now:number){
 if(!Number.isFinite(now)||thisUpdate>now+60000||
    now-thisUpdate>3600000||nextUpdate<=now||nextUpdate<=thisUpdate||
    nextUpdate-thisUpdate>86400000)
  throw Error('BS_STATUS_STALE_FUTURE_OR_UNBOUNDED');
}
function parseCrl(crl:Buffer,issuer:X509Certificate,subject:Buffer,
 leafSerial:bigint,now:number,minimum:number){
 const parts=derChildren(derTop(crl,0x30),3);
 if(parts.length!==3)throw Error('BS_CRL_STRUCTURE_INVALID');
 const tbs=derChildren(derExact(parts[0],0x30),8);
 let i=0;
 if(tbs[i]?.tag!==0x02||derNumber(tbs[i++],1,1)!==1)
  throw Error('BS_CRL_V2_REQUIRED');
 const algorithm=tbs[i++],name=tbs[i++];
 if(!derRaw(derExact(name,0x30)).equals(subject))
  throw Error('BS_CRL_ISSUER_MISMATCH');
 const updated=derTime(tbs[i++]),until=derTime(tbs[i++]);
 freshness(updated,until,now);
 let revoked=false;
 if(tbs[i]?.tag===0x30){
  const entries=derChildren(tbs[i++],1000),seen=new Set<string>();
  for(const entry of entries){
   const x=derChildren(derExact(entry,0x30),4);
   if(x.length<2||x.length>3)throw Error('BS_CRL_REVOKED_ENTRY_INVALID');
   const serial=derInteger(x[0]),key=serial.toString(16);
   if(seen.has(key))throw Error('BS_CRL_DUPLICATE_SERIAL');
   seen.add(key);
   const date=derTime(x[1]);
   if(date>now+60000)throw Error('BS_CRL_FUTURE_REVOCATION');
   if(x[2])throw Error('BS_CRL_ENTRY_EXTENSION_UNSUPPORTED');
   if(serial===leafSerial)revoked=true;
  }
 }
 if(tbs[i]?.tag!==0xa0||i!==tbs.length-1)
  throw Error('BS_CRL_NUMBER_REQUIRED');
 const ext=derChildren(tbs[i++],1);
 if(ext.length!==1)throw Error('BS_CRL_EXTENSION_INVALID');
 const extensions=derExtensions(ext[0]);
 if(extensions.size!==1||!extensions.has(CRL_NUMBER))
  throw Error('BS_CRL_EXTENSION_UNSUPPORTED');
 const number=derNumber(derTop(extensions.get(CRL_NUMBER)!,0x02),1,2147483647);
 if(number<minimum)throw Error('BS_CRL_NUMBER_ROLLBACK');
 verifyRsaSha256(parts[0],parts[1],parts[2],issuer.publicKey,algorithm);
 if(revoked)throw Error('BS_TARGET_SERIAL_REVOKED');
 return {number,updated,until};
}
function parseOcsp(ocsp:Buffer,issuer:X509Certificate,
 issuerParts:ReturnType<typeof derCertParts>,leafSerial:bigint,
 nonce:Buffer,now:number){
 const response=derChildren(derTop(ocsp,0x30),2);
 if(response.length!==2||response[0].tag!==0x0a||
    !derValue(response[0]).equals(Buffer.from([0]))||
    response[1].tag!==0xa0)
  throw Error('BS_OCSP_UNSUCCESSFUL_OR_MALFORMED');
 const wrapping=derChildren(response[1],1);
 const wrapper=derChildren(derExact(wrapping[0],0x30),2);
 if(wrapping.length!==1||wrapper.length!==2||
    derOid(wrapper[0])!==BASIC_OCSP||wrapper[1].tag!==0x04)
  throw Error('BS_OCSP_BASIC_RESPONSE_REQUIRED');
 const basic=derChildren(derTop(derValue(wrapper[1]),0x30),4);
 if(basic.length!==3)
  throw Error('BS_DELEGATED_OCSP_CERTS_UNSUPPORTED');
 const tbs=derChildren(derExact(basic[0],0x30),6);
 let i=0;
 if(tbs[i]?.tag===0xa0){
  const version=derChildren(tbs[i++],1);
  if(version.length!==1||derNumber(version[0],0,0)!==0)
   throw Error('BS_OCSP_VERSION_UNSUPPORTED');
 }
 const responder=tbs[i++];
 if(!responder||responder.tag!==0xa1)
  throw Error('BS_ONLY_ISSUER_NAME_RESPONDER_SUPPORTED');
 const responseName=derChildren(responder,1);
 if(responseName.length!==1||!derRaw(responseName[0]).equals(issuerParts.subject))
  throw Error('BS_OCSP_RESPONDER_NOT_ISSUER');
 const producedAt=derTime(derExact(tbs[i++],0x18));
 const responses=derChildren(derExact(tbs[i++],0x30),2);
 if(responses.length!==1)throw Error('BS_OCSP_EXACT_ONE_SINGLE_RESPONSE');
 const single=derChildren(derExact(responses[0],0x30),6);
 if(single.length<3||single.length>5)throw Error('BS_OCSP_SINGLE_MALFORMED');
 let j=0;
 const certId=derChildren(derExact(single[j++],0x30),4);
 if(certId.length!==4)throw Error('BS_OCSP_CERT_ID_INVALID');
 const hashOid=derAlg(certId[0]);
 const hash=hashOid===SHA1?'sha1':hashOid===SHA256?'sha256':null;
 if(!hash)throw Error('BS_OCSP_CERTID_HASH_UNSUPPORTED');
 const expected=derIssuerHash(issuerParts.subject,issuerParts.subjectPublicKey,hash);
 if(certId[1].tag!==0x04||certId[2].tag!==0x04||
    !derValue(certId[1]).equals(expected.name)||
    !derValue(certId[2]).equals(expected.key)||
    derInteger(certId[3])!==leafSerial)
  throw Error('BS_OCSP_CERT_ID_ISSUER_OR_SERIAL_MISMATCH');
 const status=single[j++];
 if(status.tag!==0x80||derValue(status).length!==0)
  throw Error('BS_OCSP_TARGET_NOT_GOOD');
 const updated=derTime(derExact(single[j++],0x18));
 if(single[j]?.tag!==0xa0)
  throw Error('BS_OCSP_NEXTUPDATE_REQUIRED');
 const wrappedNext=derChildren(single[j++],1);
 if(wrappedNext.length!==1)throw Error('BS_OCSP_NEXTUPDATE_INVALID');
 const until=derTime(derExact(wrappedNext[0],0x18));
 if(j!==single.length)throw Error('BS_OCSP_SINGLE_EXTENSION_UNSUPPORTED');
 freshness(updated,until,now);
 if(producedAt>now+60000||now-producedAt>3600000||
    producedAt+60000<updated)
  throw Error('BS_OCSP_PRODUCEDAT_INVALID');
 if(tbs[i]?.tag!==0xa1||i!==tbs.length-1)
  throw Error('BS_OCSP_NONCE_EXTENSION_REQUIRED');
 const responseExt=derChildren(tbs[i++],1);
 if(responseExt.length!==1)throw Error('BS_OCSP_EXTENSIONS_INVALID');
 const ext=derExtensions(responseExt[0]);
 if(ext.size!==1||!ext.has(NONCE)||
    !derValue(derTop(ext.get(NONCE)!,0x04)).equals(nonce))
  throw Error('BS_OCSP_NONCE_MISMATCH');
 verifyRsaSha256(basic[0],basic[1],basic[2],issuer.publicKey);
 return {updated,until,producedAt};
}
export type CandidateRevocationExpected={
 quoteId:string;brPacketSha256:string;rootCertSha256:string;
 minimumRevocationEpoch:number;brLocallyConsistent:boolean;
 brGovernanceState:'HELD_UNVERIFIED'|'QUARANTINED'|'ABSENT';
 brExists:boolean
};
export function assessCandidateSignedRevocation(args:{
 brPacket:CandidateProviderBytePacket;expected:CandidateRevocationExpected;
 issuerCertificatePem:string;expectedIssuerRootSha256:string;now:Date
}){
 const errors=new Set<string>(),{brPacket:p,expected:e,now}=args;
 let crlNumber:number|null=null,crlThisUpdate:number|null=null,
  ocspThisUpdate:number|null=null,crlUntil:number|null=null,
  ocspUntil:number|null=null,issuerRootSha256:string|null=null;
 const at=now instanceof Date?now.getTime():NaN;
 if(!Number.isFinite(at))errors.add('BS_CLOCK_INVALID');
 if(!e||!SHA.test(String(e.brPacketSha256))||
    !SHA.test(String(e.rootCertSha256))||
    !Number.isSafeInteger(e.minimumRevocationEpoch)||
    e.minimumRevocationEpoch<1||!e.brExists||!e.brLocallyConsistent||
    e.brGovernanceState!=='HELD_UNVERIFIED')
  errors.add('BS_UPSTREAM_BR_NOT_HELD');
 let packetHash='';
 try{packetHash=candidateBytePacketDigest(p);}
 catch{errors.add('BS_BR_PACKET_INVALID');}
 if(packetHash!==e?.brPacketSha256||!SHA.test(String(p?.challengeSha256)))
  errors.add('BS_BR_HASH_OR_CHALLENGE_MISMATCH');
 try{
  const issuer=new X509Certificate(args.issuerCertificatePem);
  const leaf=new X509Certificate(p.leafCertificatePem);
  issuerRootSha256=candidateRootCertificateDigest(args.issuerCertificatePem);
  if(!SHA.test(args.expectedIssuerRootSha256)||
     issuerRootSha256!==args.expectedIssuerRootSha256||
     issuerRootSha256!==e.rootCertSha256||
     !issuer.ca||!issuer.verify(issuer.publicKey)||
     leaf.ca||!leaf.checkIssued(issuer)||!leaf.verify(issuer.publicKey))
   throw Error('BS_ISSUER_ROOT_PIN_OR_LEAF_CHAIN_INVALID');
  const issuerValidity=[Date.parse(issuer.validFrom),Date.parse(issuer.validTo)];
  const leafValidity=[Date.parse(leaf.validFrom),Date.parse(leaf.validTo)];
  if(![...issuerValidity,...leafValidity].every(Number.isFinite)||
     at<Math.max(issuerValidity[0],leafValidity[0])||
     at>Math.min(issuerValidity[1],leafValidity[1]))
   throw Error('BS_CERT_VALIDITY_INVALID');
  const subject=derCertParts(issuer.raw),target=derCertParts(leaf.raw);
  if(!subject.subject.length||target.serial<=0n)
   throw Error('BS_ISSUER_OR_TARGET_DER_INVALID');
  const crl=parseCrl(decode(p.crlDerBase64,65536),issuer,subject.subject,
   target.serial,at,e.minimumRevocationEpoch);
  crlNumber=crl.number;crlThisUpdate=crl.updated;crlUntil=crl.until;
  const ocsp=parseOcsp(decode(p.ocspDerBase64,65536),issuer,subject,
   target.serial,Buffer.from(p.challengeSha256,'hex'),at);
  ocspThisUpdate=ocsp.updated;ocspUntil=ocsp.until;
  if(Math.abs(crl.updated-ocsp.updated)>3600000)
   throw Error('BS_CRL_OCSP_FRESHNESS_DIVERGENCE');
 }catch(ex){
  errors.add(ex instanceof Error&&ex.message.startsWith('BS_')?
   ex.message:'BS_ASN1_SIGNATURE_OR_STRUCTURE_INVALID');
 }
 const codes=Object.freeze([...errors].sort());
 return Object.freeze({
  candidateSignedRevocationConsistent:codes.length===0,
  candidateSignedRevocationAnomalyCodes:codes,
  brPacketSha256:packetHash||null,
  candidateIssuerRootSha256:issuerRootSha256,
  crlNumber,crlThisUpdate,crlUntil,ocspThisUpdate,ocspUntil,
  syntheticIssuerCrlSignatureChecked:codes.length===0,
  syntheticIssuerOcspSignatureChecked:codes.length===0,
  syntheticOcspSerialAndNonceChecked:codes.length===0,
  independentlyEnrolledCAKey:false,
  genuineRCAIorCCAIssuerPolicyVerified:false,
  realProviderCrlDistributionAuthenticated:false,
  liveOcspRequestResponseAuthenticated:false,
  externalMonotonicHeadIndependentlyRetained:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD' as const
 });
}
