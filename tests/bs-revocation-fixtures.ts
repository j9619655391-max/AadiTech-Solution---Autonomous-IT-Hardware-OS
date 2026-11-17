import {createHash,createSign,X509Certificate} from 'node:crypto';
import {derCertParts,derIssuerHash}
 from '../server/commercialIntegrity/quoteSignedDer';
import {brFixture,brRootPem,brRootKeyPem,brLeafPem,brNow,brHex}
 from './br-provider-byte-fixtures';
import type {CandidateRemoteExpected} from '../server/commercialIntegrity/quoteRemoteEvidence';
import {bqExpectedFixture} from './bq-remote-fixtures';

// DER fixtures are *real ASN.1 binary structures* and RSA-SHA256 signatures,
// but the issuer/key/identity is generated solely on the CI worker.
const tag=(t:number,content:Buffer):Buffer=>{
 const n=content.length;
 const len=n<128?Buffer.from([n]):n<256?Buffer.from([0x81,n]):
 n<65536?Buffer.from([0x82,n>>8,n&255]):Buffer.from([0x83,n>>16,(n>>8)&255,n&255]);
 return Buffer.concat([Buffer.from([t]),len,content]);
};
const seq=(...parts:Buffer[])=>tag(0x30,Buffer.concat(parts));
const bits=(data:Buffer)=>tag(0x03,Buffer.concat([Buffer.from([0]),data]));
const oct=(data:Buffer)=>tag(0x04,data);
const integer=(value:bigint|number):Buffer=>{
 let n=BigInt(value);
 if(n<0n)throw Error('BS synthetic negative integer');
 const bytes:number[]=[];
 do{bytes.unshift(Number(n&255n));n>>=8n;}while(n>0n);
 if(bytes[0]&0x80)bytes.unshift(0);
 return tag(0x02,Buffer.from(bytes));
};
const oid=(str:string):Buffer=>{
 const v=str.split('.').map(BigInt);
 if(v.length<2||v[0]>2n)throw Error('BS synthetic OID invalid');
 const values=[v[0]*40n+v[1],...v.slice(2)];
 const out:number[]=[];
 for(let n of values){
  const digits=[Number(n&127n)];n>>=7n;
  while(n){digits.unshift(Number(n&127n)|128);n>>=7n;}
  out.push(...digits);
 }
 return tag(0x06,Buffer.from(out));
};
const rsaAlg=()=>seq(oid('1.2.840.113549.1.1.11'),tag(0x05,Buffer.alloc(0)));
const hashAlg=()=>seq(oid('2.16.840.1.101.3.4.2.1'),tag(0x05,Buffer.alloc(0)));
const gtime=(at:Date)=>tag(0x18,Buffer.from(
 at.toISOString().replace(/[-:T]/g,'').replace(/\.\d{3}Z$/,'Z'),'ascii'));
const signed=(tbs:Buffer)=>{
 const sign=createSign('RSA-SHA256');sign.update(tbs);
 return sign.sign(brRootKeyPem);
};
const root=new X509Certificate(brRootPem),leaf=new X509Certificate(brLeafPem);
const rootParts=derCertParts(root.raw),leafParts=derCertParts(leaf.raw);
export type BsFixtureOptions={
 crlNumber?:number;crlRevoked?:boolean;ocspStatus?:'GOOD'|'REVOKED'|'UNKNOWN';
 ocspSerial?:bigint;ocspNonceHex?:string;crlIssuerMismatched?:boolean;
 crlUnsigned?:boolean;ocspUnsigned?:boolean;ocspResponderWrong?:boolean;
 crlUpdatedMinutesAgo?:number;ocspUpdatedMinutesAgo?:number;
 ocspNextMinutes?:number;crlNextMinutes?:number;
 ocspIssuerHashWrong?:boolean
};
export const bsNow=brNow;
export function bsSignedFixture(
 bqExpected:CandidateRemoteExpected=bqExpectedFixture(),
 challengeSha256=brHex('e'),now=bsNow,
 opts:BsFixtureOptions={}){
 const min=bqExpected.minRevocationEpoch;
 const revokedSerial=opts.crlRevoked?leafParts.serial:leafParts.serial+1n;
 const entries=opts.crlRevoked?seq(seq(
  integer(revokedSerial),gtime(new Date(now.getTime()-180000)))):null;
 const issuerName=opts.crlIssuerMismatched?leafParts.subject:rootParts.subject;
 const crlNum=opts.crlNumber??min;
 const extCrlNumber=seq(oid('2.5.29.20'),oct(integer(crlNum)));
 const tbsCrl=seq(integer(1),rsaAlg(),issuerName,
  gtime(new Date(now.getTime()-(opts.crlUpdatedMinutesAgo??3)*60000)),
  gtime(new Date(now.getTime()+(opts.crlNextMinutes??25)*60000)),
  ...(entries?[entries]:[]),tag(0xa0,seq(extCrlNumber)));
 const crlSignature=signed(tbsCrl);
 if(opts.crlUnsigned)crlSignature[0]^=1;
 const crlDer=seq(tbsCrl,rsaAlg(),bits(crlSignature));
 const hashes=derIssuerHash(rootParts.subject,rootParts.subjectPublicKey,'sha256');
 const nameHash=opts.ocspIssuerHashWrong?Buffer.alloc(32,9):hashes.name;
 const id=seq(hashAlg(),oct(nameHash),oct(hashes.key),
  integer(opts.ocspSerial??leafParts.serial));
 const status=opts.ocspStatus==='REVOKED'?
  tag(0xa1,gtime(new Date(now.getTime()-60000))):
  opts.ocspStatus==='UNKNOWN'?tag(0x82,Buffer.alloc(0)):
  tag(0x80,Buffer.alloc(0));
 const single=seq(id,status,
  gtime(new Date(now.getTime()-(opts.ocspUpdatedMinutesAgo??2)*60000)),
  tag(0xa0,gtime(new Date(now.getTime()+(opts.ocspNextMinutes??25)*60000))));
 const nonce=Buffer.from(opts.ocspNonceHex??challengeSha256,'hex');
 const nonceExt=seq(oid('1.3.6.1.5.5.7.48.1.2'),oct(oct(nonce)));
 const byName=tag(0xa1,opts.ocspResponderWrong?leafParts.subject:rootParts.subject);
 const tbsOcsp=seq(byName,gtime(new Date(now.getTime()-60000)),
  seq(single),tag(0xa1,seq(nonceExt)));
 const ocspSignature=signed(tbsOcsp);
 if(opts.ocspUnsigned)ocspSignature[0]^=1;
 const basic=seq(tbsOcsp,rsaAlg(),bits(ocspSignature));
 const respBytes=seq(oid('1.3.6.1.5.5.7.48.1.1'),oct(basic));
 const ocspDer=seq(tag(0x0a,Buffer.from([0])),tag(0xa0,respBytes));
 const material=brFixture(bqExpected,challengeSha256,now,{crlDer,ocspDer});
 return {material,crlDer,ocspDer,issuerCertificatePem:brRootPem,
  issuerRootSha256:material?createHash('sha256').update(root.raw).digest('hex'):''};
}
