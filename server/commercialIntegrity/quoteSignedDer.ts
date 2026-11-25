import {createHash} from 'node:crypto';

// Small strict bounded DER *subset* for offline issuer-signed candidate CRL/OCSP.
// Reject unknown tags/indefinite/nonminimal encodings; never a general PKIX
// path validator, live responder, or evidence of external provider authority.
export type DerNode={tag:number,start:number,content:number,end:number,bytes:Buffer};
export function derRead(bytes:Buffer,start=0,limit=bytes.length):DerNode{
 if(!Buffer.isBuffer(bytes)||bytes.length>131072||start<0||start>=limit||
    limit>bytes.length||limit-start<2)throw Error('BS DER truncated');
 const tag=bytes[start];
 if((tag&31)===31)throw Error('BS DER high-tag unsupported');
 let length=bytes[start+1],offset=start+2;
 if(length===0x80)throw Error('BS DER indefinite forbidden');
 if(length>127){
  const n=length&127;
  if(n<1||n>3||offset+n>limit||bytes[offset]===0)
   throw Error('BS DER nonminimal length');
  length=0;
  for(let i=0;i<n;i++)length=length*256+bytes[offset++];
  if(length<128)throw Error('BS DER nonminimal length');
 }
 if(length>65536||offset+length>limit)throw Error('BS DER length overflow');
 return {tag,start,content:offset,end:offset+length,bytes};
}
export function derTop(bytes:Buffer,tag:number):DerNode{
 const top=derRead(bytes);
 if(top.tag!==tag||top.end!==bytes.length)throw Error('BS DER top-level trailing bytes');
 return top;
}
export function derChildren(n:DerNode,max=32):DerNode[]{
 const r:DerNode[]=[];
 let offset=n.content;
 while(offset<n.end){
  if(r.length>=max)throw Error('BS DER excessive children');
  const next=derRead(n.bytes,offset,n.end);
  r.push(next);offset=next.end;
 }
 if(offset!==n.end)throw Error('BS DER children overflow');
 return r;
}
export function derExact(n:DerNode,tag:number){
 if(n.tag!==tag)throw Error('BS DER unexpected tag');
 return n;
}
export function derRaw(n:DerNode):Buffer{
 return n.bytes.subarray(n.start,n.end);
}
export function derValue(n:DerNode):Buffer{
 return n.bytes.subarray(n.content,n.end);
}
export function derInteger(n:DerNode):bigint{
 derExact(n,0x02);
 const b=derValue(n);
 if(!b.length||b.length>32||(b[0]&128)!==0||
    (b.length>1&&b[0]===0&&(b[1]&128)===0))
  throw Error('BS DER integer nonminimal/negative');
 let value=0n;
 for(const c of b)value=(value<<8n)+BigInt(c);
 return value;
}
export function derNumber(n:DerNode,min=0,max=2147483647):number{
 const v=derInteger(n);
 if(v<BigInt(min)||v>BigInt(max))throw Error('BS DER integer outside limit');
 return Number(v);
}
export function derOid(n:DerNode):string{
 derExact(n,0x06);
 const bytes=derValue(n);
 if(!bytes.length||bytes.length>32)throw Error('BS OID length');
 const fields:bigint[]=[];
 let value=0n,octets=0;
 for(const c of bytes){
  if(octets===0&&c===0x80)throw Error('BS OID nonminimal');
  value=(value<<7n)|BigInt(c&127);octets++;
  if(octets>9)throw Error('BS OID too large');
  if(!(c&128)){fields.push(value);value=0n;octets=0;}
 }
 if(octets||!fields.length)throw Error('BS OID truncated');
 const head=fields.shift()!;
 const first=head<40n?0n:head<80n?1n:2n;
 return [first,head-first*40n,...fields].join('.');
}
export function derBits(n:DerNode):Buffer{
 derExact(n,0x03);
 const b=derValue(n);
 if(b.length<2||b[0]!==0)throw Error('BS non-byte-aligned BIT STRING');
 return b.subarray(1);
}
export function derTime(n:DerNode):number{
 if(n.tag!==0x17&&n.tag!==0x18)throw Error('BS ASN1 time tag');
 const value=derValue(n).toString('ascii');
 let y=0,m=0,d=0,h=0,mi=0,s=0;
 if(n.tag===0x18){
  if(!/^\d{14}Z$/.test(value))throw Error('BS GeneralizedTime requires seconds Z');
  y=Number(value.slice(0,4));m=Number(value.slice(4,6));
  d=Number(value.slice(6,8));h=Number(value.slice(8,10));
  mi=Number(value.slice(10,12));s=Number(value.slice(12,14));
 }else{
  if(!/^\d{12}Z$/.test(value))throw Error('BS UTCTime requires seconds Z');
  y=Number(value.slice(0,2));y=y>=50?1900+y:2000+y;
  m=Number(value.slice(2,4));d=Number(value.slice(4,6));
  h=Number(value.slice(6,8));mi=Number(value.slice(8,10));s=Number(value.slice(10,12));
 }
 const ms=Date.UTC(y,m-1,d,h,mi,s);
 const t=new Date(ms);
 if(!Number.isFinite(ms)||t.getUTCFullYear()!==y||
    t.getUTCMonth()!==m-1||t.getUTCDate()!==d||
    t.getUTCHours()!==h||t.getUTCMinutes()!==mi||t.getUTCSeconds()!==s)
  throw Error('BS invalid ASN1 date');
 return ms;
}
export function derAlg(n:DerNode):string{
 const children=derChildren(derExact(n,0x30),2);
 if(children.length<1||children.length>2)throw Error('BS signature algorithm');
 const oid=derOid(children[0]);
 if(children[1]&&(children[1].tag!==0x05||derValue(children[1]).length!==0))
  throw Error('BS unsupported algorithm parameters');
 return oid;
}
export function derExtensions(n:DerNode):Map<string,Buffer>{
 const entries=derChildren(derExact(n,0x30),16),out=new Map<string,Buffer>();
 for(const entry of entries){
  const cells=derChildren(derExact(entry,0x30),3);
  if(cells.length<2||cells.length>3)throw Error('BS invalid extension');
  const oid=derOid(cells[0]);
  if(out.has(oid))throw Error('BS duplicate extension');
  let i=1;
  if(cells[i].tag===0x01){
   const b=derValue(cells[i++]);
   if(b.length!==1||b[0]!==0xff)throw Error('BS noncanonical/unsupported critical boolean');
  }
  if(i!==cells.length-1||cells[i].tag!==0x04)throw Error('BS extension missing OCTET STRING');
  out.set(oid,derValue(cells[i]));
 }
 return out;
}
export function derCertParts(certRaw:Buffer){
 const outer=derChildren(derTop(certRaw,0x30),3);
 if(outer.length!==3)throw Error('BS certificate envelope');
 const tbs=derChildren(derExact(outer[0],0x30),12);
 let i=0;if(tbs[i]?.tag===0xa0)i++;
 const serial=derInteger(tbs[i++]);
 i++; // Certificate signatureAlgorithm
 const issuer=tbs[i++];i++; // validity
 const subject=tbs[i++];
 const spki=derChildren(derExact(tbs[i++],0x30),2);
 if(spki.length!==2)throw Error('BS certificate SPKI malformed');
 const key=derBits(spki[1]);
 return {serial,issuer:derRaw(issuer),subject:derRaw(subject),
  subjectPublicKey:key};
}
export function derIssuerHash(name:Buffer,key:Buffer,algorithm:'sha1'|'sha256'){
 return {name:createHash(algorithm).update(name).digest(),
  key:createHash(algorithm).update(key).digest()};
}
