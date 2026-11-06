import {randomBytes,createCipheriv,createDecipheriv,createHmac,timingSafeEqual} from 'node:crypto';
const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buf:Buffer):string{
 let bits=0,value=0,out='';
 for(const b of buf){value=(value<<8)|b;bits+=8;while(bits>=5){out+=alphabet[(value>>>(bits-5))&31];bits-=5;}}
 if(bits>0)out+=alphabet[(value<<(5-bits))&31];
 return out;
}
export function base32Decode(text:string):Buffer{
 if(!/^[A-Z2-7]{16,128}$/.test(text))throw Error('Invalid TOTP secret');
 let bits=0,value=0,out:number[]=[];
 for(const c of text){value=(value<<5)|alphabet.indexOf(c);bits+=5;if(bits>=8){out.push((value>>>(bits-8))&255);bits-=8;}}
 return Buffer.from(out);
}
export function encryptionKey():Buffer{
 const raw=process.env.MFA_ENCRYPTION_KEY??'';
 if(!/^[a-fA-F0-9]{64}$/.test(raw))throw Error('MFA_ENCRYPTION_KEY must be 32 random bytes in hex');
 return Buffer.from(raw,'hex');
}
export function encryptSecret(secret:string):string{
 const key=encryptionKey(),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
 const ciphertext=Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]);
 return [iv,cipher.getAuthTag(),ciphertext].map(x=>x.toString('base64url')).join('.');
}
export function decryptSecret(value:string):string{
 const [iv,tag,encrypted]=value.split('.');
 if(!iv||!tag||!encrypted)throw Error('Invalid encrypted secret');
 const decipher=createDecipheriv('aes-256-gcm',encryptionKey(),Buffer.from(iv,'base64url'));
 decipher.setAuthTag(Buffer.from(tag,'base64url'));
 return Buffer.concat([decipher.update(Buffer.from(encrypted,'base64url')),decipher.final()]).toString('utf8');
}
export function generateTotpSecret():string{return base32Encode(randomBytes(20));}
export function totpAt(secret:string,counter:number):string{
 if(!Number.isSafeInteger(counter)||counter<0)throw Error('Invalid TOTP counter');
 const input=Buffer.alloc(8);input.writeBigUInt64BE(BigInt(counter));
 const digest=createHmac('sha1',base32Decode(secret)).update(input).digest();
 const offset=digest[digest.length-1]&15;
 const truncated=(digest.readUInt32BE(offset)&0x7fffffff)%1000000;
 return String(truncated).padStart(6,'0');
}
export function matchTotp(secret:string,code:string,minimumCounter=-1,now=Date.now()):number|null{
 if(!/^\d{6}$/.test(code))return null;
 const current=Math.floor(now/30000);
 for(let i=-1;i<=1;i++){
  const count=current+i;
  if(count<=minimumCounter||count<0)continue;
  const expected=Buffer.from(totpAt(secret,count));
  if(timingSafeEqual(expected,Buffer.from(code)))return count;
 }
 return null;
}
export function newRecoveryCodes():string[]{
 return Array.from({length:8},()=>randomBytes(10).toString('hex').toUpperCase());
}
