import test from 'node:test';
import assert from 'node:assert/strict';
import {base32Encode,base32Decode,totpAt,matchTotp,encryptSecret,decryptSecret,generateTotpSecret,newRecoveryCodes} from '../server/auth/totp';

test('RFC 6238 TOTP SHA1 vector and tolerance',()=>{
 const secret=base32Encode(Buffer.from('12345678901234567890'));
 assert.equal(totpAt(secret,59/30|0), '287082'); // 8 digit RFC vector 94287082 truncated to 6
 const code=totpAt(secret,1234567);
 assert.equal(matchTotp(secret,code,-1,1234567*30000),1234567);
 assert.equal(matchTotp(secret,code,1234567,1234567*30000),null);
 assert.equal(matchTotp(secret,'000',-1,1234567*30000),null);
 assert.deepEqual(base32Decode(secret),Buffer.from('12345678901234567890'));
});
test('AES-GCM authentication roundtrip and failure on tampering',()=>{
 const before=process.env.MFA_ENCRYPTION_KEY;
 try{
  process.env.MFA_ENCRYPTION_KEY='44'.repeat(32);
  const secret=generateTotpSecret();
  const encrypted=encryptSecret(secret);
  assert.notEqual(encrypted,secret);
  assert.equal(decryptSecret(encrypted),secret);
  const parts=encrypted.split('.');
  parts[2]='A'+parts[2].slice(1);
  assert.throws(()=>decryptSecret(parts.join('.')));
  delete process.env.MFA_ENCRYPTION_KEY;
  assert.throws(()=>encryptSecret(secret),/MFA_ENCRYPTION_KEY/);
 }finally{
  if(before===undefined)delete process.env.MFA_ENCRYPTION_KEY;
  else process.env.MFA_ENCRYPTION_KEY=before;
 }
});
test('recovery codes are unique random 20-hex-character strings',()=>{
 const codes=newRecoveryCodes();
 assert.equal(codes.length,8);
 assert.equal(new Set(codes).size,8);
 assert.ok(codes.every(code=>/^[A-F0-9]{20}$/.test(code)));
});
