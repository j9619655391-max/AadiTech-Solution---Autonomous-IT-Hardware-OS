import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {GR_TABLES,grMakeManifest,grManifestBytes,grVerifyManifest} from '../scripts/lib/grAuthorityRecoveryManifest';
test('1GR recovery manifest binds seven ordered table digests, sequence, predecessor, exact commit and pinned signer',()=>{
 const pair=generateKeyPairSync('ed25519');
 const tables=GR_TABLES.map((table,i)=>({table,rowCount:i,sha256:createHash('sha256').update(table).digest('hex')}));
 const anchor={sequence:2,previousSha256:'a'.repeat(64),sourceCommit:'b'.repeat(40),observedAtMs:1700000000000};
 const manifest=grMakeManifest(tables,anchor),signature=sign(null,grManifestBytes(manifest),pair.privateKey).toString('base64url');
 const expected={...anchor,publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}).toString(),spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex')};
 assert.equal(grVerifyManifest(manifest,signature,expected,tables).status,'MATCH');
 for(const actual of [tables.slice(1),[...tables].reverse(),tables.map((t,i)=>i===0?{...t,rowCount:1}:t),tables.map((t,i)=>i===0?{...t,sha256:'0'.repeat(64)}:t)])
  assert.throws(()=>grVerifyManifest(manifest,signature,expected,actual),/GR_RECOVERY_HOLD/);
 for(const patch of [{sequence:3},{previousSha256:'c'.repeat(64)},{sourceCommit:'c'.repeat(40)},{spkiSha256:'0'.repeat(64)}])
  assert.throws(()=>grVerifyManifest(manifest,signature,{...expected,...patch},tables),/GR_RECOVERY_HOLD/);
 assert.throws(()=>grVerifyManifest({...manifest,observedAtMs:anchor.observedAtMs+1},signature,expected,tables),/GR_RECOVERY_HOLD/);
 assert.throws(()=>grVerifyManifest(manifest,signature+'=',expected,tables),/GR_RECOVERY_HOLD/);
 assert.throws(()=>grManifestBytes({...manifest,extra:true}),/GR_RECOVERY_HOLD/);
});
