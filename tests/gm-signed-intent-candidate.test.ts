import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {GM_AUDIENCE,gmCanonicalIntent,gmVerifyIntent,gmIssueVerifiedIntent,gmValidatePinTransition,type GmEnvelope,type GmPinnedKey} from '../scripts/lib/gmSignedIntentCandidate';
const now=1700000000000;
const pair=generateKeyPairSync('ed25519');
const pin:GmPinnedKey={keyId:'ci-gm-1',publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}).toString(),
 spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex'),
 notBeforeMs:now-1000,notAfterMs:now+600000,revoked:false,operations:['customers','leads','products','quote-binding']};
const customer:GmEnvelope={version:1,audience:GM_AUDIENCE,keyId:pin.keyId,operation:'customers',
 actorId:randomUUID(),sessionHash:'a'.repeat(64),intentHash:'b'.repeat(64),entityId:randomUUID(),auditId:randomUUID(),
 issuedAtMs:now-100,expiresAtMs:now+100000,
 payload:{name:'Synthetic',gstin:null,contactPerson:'CI',email:'ci@example.invalid',phone:'0000000000',city:'Mumbai',state:'Maharashtra'}};
function signature(e:unknown){return sign(null,gmCanonicalIntent(e).bytes,pair.privateKey).toString('base64url');}
test('1GM signed canonical intent is order independent and byte-bound to operation, actor, session, payload, expiry and IDs',()=>{
 const sig=signature(customer);
 const reversed=Object.fromEntries(Object.entries(customer).reverse());
 reversed.payload=Object.fromEntries(Object.entries(customer.payload).reverse());
 assert.deepEqual(gmVerifyIntent(reversed,sig,[pin],now).payload,gmCanonicalIntent(customer).envelope.payload);
 for(const drift of [{actorId:randomUUID()},{entityId:randomUUID()},{auditId:randomUUID()},{sessionHash:'c'.repeat(64)},
  {intentHash:'d'.repeat(64)},{expiresAtMs:now+200000},{payload:{...customer.payload,name:'Different'}},
  {keyId:'unknown'},{audience:'other'},{operation:'leads'},{extra:true}])
  assert.throws(()=>gmVerifyIntent({...customer,...drift},sig,[pin],now),/GM_INTENT_REJECTED/);
 const quote={...customer,operation:'quote-binding',auditId:null,payload:{requestKey:randomUUID(),requestHash:'c'.repeat(64)}};
 assert.equal(gmVerifyIntent(quote,signature(quote),[pin],now).operation,'quote-binding');
 assert.throws(()=>gmVerifyIntent(quote,sig,[pin],now),/GM_INTENT_REJECTED/);
});
test('1GM rejects wrong key, duplicate pins, revoked/out-of-scope keys, expiry, future issue, malformed signatures and uncanonical payload',()=>{
 const sig=signature(customer);
 const wrong=generateKeyPairSync('ed25519');
 for(const pins of [[],[pin,pin],[{...pin,revoked:true}],[{...pin,operations:['products'] as const}],
  [{...pin,spkiSha256:'0'.repeat(64)}],[{...pin,publicKeyPem:wrong.publicKey.export({format:'pem',type:'spki'}).toString()}],
  [{...pin,notBeforeMs:now}],[{...pin,notAfterMs:now+1}]])
  assert.throws(()=>gmVerifyIntent(customer,sig,pins,now),/GM_INTENT_REJECTED/);
 for(const time of [customer.expiresAtMs,customer.issuedAtMs-1,NaN])
  assert.throws(()=>gmVerifyIntent(customer,sig,[pin],time),/GM_INTENT_REJECTED/);
 for(const bad of [sig+'=',sig.slice(1),'!'.repeat(86),'A'.repeat(86)])
  assert.throws(()=>gmVerifyIntent(customer,bad,[pin],now),/GM_INTENT_REJECTED/);
 for(const payload of [{...customer.payload,name:' Synthetic '},{...customer.payload,gstin:'invalid'},{...customer.payload,email:'bad'},
  {...customer.payload,extra:true},Object.fromEntries(Object.entries(customer.payload).filter(([k])=>k!=='gstin'))])
  assert.throws(()=>gmCanonicalIntent({...customer,payload}),/GM_INTENT_REJECTED/);
 assert.throws(()=>gmCanonicalIntent({...customer,expiresAtMs:customer.issuedAtMs+300001}),/GM_INTENT_REJECTED/);
});
test('1GM issuer entry point refuses non-CI and invalid signature before executing SQL',async()=>{
 let calls=0;
 const db={execute:async()=>{calls++;throw Error('unexpected');}} as unknown as Parameters<typeof gmIssueVerifiedIntent>[0];
 const original={NODE_ENV:process.env.NODE_ENV,CRM_TEST_DB:process.env.CRM_TEST_DB,DB_NAME:process.env.DB_NAME,DB_SSL:process.env.DB_SSL};
 try{
  process.env.NODE_ENV='production';
  await assert.rejects(gmIssueVerifiedIntent(db,customer,signature(customer),[pin]),/CI-only/);
  Object.assign(process.env,{NODE_ENV:'test',CRM_TEST_DB:'1',DB_NAME:'aaditech_ci',DB_SSL:'false'});
  const live={...customer,issuedAtMs:Date.now()-100,expiresAtMs:Date.now()+100000};
  const livePin={...pin,notBeforeMs:live.issuedAtMs-1000,notAfterMs:live.expiresAtMs+1000};
  await assert.rejects(gmIssueVerifiedIntent(db,live,'A'.repeat(86),[livePin]),/GM_INTENT_REJECTED/);
  assert.equal(calls,0);
 }finally{for(const [k,v] of Object.entries(original)){if(v===undefined)delete process.env[k];else process.env[k]=v;}}
});

test('1GN pin rollover preserves historical identity, scope, validity and irreversible revocation',()=>{
 const nextPair=generateKeyPairSync('ed25519');
 const next:GmPinnedKey={...pin,keyId:'ci-gm-2',publicKeyPem:nextPair.publicKey.export({format:'pem',type:'spki'}).toString(),
 spkiSha256:createHash('sha256').update(nextPair.publicKey.export({format:'der',type:'spki'})).digest('hex'),
 notBeforeMs:now,notAfterMs:now+900000};
 const revoked={...pin,revoked:true};
 assert.doesNotThrow(()=>gmValidatePinTransition([pin],[revoked,next],now));
 assert.throws(()=>gmVerifyIntent(customer,signature(customer),[revoked,next],now),/GM_INTENT_REJECTED/);
 for(const candidate of [[next],[pin,{...next,notBeforeMs:now-1}],[{...pin,notAfterMs:pin.notAfterMs+1},next],
  [{...pin,operations:['products'] as const},next],[pin,{...next,spkiSha256:pin.spkiSha256,publicKeyPem:pin.publicKeyPem}],
  [pin,{...next,keyId:pin.keyId}],[pin,{...next,spkiSha256:'0'.repeat(64)}]])
  assert.throws(()=>gmValidatePinTransition([pin],candidate,now),/GM_INTENT_REJECTED/);
 assert.throws(()=>gmValidatePinTransition([revoked],[pin,next],now),/GM_INTENT_REJECTED/);
});
