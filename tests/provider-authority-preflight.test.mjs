import test from 'node:test';
import assert from 'node:assert/strict';
import {reviewPhase1ApDigestInventory,AUTHORITY_DIGEST_FIELDS,
 INDEPENDENT_REVIEW_DIGEST_FIELDS,PROVIDER_CODE,REQUESTED_SCOPE}
 from '../scripts/lib/providerAuthorityPreflight.mjs';
function sample(){
 let n=1;
 const digest=()=>{const v=n;n++;return v.toString(16).padStart(64,'0');};
 return {schemaVersion:1,providerCode:PROVIDER_CODE,requestedScope:REQUESTED_SCOPE,
  artifactDigests:Object.fromEntries(AUTHORITY_DIGEST_FIELDS.map(k=>[k,digest()])),
  reviewDigests:Object.fromEntries(INDEPENDENT_REVIEW_DIGEST_FIELDS.map(k=>[k,digest()]))};
}
test('absence of provider agreement keeps all external authority and stock denied',()=>{
 const r=reviewPhase1ApDigestInventory();
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.packetInspected,false);
 for(const k of ['sandboxServiceAuthorized','authorizedCredentialsBound',
  'externalProviderIdentityVerified','legallyVerifiedMcaAndSignatory',
  'productionReleaseAuthorized','stockPostingEnabled','officialGrnVerified'])
  assert.equal(r[k],false);
 assert.equal(r.availableToSell,null);
 assert.ok(r.blockers.length>=6);
});
test('even complete synthetic fingerprints never grant external authority',()=>{
 const p=sample(),r=reviewPhase1ApDigestInventory(p);
 assert.equal(r.declaredDigestCount,16);
 assert.equal(r.packetInspected,true);
 assert.match(r.inventoryFingerprintSha256,/^[a-f0-9]{64}$/);
 for(const k of ['sandboxServiceAuthorized','independentlyAuthenticatedRcaiCaChain',
  'authenticatedLiveCrlOcsp','officialGrnVerified','productionReleaseAuthorized'])
  assert.equal(r[k],false);
 assert.equal(reviewPhase1ApDigestInventory(p).inventoryFingerprintSha256,
  r.inventoryFingerprintSha256);
 p.artifactDigests.signedAgreementSha256='b'.repeat(64);
 assert.notEqual(reviewPhase1ApDigestInventory(p).inventoryFingerprintSha256,
  r.inventoryFingerprintSha256);
});
test('reject credentials, activation switches, raw documents and unauthenticated provider promotion',()=>{
 const cases=[
  {...sample(),apiKey:'secret'},
  {...sample(),productionReady:true},
  {...sample(),secretManagerRef:'vault://private'},
  {...sample(),artifactDigests:{...sample().artifactDigests,password:'secret'}},
  {...sample(),reviewDigests:{...sample().reviewDigests,authorized:true}},
  {...sample(),providerCode:'EMUDHRA_PRODUCTION'},
  {...sample(),requestedScope:'STOCK_POSTING'},
  {...sample(),schemaVersion:2},
  {...sample(),artifactDigests:{...sample().artifactDigests,signedAgreementSha256:'0'.repeat(64)}},
  {...sample(),artifactDigests:{...sample().artifactDigests,signedAgreementSha256:'A'.repeat(64)}},
  {...sample(),artifactDigests:{...sample().artifactDigests,signedAgreementSha256:'raw document text'}}
 ];
 for(const v of cases)assert.throws(()=>reviewPhase1ApDigestInventory(v));
});
test('missing and duplicate SHA, arrays and untrusted object types are denied',()=>{
 const p=sample();delete p.artifactDigests.signedAgreementSha256;
 assert.throws(()=>reviewPhase1ApDigestInventory(p));
 const q=sample();
 q.reviewDigests.legalReviewSha256=q.artifactDigests.signedAgreementSha256;
 assert.throws(()=>reviewPhase1ApDigestInventory(q),/Distinct/);
 for(const v of [[],42,'text',Object.create(null)])
  assert.throws(()=>reviewPhase1ApDigestInventory(v));
});
