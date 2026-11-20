import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {V2_ROLES,witnessSigningBytesV2,checkpointDigestV2,
 assessKeyIdBoundWitnessV2Candidate}
 from '../scripts/phase1dr-offline-keyid-bound-witness-v2.mjs';

const HASH=x=>createHash('sha256').update(x).digest('hex');
const NOW='2026-11-21T00:00:00.000Z';
const PREV={sequence:0,checkpointSha256:'0'.repeat(64)};
const pair=()=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const publicKeyPem=publicKey.export({type:'spki',format:'pem'}).toString();
 const spkiSha256=HASH(publicKey.export({type:'spki',format:'der'}));
 return {privateKey,publicKeyPem,spkiSha256};
};
const legal=pair(),registry=pair(),registrar=pair();
const witnessPins={
 legalWitnessSpkiSha256:legal.spkiSha256,
 registryWitnessSpkiSha256:registry.spkiSha256
};
const baseManifest={
 schemaVersion:2,kind:'UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE_V2',
 repository:REPO,organizationId:'aaditech_corp',
 sourceHeadSha:'a'.repeat(40),mainBaseSha:'b'.repeat(40),
 registrarSpkiSha256:registrar.spkiSha256,
 registryEvidenceSha256:'c'.repeat(64),
 appointmentDigestSha256:'d'.repeat(64),nonce:'e'.repeat(64),
 sequence:1,previousCheckpointSha256:PREV.checkpointSha256,
 issuedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',decision:'HOLD'
};
const comparisonPins={
 organizationId:baseManifest.organizationId,
 sourceHeadSha:baseManifest.sourceHeadSha,
 mainBaseSha:baseManifest.mainBaseSha,
 registrarSpkiSha256:baseManifest.registrarSpkiSha256,
 registryEvidenceSha256:baseManifest.registryEvidenceSha256,
 appointmentDigestSha256:baseManifest.appointmentDigestSha256,
 nonce:baseManifest.nonce
};
const copy=x=>structuredClone(x);
function witness(key,role,manifest,keyId){
 const identity={keyId,spkiSha256:key.spkiSha256};
 return {...identity,publicKeyPem:key.publicKeyPem,
  signature:sign(null,witnessSigningBytesV2(role,manifest,identity),
   key.privateKey).toString('base64')};
}
function packet(manifest=copy(baseManifest),ids=['legal-alpha','registry-beta']){
 const witnesses={
  LEGAL_WITNESS:witness(legal,'LEGAL_WITNESS',manifest,ids[0]),
  REGISTRY_WITNESS:witness(registry,'REGISTRY_WITNESS',manifest,ids[1])
 };
 return {manifest,witnesses,
  claimedCheckpointSha256:checkpointDigestV2(manifest,witnesses)};
}
function assess(observations,other={}){
 return assessKeyIdBoundWitnessV2Candidate({
  observations,comparisonPins,witnessPins,previousCheckpoint:PREV,
  now:NOW,...other
 });
}
const has=(r,code)=>assert.ok(r.anomalyCodes.includes(code),
 'Expected '+code+'; got '+r.anomalyCodes.join(','));
const hold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionOrReviewerStateChangesPossible,false);
 assert.equal(r.independentWitnessKeyRegistryAndLegalMandatesAuthenticated,false);
};

test('1DR signs v2 key ID and SPKI, preserving unconditional HARD HOLD',()=>{
 const a=packet(),r=assess([a,copy(a)]);
 assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,2);
 assert.equal(r.distinctSignedManifestDigestsOnly,1);
 assert.equal(r.signedManifestForkObservedOnly,false);
 assert.equal(r.witnessKeyIdAndSpkiBoundByRoleSignatureV2Only,true);
 assert.equal(r.legacyV1SignaturesNotReinterpretedOrMigrated,true);
 has(r,'DR_DUPLICATE_IS_NOT_INDEPENDENT_PUBLICATION');hold(r);
});
test('1DR changed unsigned key ID with recomputed checkpoint fails signature',()=>{
 const a=packet(),b=copy(a);
 b.witnesses.LEGAL_WITNESS.keyId='legal-forged';
 b.claimedCheckpointSha256=checkpointDigestV2(b.manifest,b.witnesses);
 const r=assess([a,b]);has(r,'DR_V2_SIGNED_IDENTITY_OR_MANIFEST_INVALID');
 has(r,'DR_INCOMPLETE_VALID_OBSERVATION_QUORUM');
 assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,1);
 assert.equal(r.signedWitnessIdentityForkObservedOnly,false);hold(r);
});
test('1DR valid re-signed identity change is a SIGNED identity fork, not manifest fork',()=>{
 const a=packet(),b=packet(copy(baseManifest),['legal-rotated','registry-beta']);
 const r=assess([a,b]);
 assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,2);
 assert.equal(r.signedWitnessIdentityForkObservedOnly,true);
 assert.equal(r.signedManifestForkObservedOnly,false);
 has(r,'DR_SIGNED_WITNESS_IDENTITY_FORK_QUARANTINE');hold(r);
});
test('1DR genuinely different dual-signed manifest is quarantined',()=>{
 const a=packet(),m=copy(baseManifest);
 m.issuedAt='2026-11-20T23:59:59.000Z';
 const r=assess([a,packet(m)]);
 assert.equal(r.signedManifestForkObservedOnly,true);
 assert.equal(r.signedWitnessIdentityForkObservedOnly,false);
 has(r,'DR_DUAL_SIGNED_MANIFEST_FORK_QUARANTINE');hold(r);
});
test('1DR mixed signed identity and signed manifest fork records both',()=>{
 const m=copy(baseManifest);m.issuedAt='2026-11-20T23:59:59.000Z';
 const r=assess([packet(),packet(m,['legal-rotated','registry-beta'])]);
 assert.equal(r.signedManifestForkObservedOnly,true);
 assert.equal(r.signedWitnessIdentityForkObservedOnly,true);hold(r);
});
test('1DR forged claimed digest is never counted as validated observation',()=>{
 const a=packet(),b=packet();
 b.claimedCheckpointSha256='f'.repeat(64);
 const r=assess([a,b]);has(r,'DR_CHECKPOINT_CLAIM_MISMATCH');
 assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,1);hold(r);
});
test('1DR tampered v2 signed manifest with stale signatures fails',()=>{
 const a=packet(),b=copy(a);
 b.manifest.issuedAt='2026-11-20T23:59:59.000Z';
 b.claimedCheckpointSha256=checkpointDigestV2(b.manifest,b.witnesses);
 const r=assess([a,b]);has(r,'DR_V2_SIGNED_IDENTITY_OR_MANIFEST_INVALID');
 assert.equal(r.signedManifestForkObservedOnly,false);hold(r);
});
test('1DR v1 envelopes cannot be silently interpreted as v2',()=>{
 const a=packet(),b=copy(a);
 b.manifest.schemaVersion=1;
 b.manifest.kind='UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE';
 const r=assess([a,b]);has(r,'DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');
 assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,1);hold(r);
});
test('1DR exact-schema extra fields and fake GO fail closed',()=>{
 const a=packet(),b=copy(a);b.manifest.decision='GO';
 let r=assess([a,b]);has(r,'DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');hold(r);
 const c=copy(a);c.witnesses.LEGAL_WITNESS.approved=true;
 r=assess([a,c]);has(r,'DR_WITNESS_KEY_ROLE_OR_PIN_INVALID');hold(r);
 const d=copy(a);d.externalAuthorized=true;
 r=assess([a,d]);has(r,'DR_OBSERVATION_SCHEMA_OR_SIZE_INVALID');hold(r);
});
test('1DR missing, malformed and stale explicit time fail closed',()=>{
 const a=packet();
 for(const bad of [null,'2026-11-21','2026-11-22T00:00:00.000Z']){
  const r=assess([a,a],{now:bad});
  if(bad===null||bad==='2026-11-21')has(r,'DR_EXPLICIT_CLOCK_REQUIRED');
  else has(r,'DR_EXPLICIT_CLOCK_OR_EXPIRY_INVALID');
  assert.equal(r.verifiedV2DualSignedPacketsMathematicallyOnly,0);hold(r);
 }
});
test('1DR future issue time and overlong expiry invalidate observations',()=>{
 const a=packet(),future=copy(baseManifest);
 future.issuedAt='2026-11-21T00:06:00.000Z';
 future.expiresAt='2026-11-21T00:10:00.000Z';
 let r=assess([a,packet(future)]);has(r,'DR_EXPLICIT_CLOCK_OR_EXPIRY_INVALID');hold(r);
 const long=copy(baseManifest);long.expiresAt='2026-11-21T00:16:00.000Z';
 r=assess([a,packet(long)]);has(r,'DR_EXPLICIT_CLOCK_OR_EXPIRY_INVALID');hold(r);
});
test('1DR swapped signers, duplicate role key IDs and SPKI pin collisions reject',()=>{
 const a=packet(),b=copy(a);
 [b.witnesses.LEGAL_WITNESS,b.witnesses.REGISTRY_WITNESS]=
 [b.witnesses.REGISTRY_WITNESS,b.witnesses.LEGAL_WITNESS];
 b.claimedCheckpointSha256=checkpointDigestV2(b.manifest,b.witnesses);
 let r=assess([a,b]);has(r,'DR_WITNESS_KEY_ROLE_OR_PIN_INVALID');hold(r);
 const c=packet(copy(baseManifest),['same-keyid','same-keyid']);
 r=assess([a,c]);has(r,'DR_WITNESS_KEY_ROLE_OR_PIN_INVALID');hold(r);
 r=assess([a,a],{witnessPins:{
  ...witnessPins,registryWitnessSpkiSha256:legal.spkiSha256
 }});has(r,'DR_TWO_DISTINCT_WITNESS_PINS_REQUIRED');hold(r);
});
test('1DR wrong SPKI fingerprint and invalid signature reject',()=>{
 const a=packet(),b=copy(a);b.witnesses.LEGAL_WITNESS.spkiSha256='f'.repeat(64);
 b.claimedCheckpointSha256=checkpointDigestV2(b.manifest,b.witnesses);
 let r=assess([a,b]);has(r,'DR_WITNESS_KEY_ROLE_OR_PIN_INVALID');hold(r);
 const c=copy(a);c.witnesses.LEGAL_WITNESS.signature='A'.repeat(86)+'==';
 c.claimedCheckpointSha256=checkpointDigestV2(c.manifest,c.witnesses);
 r=assess([a,c]);has(r,'DR_V2_SIGNED_IDENTITY_OR_MANIFEST_INVALID');hold(r);
});
test('1DR source, organization, nonce or independent pin drift reject',()=>{
 const a=packet();
 for(const k of ['sourceHeadSha','organizationId','nonce']){
  const m=copy(baseManifest);m[k]=k==='sourceHeadSha'?'9'.repeat(40):
   k==='nonce'?'9'.repeat(64):'other_corp';
  const r=assess([a,packet(m)]);
  has(r,'DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');hold(r);
 }
 const r=assess([a,a],{comparisonPins:{
  ...comparisonPins,sourceHeadSha:'9'.repeat(40)
 }});has(r,'DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');hold(r);
});
test('1DR previous-checkpoint rollback, genesis forgery and sequence overflow fail',()=>{
 const a=packet();
 let r=assess([a,a],{previousCheckpoint:{
  sequence:0,checkpointSha256:'f'.repeat(64)
 }});has(r,'DR_PREVIOUS_CHECKPOINT_INVALID');hold(r);
 const m=copy(baseManifest);m.sequence=2;
 r=assess([a,packet(m)]);has(r,'DR_V2_SIGNED_SCOPE_OR_SEQUENCE_INVALID');hold(r);
 r=assess([a,a],{previousCheckpoint:{
  sequence:Number.MAX_SAFE_INTEGER,checkpointSha256:'f'.repeat(64)
 }});has(r,'DR_PREVIOUS_CHECKPOINT_INVALID');hold(r);
});
test('1DR malformed observations, oversized and missing quorum fail',()=>{
 const a=packet();
 for(const bad of [null,[],[a],[a,a,a,a,a,a,a,a,a]]){
  const r=assess(bad);has(r,'DR_TWO_TO_EIGHT_OBSERVATIONS_REQUIRED');hold(r);
 }
 const b=copy(a);b.untrustedPadding='z'.repeat(25000);
 const r=assess([a,b]);has(r,'DR_OBSERVATION_SCHEMA_OR_SIZE_INVALID');hold(r);
});
test('1DR invalid identity signing parameters throw and never sign v1',()=>{
 const a=packet(),identity={
  keyId:'legal-alpha',spkiSha256:legal.spkiSha256
 };
 assert.throws(()=>witnessSigningBytesV2('UNKNOWN_ROLE',a.manifest,identity));
 assert.throws(()=>witnessSigningBytesV2('LEGAL_WITNESS',{
  ...a.manifest,schemaVersion:1
 },identity));
 assert.throws(()=>witnessSigningBytesV2('LEGAL_WITNESS',
  a.manifest,{...identity,algorithm:'rsa'}));
});
test('1DR output redacts raw nonce, keys, IDs, signatures and is immutable HOLD',()=>{
 const a=packet(),r=assess([a,packet()]);
 const output=JSON.stringify(r);
 for(const sensitive of [
  baseManifest.nonce,legal.publicKeyPem,registry.publicKeyPem,
  a.witnesses.LEGAL_WITNESS.signature,
  a.witnesses.REGISTRY_WITNESS.signature,
  'legal-alpha','registry-beta'
 ])assert.equal(output.includes(sensitive),false);
 assert.equal(r.rawNoncePemSignaturesAndKeyIdExcludedFromOutput,true);
 assert.equal(r.originalInMemoryOfficerGithubSessionReverified,false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);hold(r);
});
test('1DR signer algorithm is Ed25519 and candidate contract is read-only',()=>{
 const a=packet();assert.deepEqual(V2_ROLES,['LEGAL_WITNESS','REGISTRY_WITNESS']);
 assert.ok(a.witnesses.LEGAL_WITNESS.signature.endsWith('=='));
 const r=assess([a,a]);hold(r);
 assert.equal(r.previousCheckpointAndClockExternallyAuthenticated,false);
 assert.equal(r.externalWormCasRevocationMcaCcaProviderOrStagingVerified,false);
});
