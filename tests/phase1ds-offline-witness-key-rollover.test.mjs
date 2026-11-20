import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {ROTATION_DOMAIN,ROTATION_STEPS,rotationSigningBytes,
 rotationDigest,assessCrossSignedWitnessRolloverCandidate}
 from '../scripts/phase1ds-offline-witness-key-rollover.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex');
const pair=()=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {privateKey,pem:publicKey.export({type:'spki',format:'pem'}).toString(),
  spkiSha256:hash(publicKey.export({type:'spki',format:'der'}))};
};
const keys={
 LEGAL_WITNESS:{previous:pair(),next:pair()},
 REGISTRY_WITNESS:{previous:pair(),next:pair()}
};
const alternative=pair();
const roles=['LEGAL_WITNESS','REGISTRY_WITNESS'];
const now='2026-11-21T00:00:00.000Z';
const expected={
 organizationId:'aaditech_corp',sourceHeadSha:'a'.repeat(40),
 mainBaseSha:'b'.repeat(40),previousSequence:0,
 previousCheckpointSha256:'0'.repeat(64),
 nextCandidateCheckpointSha256:'c'.repeat(64)
};
const id=(role,step)=>role==='LEGAL_WITNESS'?
 (step==='previous'?'legal-old':'legal-new'):
 (step==='previous'?'registry-old':'registry-new');
const previousIdentityPins=Object.fromEntries(roles.map(role=>[role,{
 keyId:id(role,'previous'),spkiSha256:keys[role].previous.spkiSha256
}]));
const manifest={
 schemaVersion:1,kind:'UNTRUSTED_WITNESS_ROTATION_CANDIDATE',
 repository:REPO,organizationId:expected.organizationId,
 sourceHeadSha:expected.sourceHeadSha,mainBaseSha:expected.mainBaseSha,
 previousSequence:0,nextSequence:1,
 previousCheckpointSha256:expected.previousCheckpointSha256,
 nextCandidateCheckpointSha256:expected.nextCandidateCheckpointSha256,
 rotationNonce:'d'.repeat(64),reason:'PLANNED_ROLLOVER',
 issuedAt:now,expiresAt:'2026-11-21T00:10:00.000Z',decision:'HOLD'
};
const clone=x=>structuredClone(x);
function packet({
 m=clone(manifest),legalNext=keys.LEGAL_WITNESS.next,
 legalNextId='legal-new',registryNext=keys.REGISTRY_WITNESS.next
}={}){
 const keyset={
  LEGAL_WITNESS:{previous:keys.LEGAL_WITNESS.previous,next:legalNext},
  REGISTRY_WITNESS:{previous:keys.REGISTRY_WITNESS.previous,next:registryNext}
 };
 const identities=Object.fromEntries(roles.map(role=>[role,
  Object.fromEntries(ROTATION_STEPS.map(step=>[step,{
   keyId:step==='next'&&role==='LEGAL_WITNESS'?legalNextId:id(role,step),
   spkiSha256:keyset[role][step].spkiSha256
  }]))
 ]));
 const attestations=Object.fromEntries(roles.map(role=>[role,
  Object.fromEntries(ROTATION_STEPS.map(step=>[step,{
   publicKeyPem:keyset[role][step].pem,
   signature:sign(null,rotationSigningBytes(role,step,m,identities),
    keyset[role][step].privateKey).toString('base64')
  }]))
 ]));
 return {manifest:m,identities,attestations,
  claimedTransitionSha256:rotationDigest(m,identities,attestations)};
}
function assess(candidates,other={}){
 return assessCrossSignedWitnessRolloverCandidate({
  candidates,expected,previousIdentityPins,now,...other
 });
}
const has=(r,code)=>assert.ok(r.anomalyCodes.includes(code),
 'Expected '+code+' got '+r.anomalyCodes.join(','));
function held(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.oldAndNewKeysDoNotBecomeExternallyAuthorized,true);
 assert.equal(r.noKeyEnrollmentOrProductionMutation,true);
}
test('1DS four cryptographic step signatures can be verified only as a held candidate',()=>{
 const a=packet(),r=assess([a,clone(a)]);
 assert.equal(r.mathematicallyVerifiedFourSignatureCandidatesOnly,2);
 assert.equal(r.distinctCrossSignedTransitionDigestsOnly,1);
 assert.equal(r.candidateTransitionForkObservedOnly,false);
 has(r,'DS_DUPLICATE_NOT_INDEPENDENT_PUBLICATION');held(r);
});
test('1DS changed unsigned next key ID with recomputed digest fails signed transition',()=>{
 const a=packet(),b=clone(a);
 b.identities.LEGAL_WITNESS.next.keyId='forged-new';
 b.claimedTransitionSha256=rotationDigest(b.manifest,b.identities,b.attestations);
 const r=assess([a,b]);has(r,'DS_FOUR_ROLE_STEP_SIGNATURES_INVALID');
 has(r,'DS_INCOMPLETE_VALID_CANDIDATE_SET');
 assert.equal(r.mathematicallyVerifiedFourSignatureCandidatesOnly,1);held(r);
});
test('1DS four re-signed key-identity forks quarantine',()=>{
 const a=packet(),b=packet({legalNext:alternative,legalNextId:'legal-fork'});
 const r=assess([a,b]);
 assert.equal(r.mathematicallyVerifiedFourSignatureCandidatesOnly,2);
 assert.equal(r.candidateTransitionForkObservedOnly,true);
 has(r,'DS_CROSS_SIGNED_TRANSITION_FORK_QUARANTINE');
 has(r,'DS_NONCE_REUSE_ACROSS_SIGNED_FORK');held(r);
});
test('1DS valid separate nonces with same predecessor still count signed fork',()=>{
 const m=clone(manifest);m.rotationNonce='e'.repeat(64);
 const r=assess([packet(),packet({m})]);
 has(r,'DS_CROSS_SIGNED_TRANSITION_FORK_QUARANTINE');
 assert.equal(r.candidateNonceReuseForkObservedOnly,false);held(r);
});
test('1DS tampered transition manifest, forged GO and extra fields are rejected',()=>{
 const a=packet(),b=clone(a);
 b.manifest.issuedAt='2026-11-20T23:59:59.000Z';
 b.claimedTransitionSha256=rotationDigest(b.manifest,b.identities,b.attestations);
 let r=assess([a,b]);has(r,'DS_FOUR_ROLE_STEP_SIGNATURES_INVALID');held(r);
 const c=clone(a);c.manifest.decision='GO';
 r=assess([a,c]);has(r,'DS_SIGNED_SOURCE_OR_SEQUENCE_INVALID');held(r);
 const d=clone(a);d.externalApproved=true;
 r=assess([a,d]);has(r,'DS_PACKET_SCHEMA_OR_SIZE_INVALID');held(r);
});
test('1DS wrong role or old/new signer swapping is rejected',()=>{
 const a=packet(),b=clone(a);
 [b.attestations.LEGAL_WITNESS.previous,b.attestations.REGISTRY_WITNESS.previous]=
  [b.attestations.REGISTRY_WITNESS.previous,b.attestations.LEGAL_WITNESS.previous];
 const r=assess([a,b]);has(r,'DS_FOUR_ROLE_STEP_SIGNATURES_INVALID');held(r);
});
test('1DS duplicate key IDs, SPKI, predecessor drift and missing old pins reject',()=>{
 const a=packet(),b=clone(a);
 b.identities.LEGAL_WITNESS.next.keyId=b.identities.LEGAL_WITNESS.previous.keyId;
 let r=assess([a,b]);has(r,'DS_KEY_REUSE_COLLISION_OR_UNPINNED_PREDECESSOR');held(r);
 const c=clone(a);
 c.identities.LEGAL_WITNESS.next.spkiSha256=
  c.identities.LEGAL_WITNESS.previous.spkiSha256;
 r=assess([a,c]);has(r,'DS_KEY_REUSE_COLLISION_OR_UNPINNED_PREDECESSOR');held(r);
 r=assess([a,a],{previousIdentityPins:{
  ...previousIdentityPins,
  LEGAL_WITNESS:{...previousIdentityPins.LEGAL_WITNESS,keyId:'not-old'}
 }});
 has(r,'DS_KEY_REUSE_COLLISION_OR_UNPINNED_PREDECESSOR');held(r);
});
test('1DS untrusted context source, checkpoint and sequence rollback fail',()=>{
 const a=packet();
 for(const k of ['sourceHeadSha','mainBaseSha','previousCheckpointSha256',
  'nextCandidateCheckpointSha256','nextSequence']){
  const m=clone(manifest);
  m[k]=k==='nextSequence'?3:(k.endsWith('Sha')?
   'f'.repeat(k.includes('Checkpoint')?64:40):'f'.repeat(40));
  const r=assess([a,packet({m})]);
  has(r,'DS_SIGNED_SOURCE_OR_SEQUENCE_INVALID');held(r);
 }
 const r=assess([a,a],{expected:{...expected,previousSequence:
  Number.MAX_SAFE_INTEGER}});
 has(r,'DS_EXPECTED_SOURCE_SEQUENCE_REQUIRED');held(r);
});
test('1DS missing, stale, future and malformed clocks fail closed',()=>{
 const a=packet();
 for(const bad of [null,'2026-11-21','2026-11-21T01:00:00.000Z']){
  const r=assess([a,a],{now:bad});
  has(r,'DS_EXPLICIT_CLOCK_REQUIRED'===(
   bad===null||bad==='2026-11-21'?'DS_EXPLICIT_CLOCK_REQUIRED':'x')?
   'DS_EXPLICIT_CLOCK_REQUIRED':'DS_EXPLICIT_TIME_OR_EXPIRY_INVALID');
  assert.equal(r.mathematicallyVerifiedFourSignatureCandidatesOnly,0);held(r);
 }
});
test('1DS future issuance and overlong lifetime quarantine',()=>{
 const a=packet(),future=clone(manifest);
 future.issuedAt='2026-11-21T00:06:00.000Z';
 let r=assess([a,packet({m:future})]);
 has(r,'DS_EXPLICIT_TIME_OR_EXPIRY_INVALID');held(r);
 const long=clone(manifest);long.expiresAt='2026-11-21T00:16:00.000Z';
 r=assess([a,packet({m:long})]);
 has(r,'DS_EXPLICIT_TIME_OR_EXPIRY_INVALID');held(r);
});
test('1DS incident recovery never becomes authorized via old-key co-signatures',()=>{
 const m=clone(manifest);m.reason='INCIDENT_RECOVERY';
 const r=assess([packet({m}),packet({m})]);
 assert.equal(r.mathematicallyVerifiedFourSignatureCandidatesOnly,2);
 has(r,'DS_INCIDENT_RECOVERY_NEEDS_INDEPENDENT_AUTHORITY');
 assert.equal(r.incidentRecoveryMandateVerified,false);held(r);
});
test('1DS fake transition hash and invalid Ed25519 signature fail',()=>{
 const a=packet(),b=packet();
 b.claimedTransitionSha256='f'.repeat(64);
 let r=assess([a,b]);has(r,'DS_CLAIMED_TRANSITION_DIGEST_INVALID');held(r);
 const c=clone(a);c.attestations.LEGAL_WITNESS.next.signature='A'.repeat(86)+'==';
 c.claimedTransitionSha256=rotationDigest(c.manifest,c.identities,c.attestations);
 r=assess([a,c]);has(r,'DS_FOUR_ROLE_STEP_SIGNATURES_INVALID');held(r);
});
test('1DS rejects wrong signing scope and keeps role,step domain separation',()=>{
 const a=packet(),i=a.identities,m=a.manifest;
 assert.notDeepEqual(rotationSigningBytes('LEGAL_WITNESS','previous',m,i),
  rotationSigningBytes('LEGAL_WITNESS','next',m,i));
 assert.notDeepEqual(rotationSigningBytes('LEGAL_WITNESS','previous',m,i),
  rotationSigningBytes('REGISTRY_WITNESS','previous',m,i));
 assert.ok(ROTATION_DOMAIN.includes('phase1ds'));
 assert.throws(()=>rotationSigningBytes('WRONG','previous',m,i));
 assert.throws(()=>rotationSigningBytes('LEGAL_WITNESS','future',m,i));
 assert.throws(()=>rotationSigningBytes('LEGAL_WITNESS','next',
  {...m,schemaVersion:2},i));
});
test('1DS requires 2–8 bounded observations with exact packet shape',()=>{
 const a=packet();
 for(const bad of [null,[],[a],Array(9).fill(a)]){
  const r=assess(bad);has(r,'DS_TWO_TO_EIGHT_CANDIDATES_REQUIRED');held(r);
 }
 const b=clone(a);b.padding='x'.repeat(33000);
 const r=assess([a,b]);has(r,'DS_PACKET_SCHEMA_OR_SIZE_INVALID');held(r);
});
test('1DS output excludes raw key identifiers, PEM, nonce and signatures',()=>{
 const a=packet(),r=assess([a,clone(a)]);
 const s=JSON.stringify(r);
 for(const secret of [a.manifest.rotationNonce,'legal-new','registry-old',
  a.attestations.LEGAL_WITNESS.previous.publicKeyPem,
  a.attestations.REGISTRY_WITNESS.next.signature])
  assert.equal(s.includes(secret),false);
 assert.equal(r.nextV2CheckpointOrIndependentObserverVerified,false);
 assert.equal(r.historicalV1AndV2SignaturesNeverMigrated,true);
 assert.ok(Object.isFrozen(r)&&Object.isFrozen(r.anomalyCodes));held(r);
});
