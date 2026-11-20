import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {REPO} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {rotationSigningBytes,rotationDigest}
 from '../scripts/phase1ds-offline-witness-key-rollover.mjs';
import {V2_ROLES,witnessSigningBytesV2,checkpointDigestV2}
 from '../scripts/phase1dr-offline-keyid-bound-witness-v2.mjs';
import {assessOfflineRolloverCheckpointContinuity}
 from '../scripts/phase1dt-offline-rollover-checkpoint-continuity.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex');
const clone=x=>structuredClone(x);
const NOW='2026-11-21T00:00:00.000Z';
const pair=()=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {privateKey,publicKeyPem:publicKey.export({type:'spki',
  format:'pem'}).toString(),spkiSha256:hash(publicKey.export({
   type:'spki',format:'der'}))};
};
const keys={
 LEGAL_WITNESS:{previous:pair(),next:pair()},
 REGISTRY_WITNESS:{previous:pair(),next:pair()}
};
const registrar=pair(),another=pair();
const ids={
 LEGAL_WITNESS:{previous:'legal-old',next:'legal-next'},
 REGISTRY_WITNESS:{previous:'registry-old',next:'registry-next'}
};
const previousIdentityPins=Object.fromEntries(V2_ROLES.map(role=>[
 role,{keyId:ids[role].previous,
  spkiSha256:keys[role].previous.spkiSha256}
]));
const baseV2={
 schemaVersion:2,kind:'UNTRUSTED_CORPORATE_REGISTRAR_ENROLLMENT_CANDIDATE_V2',
 repository:REPO,organizationId:'aaditech_corp',
 sourceHeadSha:'a'.repeat(40),mainBaseSha:'b'.repeat(40),
 registrarSpkiSha256:registrar.spkiSha256,
 registryEvidenceSha256:'c'.repeat(64),
 appointmentDigestSha256:'d'.repeat(64),nonce:'e'.repeat(64),
 sequence:1,previousCheckpointSha256:'0'.repeat(64),
 issuedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',decision:'HOLD'
};
const comparisonPins={
 organizationId:baseV2.organizationId,sourceHeadSha:baseV2.sourceHeadSha,
 mainBaseSha:baseV2.mainBaseSha,
 registrarSpkiSha256:baseV2.registrarSpkiSha256,
 registryEvidenceSha256:baseV2.registryEvidenceSha256,
 appointmentDigestSha256:baseV2.appointmentDigestSha256,nonce:baseV2.nonce
};
function v2(m=clone(baseV2),opts={}){
 const witnesses=Object.fromEntries(V2_ROLES.map(role=>{
  const key=opts[role]?.key??keys[role].next;
  const keyId=opts[role]?.keyId??ids[role].next;
  const identity={keyId,spkiSha256:key.spkiSha256};
  return [role,{...identity,publicKeyPem:key.publicKeyPem,
   signature:sign(null,witnessSigningBytesV2(role,m,identity),
    key.privateKey).toString('base64')}];
 }));
 return {manifest:m,witnesses,
  claimedCheckpointSha256:checkpointDigestV2(m,witnesses)};
}
const defaultV2=v2();
const expected={
 organizationId:'aaditech_corp',sourceHeadSha:baseV2.sourceHeadSha,
 mainBaseSha:baseV2.mainBaseSha,previousSequence:0,
 previousCheckpointSha256:'0'.repeat(64),
 nextCandidateCheckpointSha256:defaultV2.claimedCheckpointSha256
};
const baseRotation={
 schemaVersion:1,kind:'UNTRUSTED_WITNESS_ROTATION_CANDIDATE',
 repository:REPO,organizationId:expected.organizationId,
 sourceHeadSha:expected.sourceHeadSha,mainBaseSha:expected.mainBaseSha,
 previousSequence:0,nextSequence:1,
 previousCheckpointSha256:expected.previousCheckpointSha256,
 nextCandidateCheckpointSha256:expected.nextCandidateCheckpointSha256,
 rotationNonce:'9'.repeat(64),reason:'PLANNED_ROLLOVER',
 issuedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',decision:'HOLD'
};
function rotation(m=clone(baseRotation),options={}){
 const kset=Object.fromEntries(V2_ROLES.map(role=>[role,{
  previous:keys[role].previous,next:options[role]?.key??keys[role].next
 }]));
 const identities=Object.fromEntries(V2_ROLES.map(role=>[role,
  Object.fromEntries(['previous','next'].map(step=>[
   step,{keyId:step==='next'?(options[role]?.keyId??ids[role][step]):
    ids[role][step],spkiSha256:kset[role][step].spkiSha256}
  ]))
 ]));
 const attestations=Object.fromEntries(V2_ROLES.map(role=>[role,
  Object.fromEntries(['previous','next'].map(step=>[
   step,{publicKeyPem:kset[role][step].publicKeyPem,
    signature:sign(null,rotationSigningBytes(role,step,m,identities),
     kset[role][step].privateKey).toString('base64')}
  ]))
 ]));
 return {manifest:m,identities,attestations,
  claimedTransitionSha256:rotationDigest(m,identities,attestations)};
}
const defaultRotation=rotation();
function input(options={}){
 return {transitionCandidates:[defaultRotation,clone(defaultRotation)],
  checkpointObservations:[defaultV2,clone(defaultV2)],
  expected,previousIdentityPins,comparisonPins,now:NOW,...options};
}
const assess=o=>assessOfflineRolloverCheckpointContinuity(input(o));
const has=(r,s)=>assert.ok(r.anomalyCodes.includes(s),
 'missing '+s+', got '+r.anomalyCodes.join(','));
const hold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.mutationOrKeyEnrollmentPossible,false);
 assert.equal(r.independentlyPublishedNextCheckpointVerified,false);
 assert.equal(r.independentlyAuthenticatedLegalOrRegistryKeys,false);
};
test('1DT four signed old/new keys link mathematically to next signed v2, always HOLD',()=>{
 const r=assess();
 assert.equal(r.fourWayTransitionSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.nextV2CheckpointsMathematicallyVerifiedOnly,2);
 assert.equal(r.signedTransitionAndNextV2CheckpointLinkedMathematicallyOnly,true);
 assert.equal(r.claimedNextCheckpointDigestCryptographicallyCorroboratedOnly,true);
 assert.equal(r.nextV2KeyIdAndSpkiEqualCrossSignedTransitionOnly,true);
 has(r,'DT_REPLAYED_RECEIPTS_NOT_INDEPENDENT_PUBLICATION');hold(r);
});
test('1DT rehashed but unsigned next checkpoint is rejected',()=>{
 const cp=clone(defaultV2);cp.manifest.issuedAt='2026-11-20T23:59:59.000Z';
 cp.claimedCheckpointSha256=checkpointDigestV2(cp.manifest,cp.witnesses);
 const r=assess({checkpointObservations:[defaultV2,cp]});
 assert.equal(r.signedTransitionAndNextV2CheckpointLinkedMathematicallyOnly,false);
 has(r,'DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');hold(r);
});
test('1DT properly re-signed second next V2 manifest fork quarantines',()=>{
 const m=clone(baseV2);m.issuedAt='2026-11-20T23:59:59.000Z';
 const r=assess({checkpointObservations:[defaultV2,v2(m)]});
 has(r,'DT_NEXT_V2_SIGNED_FORK_QUARANTINE');hold(r);
});
test('1DT genuinely re-signed but different single V2 checkpoint cannot match transition claim',()=>{
 const m=clone(baseV2);m.issuedAt='2026-11-20T23:59:59.000Z';
 const cp=v2(m);
 const r=assess({checkpointObservations:[cp,clone(cp)]});
 assert.equal(r.nextV2CheckpointsMathematicallyVerifiedOnly,2);
 has(r,'DT_SIGNED_NEXT_CHECKPOINT_DIGEST_MISMATCH');hold(r);
});
test('1DT re-signed V2 key ID drift rejected despite pinned SPKI',()=>{
 const cp=v2(clone(baseV2),{
  LEGAL_WITNESS:{keyId:'legal-new-id-drift'}});
 const r=assess({checkpointObservations:[cp,clone(cp)]});
 assert.equal(r.nextV2CheckpointsMathematicallyVerifiedOnly,2);
 has(r,'DT_NEXT_SIGNED_KEY_ID_OR_SPKI_UNBOUND');hold(r);
});
test('1DT replaced new V2 signing key fails cross-signed SPKI binding',()=>{
 const cp=v2(clone(baseV2),{
  LEGAL_WITNESS:{key:another}});
 const r=assess({checkpointObservations:[cp,clone(cp)]});
 has(r,'DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');hold(r);
});
test('1DT unsigned key-ID rewrite in four-way candidate fails signature',()=>{
 const bad=clone(defaultRotation);
 bad.identities.LEGAL_WITNESS.next.keyId='legal-forged-next';
 bad.claimedTransitionSha256=rotationDigest(
  bad.manifest,bad.identities,bad.attestations);
 const r=assess({transitionCandidates:[defaultRotation,bad]});
 has(r,'DT_TRANSITION_FOUR_WAY_OR_FORK_INVALID');hold(r);
});
test('1DT separately fully co-signed transition fork is quarantined',()=>{
 const mf=clone(baseRotation);mf.rotationNonce='8'.repeat(64);
 const r=assess({transitionCandidates:[defaultRotation,rotation(mf)]});
 has(r,'DT_SIGNED_ROLLOVER_FORK_QUARANTINE');hold(r);
});
test('1DT incident recovery four-way signatures still require external mandate',()=>{
 const mf=clone(baseRotation);mf.reason='INCIDENT_RECOVERY';
 const rot=rotation(mf);
 const r=assess({transitionCandidates:[rot,clone(rot)]});
 has(r,'DT_RECOVERY_REQUIRES_INDEPENDENT_MANDATE');hold(r);
});
test('1DT comparison source-pins and old checkpoint are not interchangeable',()=>{
 let r=assess({comparisonPins:{...comparisonPins,sourceHeadSha:'f'.repeat(40)}});
 has(r,'DT_CROSS_ENVELOPE_SOURCE_PINS_MISMATCH');hold(r);
 r=assess({expected:{...expected,previousCheckpointSha256:'e'.repeat(64)}});
 has(r,'DT_TRANSITION_FOUR_WAY_OR_FORK_INVALID');hold(r);
});
test('1DT refuses stale/missing clock and wrong signed sequence',()=>{
 let r=assess({now:null});
 has(r,'DT_TRANSITION_FOUR_WAY_OR_FORK_INVALID');hold(r);
 const mf=clone(baseV2);mf.sequence=2;
 const cp=v2(mf);
 r=assess({checkpointObservations:[cp,clone(cp)]});
 has(r,'DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');hold(r);
});
test('1DT incomplete, over-bounded or invalid observation sets fail',()=>{
 let r=assess({checkpointObservations:[defaultV2]});
 has(r,'DT_TWO_TO_EIGHT_CHECKPOINT_PACKETS_REQUIRED');hold(r);
 r=assess({checkpointObservations:Array(9).fill(defaultV2)});
 has(r,'DT_TWO_TO_EIGHT_CHECKPOINT_PACKETS_REQUIRED');hold(r);
 r=assess({transitionCandidates:[defaultRotation]});
 has(r,'DT_TRANSITION_FOUR_WAY_OR_FORK_INVALID');hold(r);
});
test('1DT forged GO or historical V1 checkpoint cannot be promoted',()=>{
 const cp=clone(defaultV2);cp.manifest.decision='GO';
 let r=assess({checkpointObservations:[defaultV2,cp]});
 has(r,'DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');hold(r);
 cp.manifest.schemaVersion=1;
 r=assess({checkpointObservations:[defaultV2,cp]});
 has(r,'DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');hold(r);
});
test('1DT exact API shape cannot be extended with applicant GO field',()=>{
 const r=assessOfflineRolloverCheckpointContinuity({
  ...input(),releaseApproved:true});
 has(r,'DT_EXACT_INPUT_SCHEMA_REQUIRED');
 assert.equal(r.signedTransitionAndNextV2CheckpointLinkedMathematicallyOnly,false);
 hold(r);
});
test('1DT response hides raw private evidence and remains immutable',()=>{
 const r=assess(),s=JSON.stringify(r);
 for(const hidden of [defaultRotation.manifest.rotationNonce,
  ids.LEGAL_WITNESS.next,ids.REGISTRY_WITNESS.previous,
  defaultV2.witnesses.LEGAL_WITNESS.publicKeyPem,
  defaultRotation.attestations.REGISTRY_WITNESS.next.signature])
  assert.equal(s.includes(hidden),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);hold(r);
});
