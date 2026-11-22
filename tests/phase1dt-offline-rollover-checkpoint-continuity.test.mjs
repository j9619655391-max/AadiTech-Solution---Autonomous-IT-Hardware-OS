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

/* Phase 1DU: reuse the same cryptographic fixture suite for consecutive epochs.
 * Both epochs remain completely synthetic and do NOT prove independent custody. */
import {assessOfflineMultiEpochRolloverChain}
 from '../scripts/phase1du-offline-multi-epoch-rollover-chain.mjs';

function twoEpochFixture(options={}){
 const fresh={LEGAL_WITNESS:pair(),REGISTRY_WITNESS:pair()};
 const newIds={LEGAL_WITNESS:'legal-third',
  REGISTRY_WITNESS:'registry-third'};
 const oldKeys=options.roguePrevious?
  {LEGAL_WITNESS:pair(),REGISTRY_WITNESS:pair()}:
  Object.fromEntries(V2_ROLES.map(role=>[role,keys[role].next]));
 const oldIds=options.roguePrevious?
  {LEGAL_WITNESS:'rogue-legal-old',REGISTRY_WITNESS:'rogue-registry-old'}:
  Object.fromEntries(V2_ROLES.map(role=>[role,ids[role].next]));
 const issued=options.sameTimes?NOW:'2026-11-21T00:00:01.000Z';
 const m2={...baseV2,sequence:2,
  previousCheckpointSha256:defaultV2.claimedCheckpointSha256,
  nonce:options.reuseCheckpointNonce?baseV2.nonce:'f'.repeat(64),
  issuedAt:issued,
  expiresAt:'2026-11-21T00:11:00.000Z'};
 const opts=Object.fromEntries(V2_ROLES.map(role=>[role,
  {key:fresh[role],keyId:newIds[role]}]));
 const cp2=v2(m2,opts);
 const rm2={...baseRotation,previousSequence:1,nextSequence:2,
  previousCheckpointSha256:defaultV2.claimedCheckpointSha256,
  nextCandidateCheckpointSha256:cp2.claimedCheckpointSha256,
  rotationNonce:options.reuseRotationNonce?baseRotation.rotationNonce:
   '8'.repeat(64),
  issuedAt:issued,
  expiresAt:'2026-11-21T00:11:00.000Z'};
 const identities=Object.fromEntries(V2_ROLES.map(role=>[
  role,{previous:{keyId:oldIds[role],
   spkiSha256:oldKeys[role].spkiSha256},
   next:{keyId:newIds[role],spkiSha256:fresh[role].spkiSha256}}
 ]));
 const attestations=Object.fromEntries(V2_ROLES.map(role=>{
  const old=oldKeys[role],upcoming=fresh[role];
  return [role,Object.fromEntries([
   ['previous',{publicKeyPem:old.publicKeyPem,
    signature:sign(null,rotationSigningBytes(
     role,'previous',rm2,identities),old.privateKey).toString('base64')}],
   ['next',{publicKeyPem:upcoming.publicKeyPem,
    signature:sign(null,rotationSigningBytes(
     role,'next',rm2,identities),upcoming.privateKey).toString('base64')}]
  ])];
 }));
 const rot2={manifest:rm2,identities,attestations,
  claimedTransitionSha256:rotationDigest(rm2,identities,attestations)};
 const ep1=clone(input());delete ep1.now; // isolate per-test signed fixtures
 const ep2={transitionCandidates:[rot2,clone(rot2)],
  checkpointObservations:[cp2,clone(cp2)],
  expected:{...expected,previousSequence:1,
   previousCheckpointSha256:defaultV2.claimedCheckpointSha256,
   nextCandidateCheckpointSha256:cp2.claimedCheckpointSha256},
  previousIdentityPins:Object.fromEntries(V2_ROLES.map(role=>[
   role,{...identities[role].previous}])),
  comparisonPins:{...comparisonPins,nonce:m2.nonce}};
 return {epochs:[ep1,ep2],now:NOW};
}
const du=o=>assessOfflineMultiEpochRolloverChain(o);
const duHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionMutationOrKeyEnrollmentPossible,false);
 assert.equal(r.trustedTimeExternalWormCasTransparencyAndRevocationVerified,false);
};
test('1DU valid two-step four-way and signed-v2 chain is mathematical only',()=>{
 const r=du(twoEpochFixture());
 assert.equal(r.independentlyReverifiedEpochsMathematicallyOnly,2);
 assert.equal(r.consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly,true);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.applicantSuppliedHistoryIsNotIndependentPublication,true);
 duHold(r);
});
test('1DU swapped signed chronology cannot establish history',()=>{
 const x=twoEpochFixture();x.epochs.reverse();
 const r=du(x);
 has(r,'DU_NONCONTIGUOUS_SEQUENCE_OR_PREDECESSOR');
 duHold(r);
});
test('1DU reusing a signed epoch cannot count as additional rollover',()=>{
 const x=twoEpochFixture();x.epochs[1]=clone(x.epochs[0]);
 const r=du(x);
 has(r,'DU_REPLAYED_CHECKPOINT_OR_TRANSITION');
 has(r,'DU_CROSS_EPOCH_SIGNED_NONCE_REUSE');
 assert.equal(r.consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly,false);
 duHold(r);
});
test('1DU signed checkpoint predecessor claim mismatch is quarantined',()=>{
 const x=twoEpochFixture();
 x.epochs[1].expected.previousCheckpointSha256='a'.repeat(64);
 const r=du(x);
 has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');duHold(r);
});
test('1DU predecessor witness key ID drift cannot inherit old authority',()=>{
 const x=twoEpochFixture();
 x.epochs[1].previousIdentityPins.LEGAL_WITNESS.keyId='forged-old';
 const r=du(x);
 has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');duHold(r);
});
test('1DU unsigned checkpoint tampering in a later epoch denied',()=>{
 const x=twoEpochFixture();
 x.epochs[1].checkpointObservations[0].manifest.issuedAt=
  '2026-11-21T00:00:02.000Z';
 const r=du(x);
 has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');duHold(r);
});
test('1DU partial transition observation list is not a verifier quorum',()=>{
 const x=twoEpochFixture();x.epochs[1].transitionCandidates.length=1;
 const r=du(x);
 has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');duHold(r);
});
test('1DU cannot skip a broken first epoch and restart the chain',()=>{
 const x=twoEpochFixture();
 x.epochs[0].checkpointObservations[0].manifest.decision='GO';
 const r=du(x);
 has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');
 has(r,'DU_PREDECESSOR_EPOCH_NOT_VERIFIED');duHold(r);
});
test('1DU rejects applicant-supplied approval/extension fields',()=>{
 const x=twoEpochFixture();
 x.epochs[1].approved=true;
 const r=du(x);
 has(r,'DU_EPOCH_SCHEMA_INVALID');duHold(r);
});
test('1DU refuses omitted or stale clock',()=>{
 const x=twoEpochFixture();x.now=null;
 let r=du(x);has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');
 duHold(r);
 x.now='2026-11-22T00:00:00.000Z';
 r=du(x);has(r,'DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');
 duHold(r);
});
test('1DU rejects unbounded, singleton and malformed histories',()=>{
 let r=du({epochs:[],now:NOW});has(r,'DU_TWO_TO_SIX_EPOCHS_REQUIRED');duHold(r);
 r=du({epochs:Array(7).fill(twoEpochFixture().epochs[0]),now:NOW});
 has(r,'DU_TWO_TO_SIX_EPOCHS_REQUIRED');duHold(r);
 r=du({epochs:[{},{}],now:NOW});
 has(r,'DU_EPOCH_SCHEMA_INVALID');duHold(r);
 r=du({...twoEpochFixture(),claimedReleaseApproved:true});
 has(r,'DU_EXACT_TOP_LEVEL_INPUT_REQUIRED');duHold(r);
});
test('1DU redacts witness identities, signatures, nonce and raw PEM',()=>{
 const x=twoEpochFixture(),r=du(x),s=JSON.stringify(r);
 for(const secret of [
  x.epochs[1].transitionCandidates[0].manifest.rotationNonce,
  x.epochs[1].transitionCandidates[0].attestations.LEGAL_WITNESS.next.signature,
  x.epochs[1].checkpointObservations[0].witnesses.REGISTRY_WITNESS.publicKeyPem,
  'legal-third','registry-third'
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);
 duHold(r);
});

test('1DU individually valid rogue predecessor keys cannot inherit prior epoch',()=>{
 const r=du(twoEpochFixture({roguePrevious:true}));
 assert.equal(r.independentlyReverifiedEpochsMathematicallyOnly,2);
 has(r,'DU_PREDECESSOR_SIGNED_KEY_ID_OR_SPKI_MISMATCH');
 assert.equal(r.consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly,false);
 duHold(r);
});
test('1DU individually valid signatures with repeated cross-epoch nonces fail',()=>{
 for(const opts of [{reuseCheckpointNonce:true},{reuseRotationNonce:true}]){
  const r=du(twoEpochFixture(opts));
  assert.equal(r.independentlyReverifiedEpochsMathematicallyOnly,2);
  has(r,'DU_CROSS_EPOCH_SIGNED_NONCE_REUSE');duHold(r);
 }
});
test('1DU fully verified but same-time successor fails strict signed chronology',()=>{
 const r=du(twoEpochFixture({sameTimes:true}));
 assert.equal(r.independentlyReverifiedEpochsMathematicallyOnly,2);
 has(r,'DU_SIGNED_EPOCH_TIME_ORDER_INVALID');duHold(r);
});

/* Phase 1DV: synthetic candidate-only signatures; no independent source access. */
import {DV_ROLES,observerSigningBytesDv,assessOfflineObserverPublicationCandidate}
 from '../scripts/phase1dv-offline-observer-publication-candidate.mjs';

function dvFixture(){
 const history=twoEpochFixture();
 const terminal=history.epochs.at(-1).checkpointObservations[0];
 const archive=Buffer.from('synthetic offline archive bytes','utf8');
 const expected={
  organizationId:terminal.manifest.organizationId,
  sourceHeadSha:terminal.manifest.sourceHeadSha,
  mainBaseSha:terminal.manifest.mainBaseSha,
  checkpointSha256:terminal.claimedCheckpointSha256,
  previousCheckpointSha256:terminal.manifest.previousCheckpointSha256,
  sequence:terminal.manifest.sequence,archiveVersion:'snapshot_01',
  archiveSha256:hash(archive),legalMandateDigestSha256:'1'.repeat(64),
  revocationDigestSha256:'2'.repeat(64),challengeNonce:'3'.repeat(64)
 };
 const comparisonPins={},privateKeys={};
 const observations=DV_ROLES.map((role,index)=>{
  const kp=pair(),n=index===0?'pub':'arc';
  privateKeys[role]=kp.privateKey;
  const pin={keyId:'observer_'+n+'01',observerId:'observer_'+n+'01',
   operatorId:'operator_'+n+'01',spkiSha256:kp.spkiSha256,
   endpointHost:n+'.example.invalid',
   tlsPeerSpkiSha256:(index===0?'4':'5').repeat(64)};
  comparisonPins[role]=pin;
  const statement={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_OBSERVER_PUBLICATION_CANDIDATE',
   role,repository:REPO,...expected,...pin,
   httpStatus:200,redirectCount:0,observedAt:NOW,
   expiresAt:'2026-11-21T00:10:00.000Z',decision:'HOLD'};
  return {statement,publicKeyPem:kp.publicKeyPem,
   signature:sign(null,observerSigningBytesDv(statement),
    kp.privateKey).toString('base64')};
 });
 return {args:{history,observations,comparisonPins,expected,
  archivePayloadBase64:archive.toString('base64'),now:NOW},privateKeys};
}
function dvResign(f,index){
 const packet=f.args.observations[index];
 packet.signature=sign(null,observerSigningBytesDv(packet.statement),
  f.privateKeys[packet.statement.role]).toString('base64');
}
const dvHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionMutationOrKeyEnrollmentPossible,false);
 assert.equal(r.externalIndependentPublicationAndRetrievalAuthenticated,false);
 assert.equal(r.externalSignedLegalMandateAndMcaAuthorityAuthenticated,false);
 assert.equal(r.liveSignedRevocationChainCrlOcspAuthenticated,false);
};
test('1DV two different Ed25519 observations corroborate untrusted archive bytes mathematically only',()=>{
 const r=assessOfflineObserverPublicationCandidate(dvFixture().args);
 assert.equal(r.fullSignedHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.roleSeparatedSignedObserverPacketsMathematicallyVerifiedOnly,2);
 assert.equal(r.candidateObserverPublicationCorroboratedMathematicallyOnly,true);
 assert.deepEqual(r.anomalyCodes,[]);dvHold(r);
});
test('1DV duplicate signed observer packet fails independent role quorum',()=>{
 const f=dvFixture();f.args.observations[1]=clone(f.args.observations[0]);
 const r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_OBSERVER_ROLE_PACKET_SCHEMA_OR_DUPLICATE');
 has(r,'DV_INCOMPLETE_ROLE_QUORUM');dvHold(r);
});
test('1DV fully resigned wrong source, signed checkpoint or predecessor scope cannot pass',()=>{
 for(const key of ['sourceHeadSha','checkpointSha256','previousCheckpointSha256']){
  const f=dvFixture(),replacement=key==='sourceHeadSha'?'f'.repeat(40):
   'f'.repeat(64);
  f.args.expected[key]=replacement;
  f.args.observations.forEach((o,i)=>{
   o.statement[key]=replacement;dvResign(f,i);
  });
  const r=assessOfflineObserverPublicationCandidate(f.args);
  has(r,'DV_TERMINAL_SIGNED_CHECKPOINT_SCOPE_MISMATCH');dvHold(r);
 }
});
test('1DV applicant can change mandate or revocation digests but cannot authenticate authority',()=>{
 const r=assessOfflineObserverPublicationCandidate(dvFixture().args);
 assert.equal(r.externalSignedLegalMandateAndMcaAuthorityAuthenticated,false);
 assert.equal(r.liveSignedRevocationChainCrlOcspAuthenticated,false);
 for(const key of ['legalMandateDigestSha256','revocationDigestSha256']){
  const f=dvFixture();f.args.expected[key]='f'.repeat(64);
  const v=assessOfflineObserverPublicationCandidate(f.args);
  has(v,'DV_SIGNED_SCOPE_RETRIEVAL_OR_HOLD_INVALID');dvHold(v);
 }
});
test('1DV signed hash never overrides actual supplied archive bytes',()=>{
 const f=dvFixture();
 f.args.archivePayloadBase64=Buffer.from('counterfeit').toString('base64');
 const r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_SUPPLIED_ARCHIVE_BYTES_OR_DIGEST_INVALID');dvHold(r);
});
test('1DV re-signed GO, HTTP redirect, or fake observer kind refused',()=>{
 for(const [key,value] of [['decision','GO'],['httpStatus',302],
  ['redirectCount',1],['kind','CLAIMED_AUTHORIZED']]){
  const f=dvFixture();f.args.observations[0].statement[key]=value;
  dvResign(f,0);
  const r=assessOfflineObserverPublicationCandidate(f.args);
  has(r,'DV_SIGNED_SCOPE_RETRIEVAL_OR_HOLD_INVALID');dvHold(r);
 }
});
test('1DV invalid signatures and substituted Ed25519 public keys are rejected',()=>{
 let f=dvFixture();
 f.args.observations[0].signature=f.args.observations[1].signature;
 let r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_OBSERVER_SIGNATURE_OR_SPKI_INVALID');dvHold(r);
 f=dvFixture();
 f.args.observations[1].publicKeyPem=f.args.observations[0].publicKeyPem;
 r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_OBSERVER_SIGNATURE_OR_SPKI_INVALID');dvHold(r);
});
test('1DV correctly signed identity/endpoint/TLS pin drift is still quarantined',()=>{
 for(const [key,val] of [['endpointHost','evil.example.invalid'],
  ['operatorId','operator_spoof'],['tlsPeerSpkiSha256','f'.repeat(64)],
  ['keyId','observer_spoof']]){
  const f=dvFixture();f.args.observations[1].statement[key]=val;
  dvResign(f,1);
  const r=assessOfflineObserverPublicationCandidate(f.args);
  has(r,'DV_OBSERVER_KEY_TLS_OR_OPERATOR_PIN_MISMATCH');dvHold(r);
 }
});
test('1DV shared operator/endpoint/TLS and reused witness signer do not establish independence',()=>{
 for(const k of ['operatorId','endpointHost','tlsPeerSpkiSha256']){
  const f=dvFixture();
  const value=f.args.comparisonPins.CHECKPOINT_PUBLISHER[k];
  f.args.comparisonPins.INDEPENDENT_ARCHIVE_OBSERVER[k]=value;
  f.args.observations[1].statement[k]=value;dvResign(f,1);
  const r=assessOfflineObserverPublicationCandidate(f.args);
  has(r,'DV_DISTINCT_DETACHED_OBSERVER_PINS_REQUIRED');dvHold(r);
 }
 const f=dvFixture(),role=DV_ROLES[0],old=keys.LEGAL_WITNESS.next;
 f.args.comparisonPins[role].spkiSha256=old.spkiSha256;
 f.args.observations[0].statement.spkiSha256=old.spkiSha256;
 f.args.observations[0].publicKeyPem=old.publicKeyPem;
 f.privateKeys[role]=old.privateKey;dvResign(f,0);
 const r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_OBSERVER_REUSES_CHAIN_WITNESS_IDENTITY');dvHold(r);
});
test('1DV tampered prior signed history cannot be rehabilitated by new observer signatures',()=>{
 const f=dvFixture();
 f.args.history.epochs[0].checkpointObservations[0].manifest.decision='GO';
 const r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_PRECEDING_DU_SIGNED_HISTORY_UNVERIFIED');dvHold(r);
});
test('1DV expired signed observer and missing verification clock are denied',()=>{
 const f=dvFixture();
 f.args.observations[0].statement.expiresAt='2026-11-20T23:59:59.000Z';
 dvResign(f,0);
 let r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_SIGNED_OBSERVER_TIME_OR_EXPIRY_INVALID');dvHold(r);
 const x=dvFixture();x.args.now=null;
 r=assessOfflineObserverPublicationCandidate(x.args);
 has(r,'DV_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'DV_PRECEDING_DU_SIGNED_HISTORY_UNVERIFIED');dvHold(r);
});
test('1DV applicant GO extensions and invalid archive encoding fail exact schema',()=>{
 const f=dvFixture();
 let r=assessOfflineObserverPublicationCandidate({...f.args,externalAuthorityApproved:true});
 has(r,'DV_EXACT_BOUNDED_INPUT_REQUIRED');dvHold(r);
 f.args.comparisonPins.CHECKPOINT_PUBLISHER.externallyEnrolled=true;
 r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_DISTINCT_DETACHED_OBSERVER_PINS_REQUIRED');dvHold(r);
 f.args.archivePayloadBase64='bad?';
 r=assessOfflineObserverPublicationCandidate(f.args);
 has(r,'DV_SUPPLIED_ARCHIVE_BYTES_OR_DIGEST_INVALID');dvHold(r);
});
test('1DV no observer signature, PEM, key ID, raw archive or nonce leaks in frozen output',()=>{
 const f=dvFixture(),r=assessOfflineObserverPublicationCandidate(f.args);
 const s=JSON.stringify(r);
 for(const hidden of [f.args.observations[0].signature,
  f.args.observations[1].publicKeyPem,
  f.args.comparisonPins.CHECKPOINT_PUBLISHER.keyId,
  f.args.archivePayloadBase64,f.args.expected.challengeNonce])
  assert.equal(s.includes(hidden),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);dvHold(r);
});

/* Phase 1DW: applicant-controlled synthetic enrollment & revocation source
 * signatures. Mathematically consistent fixtures confer NO external authority. */
import {DW_ENROLLMENT_ROLES,DW_REVOCATION_ROLES,signingBytesDw,
 observerPinDigestDw,revocationStatusDigestDw,
 assessOfflineObserverEnrollmentRevocationCandidate}
 from '../scripts/phase1dw-offline-observer-enrollment-revocation.mjs';

const DW_SCOPE=['organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','archiveSha256','legalMandateDigestSha256',
 'revocationDigestSha256','challengeNonce'];
const dwScope=e=>Object.fromEntries(DW_SCOPE.map(k=>[k,e[k]]));
function dwFixture(){
 const dv=dvFixture();
 const previousAnchor={version:6,digestSha256:'6'.repeat(64)};
 const revocationState={
  version:7,previousVersion:6,previousDigestSha256:previousAnchor.digestSha256,
  revokedKeyIds:[],observedAt:NOW
 };
 dv.args.expected.revocationDigestSha256=
  revocationStatusDigestDw(dv.args.expected,revocationState);
 dv.args.observations.forEach((p,i)=>{
  p.statement.revocationDigestSha256=
   dv.args.expected.revocationDigestSha256;
  dvResign(dv,i);
 });
 const enrollmentPins={},revocationPins={},privateKeys={};
 const pins={...enrollmentPins,...revocationPins};
 const make=(roles,pins,kind,more)=>{
  return roles.map((role,index)=>{
   const kp=pair(),prefix=role.startsWith('LEGAL_')?'leg':
    role.startsWith('SECURITY_')?'sec':
    role.startsWith('CORPORATE_')?'reg':'prov';
   privateKeys[role]=kp.privateKey;
   const pin={keyId:'key_'+prefix+'_dw01',
    operatorId:'operator_'+prefix+'_dw01',
    custodianOrganizationId:'org_'+prefix+'_dw01',
    spkiSha256:kp.spkiSha256};
   pins[role]=pin;
   const statement={schemaVersion:1,kind,role,repository:REPO,
    ...dwScope(dv.args.expected),...pin,
    observedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',
    decision:'HOLD',...more()};
   return {statement,publicKeyPem:kp.publicKeyPem,
    signature:sign(null,signingBytesDw(role,statement),
     kp.privateKey).toString('base64')};
  });
 };
 const enrollmentPackets=make(DW_ENROLLMENT_ROLES,enrollmentPins,
  'UNTRUSTED_OFFLINE_OBSERVER_ENROLLMENT_CANDIDATE',
  ()=>({observerPinDigestSha256:
   observerPinDigestDw(dv.args.comparisonPins)}));
 const revocationPackets=make(DW_REVOCATION_ROLES,revocationPins,
  'UNTRUSTED_OFFLINE_REVOCATION_SOURCE_CANDIDATE',
  ()=>({currentVersion:revocationState.version,
   previousVersion:revocationState.previousVersion,
   previousDigestSha256:revocationState.previousDigestSha256,
   revokedKeyIds:[...revocationState.revokedKeyIds]}));
 return {args:{publicationCandidate:dv.args,
  enrollmentPackets,enrollmentPins,revocationPackets,
  revocationPins,revocationState,previousAnchor,now:NOW},
  privateKeys,dv};
}
function dwResign(f,kind,index){
 const packet=f.args[kind+'Packets'][index],role=packet.statement.role;
 packet.signature=sign(null,signingBytesDw(role,packet.statement),
  f.privateKeys[role]).toString('base64');
}
function dwRefreshState(f){
 const a=f.args,e=a.publicationCandidate.expected,s=a.revocationState;
 e.revocationDigestSha256=revocationStatusDigestDw(e,s);
 f.dv.args.observations.forEach((packet,i)=>{
  packet.statement.revocationDigestSha256=e.revocationDigestSha256;
  dvResign(f.dv,i);
 });
 for(const kind of ['enrollment','revocation']){
  a[kind+'Packets'].forEach((packet,i)=>{
   packet.statement.revocationDigestSha256=e.revocationDigestSha256;
   if(kind==='revocation'){
    packet.statement.currentVersion=s.version;
    packet.statement.previousVersion=s.previousVersion;
    packet.statement.previousDigestSha256=s.previousDigestSha256;
    packet.statement.revokedKeyIds=[...s.revokedKeyIds];
    packet.statement.observedAt=s.observedAt;
   }
   dwResign(f,kind,i);
  });
 }
}
const dwAssess=f=>assessOfflineObserverEnrollmentRevocationCandidate(f.args);
const dwHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.productionMutationOrCredentialEnrollmentPossible,false);
 assert.equal(r.observerKeyEnrollmentExternallyAuthenticated,false);
 assert.equal(r.externalArchiveRetrievalAndTlsChainAuthenticated,false);
 assert.equal(r.approvedProviderTrustChainAndLiveCrlOcspAuthenticated,false);
};
test('1DW two custody and two revocation signatures correlate mathematically but never authorize',()=>{
 const r=dwAssess(dwFixture());
 assert.equal(r.dvSignedHistoryAndDualObserverCandidateReverifiedOnly,true);
 assert.equal(r.twoEnrollmentSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.twoRevocationSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.candidateEnrollmentAndRevocationClaimsCorrelatedMathematicallyOnly,true);
 assert.deepEqual(r.anomalyCodes,[]);dwHold(r);
});
test('1DW a duplicate custodian or revocation role is not an independent quorum',()=>{
 for(const kind of ['enrollment','revocation']){
  const f=dwFixture();
  f.args[kind+'Packets'][1]=clone(f.args[kind+'Packets'][0]);
  const r=dwAssess(f);
  has(r,'DW_'+kind.toUpperCase()+'_ROLE_PACKET_INVALID');
  has(r,'DW_'+kind.toUpperCase()+'_SIGNER_QUORUM_INCOMPLETE');dwHold(r);
 }
});
test('1DW signed same-operator or signer-SPKI across roles cannot impersonate independence',()=>{
 for(const attr of ['keyId','operatorId','spkiSha256','custodianOrganizationId']){
  const f=dwFixture();
  const from=f.args.enrollmentPins[DW_ENROLLMENT_ROLES[0]];
  const to=f.args.revocationPins[DW_REVOCATION_ROLES[0]];
  to[attr]=from[attr];
  const entry=f.args.revocationPackets[0];
  entry.statement[attr]=from[attr];dwResign(f,'revocation',0);
  const r=dwAssess(f);
  has(r,'DW_INDEPENDENT_CUSTODY_REVOCATION_KEYS_UNPROVEN');dwHold(r);
 }
});
test('1DW valid signature made by old witness key still cannot inherit independent custody',()=>{
 const f=dwFixture(),role=DW_ENROLLMENT_ROLES[0];
 const old=keys.LEGAL_WITNESS.next;
 f.args.enrollmentPins[role].spkiSha256=old.spkiSha256;
 f.args.enrollmentPackets[0].statement.spkiSha256=old.spkiSha256;
 f.args.enrollmentPackets[0].publicKeyPem=old.publicKeyPem;
 f.privateKeys[role]=old.privateKey;dwResign(f,'enrollment',0);
 const r=dwAssess(f);
 has(r,'DW_INDEPENDENT_CUSTODY_REVOCATION_KEYS_UNPROVEN');dwHold(r);
});
test('1DW signed revoked observer cannot be accepted even with four valid refreshed signatures',()=>{
 const f=dwFixture();
 const key=f.args.publicationCandidate.comparisonPins.CHECKPOINT_PUBLISHER.keyId;
 f.args.revocationState.revokedKeyIds=[key];
 dwRefreshState(f);
 const r=dwAssess(f);
 assert.equal(r.dvSignedHistoryAndDualObserverCandidateReverifiedOnly,true);
 assert.equal(r.twoEnrollmentSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.twoRevocationSignaturesMathematicallyVerifiedOnly,2);
 has(r,'DW_REVOKED_ACTIVE_SIGNER_OR_OBSERVER_KEY');dwHold(r);
});
test('1DW signed revoked legal witness also quarantines nominally fresh candidate',()=>{
 const f=dwFixture();
 f.args.revocationState.revokedKeyIds=[ids.LEGAL_WITNESS.next];
 dwRefreshState(f);
 const r=dwAssess(f);
 has(r,'DW_REVOKED_ACTIVE_SIGNER_OR_OBSERVER_KEY');dwHold(r);
});
test('1DW previous revocation high-watermark rollback, gap and substitution denied',()=>{
 for(const modify of [
  f=>f.args.previousAnchor.version=5,
  f=>f.args.previousAnchor.digestSha256='a'.repeat(64),
  f=>f.args.revocationState.version=9,
  f=>f.args.revocationState.previousDigestSha256='a'.repeat(64)
 ]){
  const f=dwFixture();modify(f);
  const r=dwAssess(f);
  has(r,'DW_REVOCATION_MONOTONIC_ANCHOR_OR_CLOCK_INVALID');dwHold(r);
 }
});
test('1DW independently re-signed revocation fork cannot claim same digest/anchor',()=>{
 const f=dwFixture();
 f.args.revocationPackets[1].statement.revokedKeyIds=['former_signer_01'];
 dwResign(f,'revocation',1);
 const r=dwAssess(f);
 has(r,'DW_REVOCATION_SIGNED_STATE_OR_HISTORY_MISMATCH');dwHold(r);
});
test('1DW enrolled observer key digest mismatch cannot be repaired by re-signing',()=>{
 const f=dwFixture();
 f.args.enrollmentPackets[1].statement.observerPinDigestSha256='f'.repeat(64);
 dwResign(f,'enrollment',1);
 const r=dwAssess(f);
 has(r,'DW_ENROLLMENT_SIGNED_STATE_OR_HISTORY_MISMATCH');dwHold(r);
});
test('1DW signed GO, fake legal role, forged source SHA or deadline cannot authorize',()=>{
 for(const [key,value] of [['decision','GO'],
  ['sourceHeadSha','f'.repeat(40)],
  ['kind','REAL_LEGAL_AUTHORITY'],
  ['expiresAt','2026-11-20T23:59:59.000Z']]){
  const f=dwFixture();
  f.args.enrollmentPackets[0].statement[key]=value;
  dwResign(f,'enrollment',0);
  const r=dwAssess(f);
  if(key==='expiresAt')has(r,'DW_ENROLLMENT_STALE_OR_EXPIRED_SIGNATURE');
  else has(r,'DW_ENROLLMENT_SOURCE_OR_HOLD_SCOPE_MISMATCH');
  dwHold(r);
 }
});
test('1DW public key substitution and copied signature cannot pass',()=>{
 for(const kind of ['enrollment','revocation']){
  const f=dwFixture();
  f.args[kind+'Packets'][0].publicKeyPem=
   f.args[kind+'Packets'][1].publicKeyPem;
  const r=dwAssess(f);
  has(r,'DW_'+kind.toUpperCase()+'_ED25519_OR_SPKI_UNVERIFIED');
  dwHold(r);
 }
});
test('1DW fake release metadata and malformed status or extra revoked IDs fail closed',()=>{
 let f=dwFixture();
 let r=assessOfflineObserverEnrollmentRevocationCandidate({
  ...f.args,providerApproved:true});
 has(r,'DW_EXACT_BOUNDED_INPUT_REQUIRED');dwHold(r);
 f=dwFixture();f.args.revocationState.revokedKeyIds=['duplicat_01','duplicat_01'];
 r=dwAssess(f);
 has(r,'DW_REVOCATION_MONOTONIC_ANCHOR_OR_CLOCK_INVALID');dwHold(r);
 f=dwFixture();f.args.revocationState.revokedKeyIds=['zzz','aaa'];
 r=dwAssess(f);
 has(r,'DW_REVOCATION_MONOTONIC_ANCHOR_OR_CLOCK_INVALID');dwHold(r);
});
test('1DW independent past DU signed checkpoint fork cannot be saved by four new signatures',()=>{
 const f=dwFixture();
 f.args.publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=dwAssess(f);
 has(r,'DW_DV_CANDIDATE_NOT_REVERIFIED');dwHold(r);
});
test('1DW missing clock, mismatched DV clock and stale revocation status all fail',()=>{
 let f=dwFixture();f.args.now=null;
 let r=dwAssess(f);
 has(r,'DW_EXPLICIT_TRUSTED_CLOCK_ABSENT');
 has(r,'DW_DV_CANDIDATE_NOT_REVERIFIED');dwHold(r);
 f=dwFixture();
 f.args.revocationState.observedAt='2026-11-20T00:00:00.000Z';
 r=dwAssess(f);
 has(r,'DW_REVOCATION_MONOTONIC_ANCHOR_OR_CLOCK_INVALID');dwHold(r);
});
test('1DW duplicate two-party source receipts never equal actually live CRL or OCSP',()=>{
 const r=dwAssess(dwFixture());
 assert.equal(r.approvedProviderTrustChainAndLiveCrlOcspAuthenticated,false);
 assert.equal(r.persistentExternalRevocationAnchorWormCasAndDrVerified,false);
 assert.equal(r.corporateRegistryLegalMandateIndependentlyAuthenticated,false);
 assert.equal(r.independentOperatorGitHubStagingAndProductionApprovalVerified,false);
 dwHold(r);
});
test('1DW bounded frozen decision has no raw private evidence, signers, revocation list or nonce',()=>{
 const f=dwFixture(),r=dwAssess(f),s=JSON.stringify(r);
 for(const secret of [f.args.revocationPackets[0].signature,
  f.args.enrollmentPackets[1].publicKeyPem,
  f.args.enrollmentPins[DW_ENROLLMENT_ROLES[0]].keyId,
  f.args.publicationCandidate.expected.challengeNonce,
  'former_signer_01'])
  assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);
 dwHold(r);
});

/* Phase 1DX: 3 locally supplied retrieval byte sources, linked frozen
 * incident ledger and two recovery-custodian signatures. Zero external trust. */
import {DX_SOURCES,DX_RECOVERY_ROLES,DX_STAGES,
 sourceSigningBytesDx,evidenceSetDigestDx,recoveryStepDigestDx,
 recoverySigningBytesDx,assessOfflineEvidenceIncidentRecoveryCandidate}
 from '../scripts/phase1dx-offline-evidence-incident-recovery.mjs';
import {canonical} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';

const DX_SCOPE=['organizationId','sourceHeadSha','mainBaseSha',
 'checkpointSha256','archiveSha256','revocationDigestSha256','challengeNonce'];
const dxScope=e=>Object.fromEntries(DX_SCOPE.map(k=>[k,e[k]]));
function dxFixture(){
 const dw=dwFixture(),e=dw.args.publicationCandidate.expected;
 const sourcePins={},sourceBytes={},recoveryPins={},privateKeys={};
 const prior=dw.args.previousAnchor,status=dw.args.revocationState;
 const archive=dw.args.publicationCandidate.archivePayloadBase64;
 const revoked=Buffer.from(canonical({
  previousAnchor:prior,revocationState:status
 }),'utf8').toString('base64');
 const sourceReceipts=DX_SOURCES.map((role,index)=>{
  const code=['pub','arc','rev'][index],kp=pair();
  privateKeys[role]=kp.privateKey;
  const pin={keyId:'key_dx_'+code+'01',
   spkiSha256:kp.spkiSha256,operatorId:'operator_dx_'+code+'01',
   operatorOrganizationId:'org_dx_'+code+'01',
   endpointHost:'fetch'+code+'.example.invalid',
   tlsPeerSpkiSha256:['7','8','9'][index].repeat(64)};
  sourcePins[role]=pin;
  sourceBytes[role]=index===2?revoked:archive;
  const statement={schemaVersion:1,kind:'UNTRUSTED_OFFLINE_SOURCE_RETRIEVAL',
   role,repository:REPO,...dxScope(e),
   contentSha256:hash(Buffer.from(sourceBytes[role],'base64')),
   ...pin,httpStatus:200,redirectCount:0,
   observedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',
   decision:'HOLD'};
  return {statement,publicKeyPem:kp.publicKeyPem,
   signature:sign(null,sourceSigningBytesDx(role,statement),
    kp.privateKey).toString('base64')};
 });
 const evidenceSetDigestSha256=evidenceSetDigestDx(
  sourceReceipts.map(packet=>packet.statement));
 const previousRecoveryAnchor={sequence:10,digestSha256:'d'.repeat(64)};
 const incident={schemaVersion:1,
  kind:'UNTRUSTED_SOURCE_FORK_FREEZE_REHEARSAL',incidentId:'incident_dx001',
  repository:REPO,...dxScope(e),evidenceSetDigestSha256,
  observedAt:'2026-11-20T23:59:55.000Z',decision:'FREEZE'};
 let nextDigest=previousRecoveryAnchor.digestSha256;
 const recoverySteps=DX_STAGES.map((stage,index)=>{
  const step={schemaVersion:1,kind:'UNTRUSTED_READ_ONLY_INCIDENT_STEP',
   incidentId:incident.incidentId,sequence:previousRecoveryAnchor.sequence+1+index,
   previousDigestSha256:nextDigest,stage,evidenceSetDigestSha256,
   challengeNonce:['a','b','c'][index].repeat(64),
   observedAt:'2026-11-20T23:59:'+String(56+index).padStart(2,'0')+'.000Z',
   decision:'HOLD'};
  nextDigest=recoveryStepDigestDx(step);
  return step;
 });
 const recoverySigners=DX_RECOVERY_ROLES.map((role,index)=>{
  const name=index===0?'legal':'security',kp=pair();
  privateKeys[role]=kp.privateKey;
  const pin={keyId:'key_dx_'+name+'01',
   spkiSha256:kp.spkiSha256,operatorId:'operator_dx_'+name+'01',
   operatorOrganizationId:'org_dx_'+name+'01'};
  recoveryPins[role]=pin;
  const statement={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_RECOVERY_REHEARSAL_ATTESTATION',
   role,repository:REPO,organizationId:e.organizationId,
   sourceHeadSha:e.sourceHeadSha,mainBaseSha:e.mainBaseSha,
   incidentId:incident.incidentId,evidenceSetDigestSha256,
   recoveryLedgerDigestSha256:nextDigest,
   previousRecoveryDigestSha256:previousRecoveryAnchor.digestSha256,
   recoverySequence:recoverySteps.at(-1).sequence,
   revocationDigestSha256:e.revocationDigestSha256,
   challengeNonce:e.challengeNonce,...pin,observedAt:NOW,
   expiresAt:'2026-11-21T00:10:00.000Z',decision:'REHEARSAL_ONLY_HOLD'};
  return {statement,publicKeyPem:kp.publicKeyPem,
   signature:sign(null,recoverySigningBytesDx(role,statement),
    kp.privateKey).toString('base64')};
 });
 return {args:{custodyCandidate:dw.args,sourceReceipts,sourcePins,sourceBytes,
  previousRecoveryAnchor,incident,recoverySteps,recoverySigners,
  recoveryPins,now:NOW},privateKeys,dw};
}
function dxResign(f,kind,index){
 const source=kind==='source',packet=f.args[source?'sourceReceipts':'recoverySigners'][index],
  role=packet.statement.role;
 packet.signature=sign(null,(source?sourceSigningBytesDx:recoverySigningBytesDx)(
  role,packet.statement),f.privateKeys[role]).toString('base64');
}
const dxAssess=f=>assessOfflineEvidenceIncidentRecoveryCandidate(f.args);
const dxHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.recoveryWasDryRunOnlyAndCannotThawRelease,true);
 assert.equal(r.productionMutationOrExternalEnrollmentPossible,false);
 assert.equal(r.independentlyAuthenticatedMcaLegalRegistryAndProviderAuthority,false);
 assert.equal(r.liveIssuerSignedCrLOrOcspAndCertificatePolicyAuthenticated,false);
};
test('1DX three locally supplied signed sources and two recovery signers agree mathematically under HOLD',()=>{
 const r=dxAssess(dxFixture());
 assert.equal(r.precedingDwSignatureHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.threeCandidateSourceRetrievalSignaturesMathematicallyVerifiedOnly,3);
 assert.equal(r.sourceByteHashesComparedToSubmittedSignedClaimsOnly,true);
 assert.equal(r.frozenRecoverySequenceLinkedMathematicallyOnly,true);
 assert.equal(r.twoRecoveryCustodianSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.candidateEvidenceAndFrozenRehearsalInternallyConsistentOnly,true);
 assert.deepEqual(r.anomalyCodes,[]);dxHold(r);
});
test('1DX each supplied primary/archive/revocation byte substitution is quarantined',()=>{
 for(const role of DX_SOURCES){
  const f=dxFixture();
  f.args.sourceBytes[role]=Buffer.from('forged data').toString('base64');
  const r=dxAssess(f);
  has(r,'DX_CANDIDATE_RETRIEVED_BYTES_MISMATCH');
  assert.equal(r.sourceByteHashesComparedToSubmittedSignedClaimsOnly,false);
  dxHold(r);
 }
});
test('1DX archive with valid hash but non-canonical claimed revocation bytes is rejected',()=>{
 const f=dxFixture(),role=DX_SOURCES[2],p=f.args.sourceReceipts[2];
 const original=Buffer.from(f.args.sourceBytes[role],'base64').toString('utf8');
 f.args.sourceBytes[role]=Buffer.from(original+'\n').toString('base64');
 p.statement.contentSha256=hash(Buffer.from(f.args.sourceBytes[role],'base64'));
 dxResign(f,'source',2);
 const r=dxAssess(f);
 assert.equal(r.threeCandidateSourceRetrievalSignaturesMathematicallyVerifiedOnly,3);
 has(r,'DX_CANDIDATE_RETRIEVED_BYTES_MISMATCH');dxHold(r);
});
test('1DX duplicated source signer or missing role cannot count as three independent receipts',()=>{
 const f=dxFixture();f.args.sourceReceipts[1]=clone(f.args.sourceReceipts[0]);
 const r=dxAssess(f);
 has(r,'DX_RETRIEVAL_ROLE_PACKET_INVALID');
 has(r,'DX_INCOMPLETE_SOURCE_ROLE_QUORUM');dxHold(r);
});
test('1DX correctly signed source GO, redirects or error HTTP status cannot be accepted',()=>{
 for(const [k,v] of [['decision','GO'],['redirectCount',1],
  ['httpStatus',302],['kind','AUTHENTICATED_EXTERNAL_SOURCE']]){
  const f=dxFixture();f.args.sourceReceipts[0].statement[k]=v;
  dxResign(f,'source',0);
  const r=dxAssess(f);
  has(r,'DX_SIGNED_RETRIEVAL_SCOPE_OR_HTTP_INVALID');dxHold(r);
 }
});
test('1DX source key ID, signed endpoint, TLS and operator must equal detached candidate pins',()=>{
 for(const [k,v] of [['keyId','counterfeit_id01'],
  ['endpointHost','evil.example.invalid'],
  ['tlsPeerSpkiSha256','f'.repeat(64)],
  ['operatorId','operator_spoof01']]){
  const f=dxFixture();f.args.sourceReceipts[0].statement[k]=v;
  dxResign(f,'source',0);
  const r=dxAssess(f);
  has(r,'DX_RETRIEVAL_DETACHED_PIN_MISMATCH');dxHold(r);
 }
});
test('1DX detached source signer SPKI and Ed25519 signature cannot be substituted',()=>{
 for(const change of ['signature','publicKeyPem']){
  const f=dxFixture();
  f.args.sourceReceipts[0][change]=f.args.sourceReceipts[1][change];
  const r=dxAssess(f);
  has(r,'DX_RETRIEVAL_SIGNATURE_OR_SPKI_INVALID');dxHold(r);
 }
});
test('1DX two source roles sharing operator, organization, TLS or endpoint remain untrusted',()=>{
 for(const attr of ['operatorId','operatorOrganizationId','spkiSha256',
  'keyId','endpointHost','tlsPeerSpkiSha256']){
  const f=dxFixture(),one=f.args.sourcePins[DX_SOURCES[0]];
  const two=f.args.sourcePins[DX_SOURCES[1]];
  two[attr]=one[attr];
  f.args.sourceReceipts[1].statement[attr]=one[attr];
  dxResign(f,'source',1);
  const r=dxAssess(f);
  has(r,'DX_INDEPENDENT_SOURCE_RECOVERY_PINS_UNPROVEN');dxHold(r);
 }
});
test('1DX endpoint or signer reused from old DV observer cannot be treated as new source',()=>{
 for(const attr of ['endpointHost','tlsPeerSpkiSha256','keyId','operatorId']){
  const f=dxFixture();
  const old=f.args.custodyCandidate.publicationCandidate.comparisonPins.CHECKPOINT_PUBLISHER;
  f.args.sourcePins[DX_SOURCES[0]][attr]=old[attr];
  f.args.sourceReceipts[0].statement[attr]=old[attr];dxResign(f,'source',0);
  const r=dxAssess(f);
  has(r,'DX_INDEPENDENT_SOURCE_RECOVERY_PINS_UNPROVEN');dxHold(r);
 }
});
test('1DX a previous custody private key cannot independently attest new source receipts',()=>{
 const f=dxFixture(),old=f.args.custodyCandidate.enrollmentPackets[0],
  pin=f.args.custodyCandidate.enrollmentPins[DW_ENROLLMENT_ROLES[0]];
 f.args.sourcePins[DX_SOURCES[0]].spkiSha256=pin.spkiSha256;
 f.args.sourceReceipts[0].statement.spkiSha256=pin.spkiSha256;
 f.args.sourceReceipts[0].publicKeyPem=old.publicKeyPem;
 f.privateKeys[DX_SOURCES[0]]=f.dw.privateKeys[DW_ENROLLMENT_ROLES[0]];
 dxResign(f,'source',0);
 const r=dxAssess(f);
 has(r,'DX_INDEPENDENT_SOURCE_RECOVERY_PINS_UNPROVEN');dxHold(r);
});
test('1DX a changed original 1DU/1DV/1DW history cannot be saved by new source signatures',()=>{
 const f=dxFixture();
 f.args.custodyCandidate.publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=dxAssess(f);
 has(r,'DX_PRECEDING_DW_NOT_REVERIFIED');dxHold(r);
});
test('1DX fake incident GO or signed evidence-set substitution is quarantined',()=>{
 for(const [key,value] of [['decision','GO'],
  ['evidenceSetDigestSha256','f'.repeat(64)],
  ['kind','AUTHORIZED_RECOVERY']]){
  const f=dxFixture();f.args.incident[key]=value;
  const r=dxAssess(f);
  has(r,'DX_INCIDENT_OR_PREVIOUS_RECOVERY_ANCHOR_INVALID');dxHold(r);
 }
});
test('1DX recovery chain cannot change historical predecessor high-watermark',()=>{
 for(const [key,value] of [['sequence',9],['digestSha256','e'.repeat(64)]]){
  const f=dxFixture();f.args.previousRecoveryAnchor[key]=value;
  const r=dxAssess(f);
  has(r,'DX_RECOVERY_STEP_REORDER_FORK_OR_UNFREEZE');
  has(r,'DX_READ_ONLY_RECOVERY_CHAIN_INVALID');dxHold(r);
 }
});
test('1DX broken, skipped, repeated or reversed recovery stages and nonces are rejected',()=>{
 for(const mutate of [
  f=>{f.args.recoverySteps.reverse();},
  f=>{f.args.recoverySteps[1].sequence+=1;},
  f=>{f.args.recoverySteps[1].stage='PRODUCTION_UNFREEZE';},
  f=>{f.args.recoverySteps[1].decision='GO';},
  f=>{f.args.recoverySteps[1].challengeNonce=f.args.recoverySteps[0].challengeNonce;},
  f=>{f.args.recoverySteps[1].observedAt=f.args.recoverySteps[0].observedAt;},
  f=>{f.args.recoverySteps[2].previousDigestSha256='f'.repeat(64);}
 ]){
  const f=dxFixture();mutate(f);
  const r=dxAssess(f);
  has(r,'DX_RECOVERY_STEP_REORDER_FORK_OR_UNFREEZE');dxHold(r);
 }
});
test('1DX fresh valid signature cannot approve rekeyed final ledger or a fake release GO',()=>{
 for(const [key,value] of [
  ['recoveryLedgerDigestSha256','f'.repeat(64)],
  ['decision','GO'],
  ['recoverySequence',100],
  ['sourceHeadSha','f'.repeat(40)],
  ['revocationDigestSha256','f'.repeat(64)],
  ['kind','EXTERNAL_INCIDENT_APPROVAL']
 ]){
  const f=dxFixture();f.args.recoverySigners[0].statement[key]=value;
  dxResign(f,'recovery',0);
  const r=dxAssess(f);
  has(r,'DX_SIGNED_REHEARSAL_SCOPE_OR_FORBIDDEN_THAW');dxHold(r);
 }
});
test('1DX duplicated or absent recovery custodian is not a two-party signature quorum',()=>{
 const f=dxFixture();
 f.args.recoverySigners[1]=clone(f.args.recoverySigners[0]);
 const r=dxAssess(f);
 has(r,'DX_RECOVERY_CUSTODIAN_ROLE_PACKET_INVALID');
 has(r,'DX_RECOVERY_SIGNER_QUORUM_INCOMPLETE');dxHold(r);
 const g=dxFixture();g.args.recoverySigners.pop();
 const b=dxAssess(g);has(b,'DX_TWO_EXACT_RECOVERY_CUSTODIANS_REQUIRED');dxHold(b);
});
test('1DX recovery signer key and detached pin drift remain denied despite re-signing',()=>{
 for(const key of ['keyId','operatorId','operatorOrganizationId','spkiSha256']){
  const f=dxFixture();
  f.args.recoverySigners[1].statement[key]=key==='spkiSha256'?
   'f'.repeat(64):'rogue_recovery01';
  dxResign(f,'recovery',1);
  const r=dxAssess(f);
  has(r,'DX_RECOVERY_CUSTODIAN_PIN_MISMATCH');dxHold(r);
 }
});
test('1DX a valid signature reused from another recovery role cannot pass',()=>{
 const f=dxFixture();
 f.args.recoverySigners[0].signature=f.args.recoverySigners[1].signature;
 const r=dxAssess(f);
 has(r,'DX_RECOVERY_SIGNATURE_OR_SPKI_INVALID');dxHold(r);
});
test('1DX expired or signed-before-rehearsal approval is not valid current custodian evidence',()=>{
 for(const [k,v] of [
  ['expiresAt','2026-11-20T23:59:59.000Z'],
  ['observedAt','2026-11-20T23:59:57.000Z']
 ]){
  const f=dxFixture();f.args.recoverySigners[1].statement[k]=v;
  dxResign(f,'recovery',1);
  const r=dxAssess(f);
  has(r,'DX_SIGNED_RECOVERY_STALE_OR_REORDERED');dxHold(r);
 }
});
test('1DX missing UTC clock or extra applicant claimed approvals are rejected early',()=>{
 let f=dxFixture();f.args.now=null;
 let r=dxAssess(f);
 has(r,'DX_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'DX_PRECEDING_DW_NOT_REVERIFIED');dxHold(r);
 f=dxFixture();
 r=assessOfflineEvidenceIncidentRecoveryCandidate({...f.args,approvedExternally:true});
 has(r,'DX_EXACT_BOUNDED_INPUT_REQUIRED');dxHold(r);
});
test('1DX source packets and recovery steps must have bounded exact schemata',()=>{
 const f=dxFixture();
 f.args.sourceReceipts[0].statement.isAuthenticatedExternal=true;
 const r=dxAssess(f);
 has(r,'DX_RETRIEVAL_ROLE_PACKET_INVALID');dxHold(r);
 const g=dxFixture();g.args.recoverySteps[0].objectLockAccepted=true;
 const b=dxAssess(g);
 has(b,'DX_RECOVERY_STEP_REORDER_FORK_OR_UNFREEZE');dxHold(b);
});
test('1DX synthetic authority cannot promote live CRL, MCA, TLS, WORM/DR or real staging acceptance',()=>{
 const r=dxAssess(dxFixture());
 assert.equal(r.independentlyEnrolledObserverOrRecoveryKeysAuthenticated,false);
 assert.equal(r.actualExternalPublicationAndTlsRetrievalAuthenticated,false);
 assert.equal(r.independentlyAuthenticatedMcaLegalRegistryAndProviderAuthority,false);
 assert.equal(r.liveIssuerSignedCrLOrOcspAndCertificatePolicyAuthenticated,false);
 assert.equal(r.independentWormCasDurableHighwatermarkAndDrRestoreAuthenticated,false);
 assert.equal(r.independentGithubNonauthorStagingAndIncidentApprovalVerified,false);
 dxHold(r);
});
test('1DX immutable redacted dry-run response excludes key IDs, nonces, private evidence and signatures',()=>{
 const f=dxFixture(),r=dxAssess(f),serialized=JSON.stringify(r);
 for(const sensitive of [
  f.args.sourceReceipts[0].signature,
  f.args.recoverySigners[0].publicKeyPem,
  f.args.sourcePins[DX_SOURCES[1]].keyId,
  f.args.incident.incidentId,
  f.args.recoverySteps[0].challengeNonce,
  f.args.sourceBytes[DX_SOURCES[0]],
  f.args.sourceBytes[DX_SOURCES[2]]
 ])assert.equal(serialized.includes(sensitive),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);dxHold(r);
});

/* Phase 1DY: applicant-provided external readiness status inventory,
 * two oversight receipts and three independent review-HOLD signatures.
 * Every source and clock is synthetic; NEVER a real external approval. */
import {DY_REQUIRED_GATES,DY_OVERSIGHT_ROLES,DY_REVIEW_ROLES,
 inventoryDigestDy,frozenCaseDigestDy,oversightSigningBytesDy,
 oversightSetDigestDy,reviewSigningBytesDy,
 assessOfflineAdmissionUnfreezePreconditionsDy}
 from '../scripts/phase1dy-offline-source-admission-unfreeze-preconditions.mjs';

function dyFixture(){
 const dx=dxFixture(),a=dx.args,e=a.custodyCandidate.publicationCandidate.expected;
 const authorityInventory=Object.fromEntries(DY_REQUIRED_GATES.map(g=>[
  g,{state:'MISSING',evidenceSha256:'0'.repeat(64),observedAt:null}
 ]));
 const previousObservationAnchor={sequence:5,digestSha256:'6'.repeat(64),
  observedAt:'2026-11-20T23:59:50.000Z'};
 const evidenceSetDigestSha256=evidenceSetDigestDx(DX_SOURCES.map(role=>
  a.sourceReceipts.find(p=>p.statement.role===role).statement));
 const recoveryLedgerDigestSha256=recoveryStepDigestDx(a.recoverySteps.at(-1));
 const decisionCase={schemaVersion:1,
  kind:'UNTRUSTED_INDEPENDENT_UNFREEZE_REVIEW_CASE',
  incidentId:a.incident.incidentId,repository:REPO,
  organizationId:e.organizationId,sourceHeadSha:e.sourceHeadSha,
  mainBaseSha:e.mainBaseSha,checkpointSha256:e.checkpointSha256,
  archiveSha256:e.archiveSha256,
  revocationDigestSha256:e.revocationDigestSha256,
  evidenceSetDigestSha256,recoveryLedgerDigestSha256,
  authorityInventorySha256:inventoryDigestDy(authorityInventory),
  previousObservationSha256:previousObservationAnchor.digestSha256,
  observationSequence:previousObservationAnchor.sequence+1,
  challengeNonce:e.challengeNonce,
  reviewNonce:hash('dy-review-candidate:'+e.challengeNonce),
  frozenAt:a.recoverySteps.at(-1).observedAt,decision:'REMAINS_FROZEN'};
 const oversightPins={},reviewPins={},privateKeys={};
 const base={repository:REPO,organizationId:e.organizationId,
  sourceHeadSha:e.sourceHeadSha,mainBaseSha:e.mainBaseSha,
  incidentId:decisionCase.incidentId,
  evidenceSetDigestSha256,recoveryLedgerDigestSha256,
  authorityInventorySha256:decisionCase.authorityInventorySha256,
  caseDigestSha256:frozenCaseDigestDy(decisionCase),
  previousObservationSha256:decisionCase.previousObservationSha256,
  observationSequence:decisionCase.observationSequence,
  challengeNonce:e.challengeNonce,reviewNonce:decisionCase.reviewNonce};
 const make=(roles,pins,kind,disposition,signBytes,extra=()=>({}))=>
  roles.map((role,index)=>{
   const kp=pair(),suffix='dy_'+(roles===DY_OVERSIGHT_ROLES?'oversight':'review')+index;
   privateKeys[role]=kp.privateKey;
   const pin={keyId:'key_'+suffix+'01',spkiSha256:kp.spkiSha256,
    operatorId:'operator_'+suffix+'01',
    custodianOrganizationId:'org_'+suffix+'01'};
   pins[role]=pin;
   const statement={schemaVersion:1,kind,role,...base,
    ...pin,observedAt:NOW,expiresAt:'2026-11-21T00:10:00.000Z',
    disposition,...extra()};
   return {statement,publicKeyPem:kp.publicKeyPem,
    signature:sign(null,signBytes(role,statement),
     kp.privateKey).toString('base64')};
  });
 const oversightPackets=make(DY_OVERSIGHT_ROLES,oversightPins,
  'UNTRUSTED_OFFLINE_FROZEN_SOURCE_OVERSIGHT','OBSERVE_FROZEN_ONLY',
  oversightSigningBytesDy);
 const oversightSetDigestSha256=oversightSetDigestDy(
  oversightPackets.map(p=>p.statement));
 const reviewPackets=make(DY_REVIEW_ROLES,reviewPins,
  'UNTRUSTED_OFFLINE_INDEPENDENT_REVIEW_HOLD','REVIEW_HOLD_ONLY',
  reviewSigningBytesDy,()=>({oversightSetDigestSha256}));
 return {args:{rehearsalCandidate:dx.args,authorityInventory,
  previousObservationAnchor,decisionCase,oversightPins,oversightPackets,
  reviewPins,reviewPackets,now:NOW},privateKeys,dx};
}
function dyResign(f,kind,index){
 const oversight=kind==='oversight',p=f.args[
  oversight?'oversightPackets':'reviewPackets'][index];
 const fn=oversight?oversightSigningBytesDy:reviewSigningBytesDy;
 p.signature=sign(null,fn(p.statement.role,p.statement),
  f.privateKeys[p.statement.role]).toString('base64');
}
function dyResignCompleteInventory(f){
 const a=f.args,c=a.decisionCase;
 c.authorityInventorySha256=inventoryDigestDy(a.authorityInventory);
 const caseDigestSha256=frozenCaseDigestDy(c);
 a.oversightPackets.forEach((p,i)=>{
  p.statement.authorityInventorySha256=c.authorityInventorySha256;
  p.statement.caseDigestSha256=caseDigestSha256;
  dyResign(f,'oversight',i);
 });
 const oversightSetDigestSha256=oversightSetDigestDy(
  a.oversightPackets.map(p=>p.statement));
 a.reviewPackets.forEach((p,i)=>{
  p.statement.authorityInventorySha256=c.authorityInventorySha256;
  p.statement.caseDigestSha256=caseDigestSha256;
  p.statement.oversightSetDigestSha256=oversightSetDigestSha256;
  dyResign(f,'review',i);
 });
}
const dyAssess=f=>assessOfflineAdmissionUnfreezePreconditionsDy(f.args);
const dyHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualProductionUnfreezeOrAutomaticReleasePossible,false);
 assert.equal(r.currentExternalIndependentTrustGatesAuthenticated,0);
 assert.equal(r.genuineProviderAgreementCredentialsAndIssuerTrustVerified,false);
 assert.equal(r.protectedMainNonauthorStagingAndDrAcceptanceVerified,false);
};
test('1DY 12 missing authority gates and five valid synthetic HOLD signers NEVER authorize',()=>{
 const r=dyAssess(dyFixture());
 assert.equal(r.precedingDxDwDvDuFullOriginalHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.authorityPrerequisiteSlotsInspected,12);
 assert.equal(r.authorityPrerequisitesMissing,12);
 assert.equal(r.authorityPrerequisitesPresentButNotAuthenticated,0);
 assert.equal(r.dualOversightObservationsSignedMathematicallyOnly,2);
 assert.equal(r.tripleIndependentReviewHoldSignaturesMathematicallyOnly,3);
 assert.equal(r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly,true);
 assert.deepEqual(r.anomalyCodes,[]);dyHold(r);
});
test('1DY present-but-unverified 12 prerequisites remain legally and technically untrusted',()=>{
 const f=dyFixture();
 DY_REQUIRED_GATES.forEach((g,i)=>{
  f.args.authorityInventory[g]={state:'PRESENT_UNVERIFIED',
   evidenceSha256:hash('synthetic-evidence:'+g+':'+i),observedAt:NOW};
 });
 dyResignCompleteInventory(f);
 const r=dyAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.authorityPrerequisitesMissing,0);
 assert.equal(r.authorityPrerequisitesPresentButNotAuthenticated,12);
 assert.equal(r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly,true);
 assert.equal(r.currentExternalIndependentTrustGatesAuthenticated,0);
 dyHold(r);
});
test('1DY mix of missing, rejected and present unverified preserves hold and counts',()=>{
 const f=dyFixture(),g=DY_REQUIRED_GATES;
 f.args.authorityInventory[g[0]]={state:'REJECTED',
  evidenceSha256:hash('rejected-fixture'),observedAt:NOW};
 f.args.authorityInventory[g[1]]={state:'PRESENT_UNVERIFIED',
  evidenceSha256:hash('unverified-fixture'),observedAt:NOW};
 dyResignCompleteInventory(f);
 const r=dyAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.authorityPrerequisitesMissing,10);
 assert.equal(r.authorityPrerequisitesRejected,1);
 assert.equal(r.authorityPrerequisitesPresentButNotAuthenticated,1);
 dyHold(r);
});
test('1DY forged VERIFIED or APPROVED external gate flag is not admitted by schema',()=>{
 for(const state of ['VERIFIED','APPROVED','PRODUCTION_READY']){
  const f=dyFixture(),g=DY_REQUIRED_GATES[0];
  f.args.authorityInventory[g].state=state;
  const r=dyAssess(f);
  has(r,'DY_EXACT_AUTHORITY_PREREQUISITE_STATUSES_REQUIRED');dyHold(r);
 }
});
test('1DY malformed missing evidence digest and unverified missing timestamp fail',()=>{
 for(const edit of [
  g=>{g.evidenceSha256='f'.repeat(64);},
  g=>{g.observedAt=NOW;},
  g=>{g.state='PRESENT_UNVERIFIED';},
  g=>{g.providerApproved=true;}
 ]){
  const f=dyFixture();edit(f.args.authorityInventory[DY_REQUIRED_GATES[0]]);
  const r=dyAssess(f);
  has(r,'DY_EXACT_AUTHORITY_PREREQUISITE_STATUSES_REQUIRED');dyHold(r);
 }
});
test('1DY independently signed inventory drift triggers failed frozen case binding',()=>{
 const f=dyFixture(),g=DY_REQUIRED_GATES[0];
 f.args.authorityInventory[g]={state:'PRESENT_UNVERIFIED',
  evidenceSha256:hash('other-authority-scope'),observedAt:NOW};
 const r=dyAssess(f);
 has(r,'DY_FROZEN_CASE_SCOPE_SEQUENCE_OR_THAW_INVALID');
 assert.equal(r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly,false);
 dyHold(r);
});
test('1DY future observed gate is invalid even when entirely re-signed by synthetic reviewers',()=>{
 const f=dyFixture(),g=DY_REQUIRED_GATES[0];
 f.args.authorityInventory[g]={state:'PRESENT_UNVERIFIED',
  evidenceSha256:hash('future-synthetic-gate'),
  observedAt:'2026-11-21T00:10:00.000Z'};
 dyResignCompleteInventory(f);
 const r=dyAssess(f);
 has(r,'DY_GATE_TIME_CLAIM_INVALID');dyHold(r);
});
test('1DY authority inventory missing/extra role or unbounded header cannot be admitted',()=>{
 let f=dyFixture();
 delete f.args.authorityInventory[DY_REQUIRED_GATES[0]];
 let r=dyAssess(f);
 has(r,'DY_EXACT_AUTHORITY_PREREQUISITE_STATUSES_REQUIRED');dyHold(r);
 f=dyFixture();f.args.authorityInventory.UNKNOWN_AUTHORITY={
  state:'MISSING',evidenceSha256:'0'.repeat(64),observedAt:null};
 r=dyAssess(f);
 has(r,'DY_EXACT_AUTHORITY_PREREQUISITE_STATUSES_REQUIRED');dyHold(r);
});
test('1DY no cloned oversight key, operator, organization or SPKI across five roles',()=>{
 for(const attr of ['keyId','operatorId','custodianOrganizationId','spkiSha256']){
  const f=dyFixture(),source=f.args.oversightPins[DY_OVERSIGHT_ROLES[0]];
  const other=f.args.reviewPins[DY_REVIEW_ROLES[0]];
  other[attr]=source[attr];f.args.reviewPackets[0].statement[attr]=source[attr];
  dyResign(f,'review',0);
  const r=dyAssess(f);
  has(r,'DY_NEW_INDEPENDENT_ROLE_PINS_UNPROVEN');dyHold(r);
 }
});
test('1DY prior DX recovery signer key reuse cannot become independent review',()=>{
 const f=dyFixture(),role=DY_REVIEW_ROLES[0],dxRole=DX_RECOVERY_ROLES[0];
 const old=f.args.rehearsalCandidate.recoveryPins[dxRole];
 const p=f.args.reviewPackets[0];
 p.statement.spkiSha256=old.spkiSha256;
 f.args.reviewPins[role].spkiSha256=old.spkiSha256;
 p.publicKeyPem=f.args.rehearsalCandidate.recoverySigners[0].publicKeyPem;
 f.privateKeys[role]=f.dx.privateKeys[dxRole];
 dyResign(f,'review',0);
 const r=dyAssess(f);
 has(r,'DY_NEW_INDEPENDENT_ROLE_PINS_UNPROVEN');dyHold(r);
});
test('1DY prior Legal witness re-enrolled with new role cannot impersonate oversight',()=>{
 const f=dyFixture(),role=DY_OVERSIGHT_ROLES[0],old=keys.LEGAL_WITNESS.next;
 f.args.oversightPins[role].spkiSha256=old.spkiSha256;
 f.args.oversightPackets[0].statement.spkiSha256=old.spkiSha256;
 f.args.oversightPackets[0].publicKeyPem=old.publicKeyPem;
 f.privateKeys[role]=old.privateKey;dyResign(f,'oversight',0);
 const r=dyAssess(f);
 has(r,'DY_NEW_INDEPENDENT_ROLE_PINS_UNPROVEN');dyHold(r);
});
test('1DY signed dual-oversight candidate split-view source digest is quarantined',()=>{
 const f=dyFixture();
 f.args.oversightPackets[1].statement.evidenceSetDigestSha256='f'.repeat(64);
 dyResign(f,'oversight',1);
 const r=dyAssess(f);
 assert.equal(r.dualOversightObservationsSignedMathematicallyOnly,2);
 has(r,'DY_OVERSIGHT_CASE_SCOPE_OR_DISPOSITION_MISMATCH');dyHold(r);
});
test('1DY oversight role cloning or missing independent view fails two-party quorum',()=>{
 const f=dyFixture();
 f.args.oversightPackets[1]=clone(f.args.oversightPackets[0]);
 const r=dyAssess(f);
 has(r,'DY_OVERSIGHT_ROLE_PACKET_INVALID');
 has(r,'DY_OVERSIGHT_QUORUM_INCOMPLETE');dyHold(r);
 const g=dyFixture();g.args.oversightPackets.pop();
 const b=dyAssess(g);
 has(b,'DY_TWO_EXACT_OVERSIGHT_PACKETS_REQUIRED');dyHold(b);
});
test('1DY copied Ed25519 oversight signature and PEM substitutions cannot pass',()=>{
 for(const k of ['publicKeyPem','signature']){
  const f=dyFixture();
  f.args.oversightPackets[0][k]=f.args.oversightPackets[1][k];
  const r=dyAssess(f);
  has(r,'DY_OVERSIGHT_SIGNATURE_OR_SPKI_INVALID');dyHold(r);
 }
});
test('1DY signed oversight GO, role change or expired receipt never attains quorum',()=>{
 for(const [key,value,code] of [
  ['disposition','GO','DY_OVERSIGHT_CASE_SCOPE_OR_DISPOSITION_MISMATCH'],
  ['kind','VERIFIED_REAL_EXTERNAL_OPERATOR','DY_OVERSIGHT_CASE_SCOPE_OR_DISPOSITION_MISMATCH'],
  ['expiresAt','2026-11-20T23:59:59.000Z','DY_OVERSIGHT_STALE_OR_PRE_FREEZE'],
  ['caseDigestSha256','f'.repeat(64),'DY_OVERSIGHT_CASE_SCOPE_OR_DISPOSITION_MISMATCH']
 ]){
  const f=dyFixture();
  f.args.oversightPackets[0].statement[key]=value;
  dyResign(f,'oversight',0);
  const r=dyAssess(f);has(r,code);dyHold(r);
 }
});
test('1DY stale prior observation anchor, rollback and signed sequence fork cannot pass',()=>{
 for(const edit of [
  f=>{f.args.previousObservationAnchor.sequence=1;},
  f=>{f.args.previousObservationAnchor.digestSha256='f'.repeat(64);},
  f=>{f.args.previousObservationAnchor.observedAt='2026-11-20T23:59:59.000Z';},
  f=>{f.args.previousObservationAnchor.observedAt='2026-11-19T00:00:00.000Z';},
  f=>{f.args.decisionCase.observationSequence+=1;}
 ]){
  const f=dyFixture();edit(f);
  const r=dyAssess(f);
  has(r,'DY_FROZEN_CASE_SCOPE_SEQUENCE_OR_THAW_INVALID');dyHold(r);
 }
});
test('1DY signed unfreeze decision is quarantined even if five new keys re-sign paperwork',()=>{
 for(const [key,val] of [
  ['decision','GO'],
  ['kind','AUTHENTICATED_UNFREEZE_APPROVAL'],
  ['challengeNonce','d'.repeat(64)],
  ['reviewNonce','0'.repeat(64)],
  ['frozenAt','2026-11-20T23:59:57.000Z'],
  ['sourceHeadSha','f'.repeat(40)]
 ]){
  const f=dyFixture();f.args.decisionCase[key]=val;
  const r=dyAssess(f);
  has(r,'DY_FROZEN_CASE_SCOPE_SEQUENCE_OR_THAW_INVALID');dyHold(r);
 }
});
test('1DY independently signed three-role review split-view is quarantined',()=>{
 for(const [field,value] of [
  ['oversightSetDigestSha256','f'.repeat(64)],
  ['authorityInventorySha256','f'.repeat(64)],
  ['recoveryLedgerDigestSha256','f'.repeat(64)],
  ['caseDigestSha256','f'.repeat(64)],
  ['disposition','UNFREEZE'],
  ['kind','LIVE_RELEASE_APPROVAL']
 ]){
  const f=dyFixture();
  f.args.reviewPackets[1].statement[field]=value;
  dyResign(f,'review',1);
  const r=dyAssess(f);
  has(r,'DY_REVIEW_CASE_SCOPE_OR_FORBIDDEN_UNFREEZE');dyHold(r);
 }
});
test('1DY cloned role, missing Operations and reused review signature cannot count as three',()=>{
 const f=dyFixture();
 f.args.reviewPackets[2]=clone(f.args.reviewPackets[0]);
 let r=dyAssess(f);
 has(r,'DY_REVIEW_ROLE_PACKET_INVALID');
 has(r,'DY_REVIEW_QUORUM_INCOMPLETE');dyHold(r);
 const g=dyFixture();g.args.reviewPackets.pop();
 r=dyAssess(g);
 has(r,'DY_THREE_EXACT_REVIEW_HOLD_PACKETS_REQUIRED');dyHold(r);
 const h=dyFixture();
 h.args.reviewPackets[2].signature=h.args.reviewPackets[0].signature;
 r=dyAssess(h);has(r,'DY_REVIEW_SIGNATURE_OR_SPKI_INVALID');dyHold(r);
});
test('1DY valid detached review signature with key/identity drift fails source pins',()=>{
 for(const attr of ['keyId','operatorId','custodianOrganizationId','spkiSha256']){
  const f=dyFixture();
  f.args.reviewPackets[1].statement[attr]=attr==='spkiSha256'?
   'a'.repeat(64):'malicious_review01';
  dyResign(f,'review',1);
  const r=dyAssess(f);
  has(r,'DY_REVIEW_DETACHED_PIN_MISMATCH');dyHold(r);
 }
});
test('1DY review signed before source oversight or expiry fails cryptographic chronology',()=>{
 for(const [key,val] of [
  ['observedAt','2026-11-20T23:59:59.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z']
 ]){
  const f=dyFixture();
  f.args.reviewPackets[0].statement[key]=val;
  dyResign(f,'review',0);
  const r=dyAssess(f);
  has(r,'DY_REVIEW_STALE_OR_PRE_OVERSIGHT');dyHold(r);
 }
});
test('1DY previous DU-DX original history tampering is never fixed by new committee signatures',()=>{
 const f=dyFixture();
 f.args.rehearsalCandidate.custodyCandidate.publicationCandidate.history
  .epochs[0].checkpointObservations[0].manifest.decision='GO';
 const r=dyAssess(f);
 has(r,'DY_PRECEDING_DX_OR_HISTORY_NOT_REVERIFIED');dyHold(r);
});
test('1DY missing UTC reference and unknown approval extension fail early with safe HOLD',()=>{
 let f=dyFixture();f.args.now=null;
 let r=dyAssess(f);
 has(r,'DY_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'DY_PRECEDING_DX_OR_HISTORY_NOT_REVERIFIED');dyHold(r);
 f=dyFixture();
 r=assessOfflineAdmissionUnfreezePreconditionsDy({
  ...f.args,externalProviderApproved:true});
 has(r,'DY_EXACT_BOUNDED_INPUT_REQUIRED');dyHold(r);
});
test('1DY bounded exact reviewer, oversight and frozen-case schemata disallow hidden GO field',()=>{
 for(const add of [
  f=>{f.args.reviewPackets[0].statement.verifiedRelease=true;},
  f=>{f.args.oversightPackets[0].statement.verifiedExternalTLS=true;},
  f=>{f.args.decisionCase.authorizedByCCA=true;}
 ]){
  const f=dyFixture();add(f);
  const r=dyAssess(f);
  assert.ok(r.anomalyCodes.some(code=>code.startsWith('DY_')));
  assert.equal(r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly,false);
  dyHold(r);
 }
});
test('1DY output redacts keys, signatures, roles identity strings, incident and nonce',()=>{
 const f=dyFixture(),r=dyAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.reviewPackets[0].signature,
  f.args.oversightPackets[1].publicKeyPem,
  f.args.reviewPins[DY_REVIEW_ROLES[0]].keyId,
  f.args.decisionCase.incidentId,
  f.args.decisionCase.reviewNonce,
  f.args.rehearsalCandidate.sourceBytes[DX_SOURCES[0]]
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);dyHold(r);
});

test('1DY malformed upstream array methods cannot crash evaluator or grant release',()=>{
 const f=dyFixture();
 f.args.rehearsalCandidate={now:NOW,
  recoverySteps:{at:42},custodyCandidate:{publicationCandidate:{}},
  sourceReceipts:[]};
 const r=dyAssess(f);
 has(r,'DY_PRECEDING_DX_OR_HISTORY_NOT_REVERIFIED');
 assert.equal(r.candidateFrozenCaseAndReviewScopesCorrelatedMathematicallyOnly,false);
 dyHold(r);
});
test('1DY cyclical and oversized input never bypass exact bounded denial',()=>{
 const f=dyFixture(),cyclic={...f.args};
 cyclic.rehearsalCandidate={...cyclic.rehearsalCandidate};
 cyclic.rehearsalCandidate.selfReference=cyclic;
 let r=assessOfflineAdmissionUnfreezePreconditionsDy(cyclic);
 has(r,'DY_EXACT_BOUNDED_INPUT_REQUIRED');dyHold(r);
 const oversized=dyFixture();
 oversized.args.rehearsalCandidate.oversizedNestedBlob='x'.repeat(1536*1024);
 r=dyAssess(oversized);
 has(r,'DY_EXACT_BOUNDED_INPUT_REQUIRED');dyHold(r);
});

/* Phase 1DZ: applicant-only, offline cross-epoch anchor, dual signed
 * candidate observer views and Legal/Security retention-HOLD signatures.
 * NEVER external gossip, WORM, actual DR or production release proof. */
import {DZ_ANCHOR_ROLES,DZ_CUSTODY_ROLES,
 evidenceBundleBytesDz,anchorDigestDz,anchorSigningBytesDz,
 custodySigningBytesDz,assessOfflineCrossEpochAnchorCustodyDz}
 from '../scripts/phase1dz-offline-cross-epoch-anchor-custody.mjs';
function dzFixture(){
 const dy=dyFixture(),d=dy.args,c=d.decisionCase,
  e=d.rehearsalCandidate.custodyCandidate.publicationCandidate.expected;
 const previousAnchor={sequence:c.observationSequence,
  digestSha256:frozenCaseDigestDy(c),observedAt:NOW};
 const evidenceBundleBase64=evidenceBundleBytesDz(d).toString('base64');
 const bundleSha=hash(Buffer.from(evidenceBundleBase64,'base64'));
 const anchorPins={},custodyPins={},privateKeys={},pairPems={};
 const makePin=(role,index)=>{
  const kp=pair();
  privateKeys[role]=kp.privateKey;pairPems[role]=kp.publicKeyPem;
  return {key:{privateKey:kp.privateKey,publicKeyPem:kp.publicKeyPem},
   pin:{keyId:'key_dz_'+index+'001',spkiSha256:kp.spkiSha256,
    operatorId:'operator_dz_'+index+'001',
    custodianOrganizationId:'org_dz_'+index+'001'}};
 };
 DZ_ANCHOR_ROLES.forEach((role,i)=>{
  anchorPins[role]=makePin(role,i).pin;
 });
 DZ_CUSTODY_ROLES.forEach((role,i)=>{
  custodyPins[role]=makePin(role,i+2).pin;
 });
 let previousHash=previousAnchor.digestSha256,prevSeq=previousAnchor.sequence;
 const epochs=Array.from({length:3},(_,index)=>{
  const sec=String(index+1).padStart(2,'0');
  const record={schemaVersion:1,kind:'UNTRUSTED_OFFLINE_CROSS_EPOCH_ANCHOR',
   repository:REPO,incidentId:c.incidentId,organizationId:e.organizationId,
   sourceHeadSha:e.sourceHeadSha,mainBaseSha:e.mainBaseSha,
   checkpointSha256:e.checkpointSha256,archiveSha256:e.archiveSha256,
   revocationDigestSha256:e.revocationDigestSha256,
   authorityInventorySha256:c.authorityInventorySha256,
   frozenCaseSha256:previousAnchor.digestSha256,
   sourceSetDigestSha256:c.evidenceSetDigestSha256,
   recoveryLedgerDigestSha256:c.recoveryLedgerDigestSha256,
   previousSequence:prevSeq,sequence:prevSeq+1,
   previousDigestSha256:previousHash,evidenceBundleSha256:bundleSha,
   nonce:hash('dz_anchor_nonce_'+index),
   observedAt:'2026-11-21T00:00:'+sec+'.000Z',decision:'HOLD'};
  const digest=anchorDigestDz(record);
  const observerPackets=DZ_ANCHOR_ROLES.map(role=>{
   const p=anchorPins[role];
   const statement={...record,role,...p,anchorDigestSha256:digest,
    expiresAt:'2026-11-21T00:10:00.000Z',
    disposition:'OBSERVE_HOLD_ONLY'};
   const signature=sign(null,anchorSigningBytesDz(role,statement),
    privateKeys[role]).toString('base64');
   const publicKeyPem=pairPems[role];
   return {statement,publicKeyPem,signature};
  });
  previousHash=digest;prevSeq=record.sequence;
  return {record,observerPackets};
 });
 const custodyPackets=DZ_CUSTODY_ROLES.map(role=>{
  const pin=custodyPins[role];
  const statement={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_EVIDENCE_RETENTION_CANDIDATE',
   role,repository:REPO,incidentId:c.incidentId,
   organizationId:e.organizationId,sourceHeadSha:e.sourceHeadSha,
   mainBaseSha:e.mainBaseSha,
   previousAnchorSha256:previousAnchor.digestSha256,
   finalAnchorSha256:previousHash,finalSequence:prevSeq,
   evidenceBundleSha256:bundleSha,
   authorityInventorySha256:c.authorityInventorySha256,
   sourceSetDigestSha256:c.evidenceSetDigestSha256,
   challengeNonce:c.reviewNonce,...pin,
   observedAt:'2026-11-21T00:00:04.000Z',
   expiresAt:'2026-11-21T00:10:00.000Z',
   retentionUntil:'2027-01-01T00:00:00.000Z',
   disposition:'RETAIN_HOLD_NO_DELETE'};
  return {statement,publicKeyPem:pairPems[role],
   signature:sign(null,custodySigningBytesDz(role,statement),
    privateKeys[role]).toString('base64')};
 });
 return {args:{admissionCandidate:d,previousAnchor,epochs,anchorPins,
  evidenceBundleBase64,custodyPins,custodyPackets,now:NOW},
  privateKeys,dy};
}

function dzResign(f,kind,index,which=0){
 const isAnchor=kind==='anchor',p=isAnchor?
  f.args.epochs[index].observerPackets[which]:f.args.custodyPackets[index];
 const role=p.statement.role,fn=isAnchor?
  anchorSigningBytesDz:custodySigningBytesDz;
 p.signature=sign(null,fn(role,p.statement),
  f.privateKeys[role]).toString('base64');
}
const dzAssess=f=>assessOfflineCrossEpochAnchorCustodyDz(f.args);
const dzHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.safeProductionSourceThawPossible,false);
 assert.equal(r.actualCrossSystemForkAbsenceOrGossipAuthenticated,false);
 assert.equal(r.externalWormRetentionOrObjectLockDenialTestVerified,false);
 assert.equal(r.independentlyPersistedAntiRollbackHighwatermarkVerified,false);
 assert.equal(r.productionMutationOrExternalCredentialEnrollmentPossible,false);
};
test('1DZ three contiguous synthetic epochs and two signed custody HOLD receipts are never authorization',()=>{
 const f=dzFixture(),r=dzAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.previousDuToDyOriginalSignedHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.locallyLinkedCandidateAnchorEpochs,3);
 assert.equal(r.mathematicallyVerifiedEpochWitnessSignatures,6);
 assert.equal(r.mathematicallyVerifiedRetentionCustodySignatures,2);
 assert.equal(r.suppliedEvidenceBundleBytesAgreeWithSourceDigestsOnly,true);
 assert.equal(r.candidateCrossEpochAndRetentionClaimsCorrelatedMathematicallyOnly,true);
 dzHold(r);
});
test('1DZ two-epoch minimum and four-epoch maximum bound',()=>{
 let f=dzFixture();
 f.args.epochs.pop();
 f.args.custodyPackets.forEach((p,i)=>{
  const final=f.args.epochs.at(-1);
  p.statement.finalAnchorSha256=anchorDigestDz(final.record);
  p.statement.finalSequence=final.record.sequence;
  p.statement.observedAt='2026-11-21T00:00:04.000Z';
  dzResign(f,'custody',i);
 });
 let r=dzAssess(f);
 assert.equal(r.candidateCrossEpochAndRetentionClaimsCorrelatedMathematicallyOnly,true);dzHold(r);
 f=dzFixture();f.args.epochs=[f.args.epochs[0]];
 r=dzAssess(f);has(r,'DZ_TWO_TO_FOUR_EXACT_EPOCHS_REQUIRED');dzHold(r);
});
test('1DZ fake signed multi-epoch GO cannot override HOLD',()=>{
 for(const [field,value] of [
  ['decision','GO'],['kind','AUTHORIZED_EXTERNAL_ANCHOR'],
  ['sourceHeadSha','f'.repeat(40)],['authorityInventorySha256','f'.repeat(64)]
 ]){
  const f=dzFixture(),e=f.args.epochs[0];
  e.record[field]=value;
  e.observerPackets.forEach((p,i)=>{
   p.statement[field]=value;p.statement.anchorDigestSha256=anchorDigestDz(e.record);
   dzResign(f,'anchor',0,i);
  });
  const r=dzAssess(f);
  has(r,'DZ_EPOCH_FORK_ROLLBACK_OR_SCOPE_MISMATCH');dzHold(r);
 }
});
test('1DZ independently signed archive witness fork contradicting another observer is quarantined',()=>{
 const f=dzFixture(),p=f.args.epochs[1].observerPackets[1];
 p.statement.anchorDigestSha256='f'.repeat(64);
 dzResign(f,'anchor',1,1);
 const r=dzAssess(f);
 assert.equal(r.mathematicallyVerifiedEpochWitnessSignatures,6);
 has(r,'DZ_SIGNED_CROSS_VIEW_EQUIVOCATION');dzHold(r);
});
test('1DZ full re-signing at duplicated epoch or skipped sequence remains a fork',()=>{
 for(const edit of [
  e=>{e.sequence=e.previousSequence;},
  e=>{e.sequence+=2;},
  e=>{e.previousSequence+=1;},
  e=>{e.previousDigestSha256='e'.repeat(64);}
 ]){
  const f=dzFixture(),e=f.args.epochs[1];edit(e.record);
  const digest=anchorDigestDz(e.record);
  e.observerPackets.forEach((p,i)=>{
   Object.assign(p.statement,e.record,{anchorDigestSha256:digest});
   dzResign(f,'anchor',1,i);
  });
  const r=dzAssess(f);
  has(r,'DZ_EPOCH_FORK_ROLLBACK_OR_SCOPE_MISMATCH');dzHold(r);
 }
});
test('1DZ reordering signed epochs and replaying nonce are denied',()=>{
 for(const action of [
  f=>{f.args.epochs.reverse();},
  f=>{f.args.epochs[1].record.nonce=f.args.epochs[0].record.nonce;}
 ]){
  const f=dzFixture();action(f);
  const r=dzAssess(f);
  has(r,'DZ_EPOCH_FORK_ROLLBACK_OR_SCOPE_MISMATCH');dzHold(r);
 }
});
test('1DZ previously accepted DY anchor cannot be replaced, rewound or re-dated',()=>{
 for(const edit of [
  p=>{p.sequence=5;},p=>{p.digestSha256='f'.repeat(64);},
  p=>{p.observedAt='2026-11-20T23:59:59.000Z';}
 ]){
  const f=dzFixture();edit(f.args.previousAnchor);
  const r=dzAssess(f);
  has(r,'DZ_PREVIOUS_ANCHOR_DY_CUSTODY_MISMATCH');dzHold(r);
 }
});
test('1DZ candidate retention cannot cover forged, blank, or swapped original evidence bytes',()=>{
 for(const change of [
  s=>Buffer.from('forged-evidence').toString('base64'),
  s=>'***invalid***',s=>s.slice(1)
 ]){
  const f=dzFixture();
  f.args.evidenceBundleBase64=change(f.args.evidenceBundleBase64);
  const r=dzAssess(f);
  has(r,'DZ_BUNDLE_BYTES_NOT_SOURCE_BOUND');dzHold(r);
 }
});
test('1DZ signer role copied from another role is not a witness quorum',()=>{
 const f=dzFixture();
 f.args.epochs[0].observerPackets[1]=clone(f.args.epochs[0].observerPackets[0]);
 const r=dzAssess(f);
 has(r,'DZ_EPOCH_OBSERVER_PACKET_INVALID');
 has(r,'DZ_EPOCH_WITNESS_QUORUM_INCOMPLETE');dzHold(r);
});
test('1DZ source witness key SPKI, operator and claimed organizations cannot collide',()=>{
 for(const field of ['keyId','spkiSha256','operatorId','custodianOrganizationId']){
  const f=dzFixture(),from=f.args.anchorPins[DZ_ANCHOR_ROLES[0]];
  f.args.custodyPins[DZ_CUSTODY_ROLES[0]][field]=from[field];
  f.args.custodyPackets[0].statement[field]=from[field];
  dzResign(f,'custody',0);
  const r=dzAssess(f);
  has(r,'DZ_ROLE_KEY_OPERATOR_OR_CUSTODY_COLLISION');dzHold(r);
 }
});
test('1DZ using prior DY review keys to endorse new anchor fails distinct custody gate',()=>{
 const f=dzFixture(),dyRole=DY_REVIEW_ROLES[0],dzRole=DZ_ANCHOR_ROLES[0];
 const original=f.args.admissionCandidate.reviewPackets[0];
 const pin=f.args.admissionCandidate.reviewPins[dyRole];
 f.args.anchorPins[dzRole].spkiSha256=pin.spkiSha256;
 f.args.epochs.forEach((ep,i)=>{
  const p=ep.observerPackets[0];p.statement.spkiSha256=pin.spkiSha256;
  p.publicKeyPem=original.publicKeyPem;
 });
 f.privateKeys[dzRole]=f.dy.privateKeys[dyRole];
 f.args.epochs.forEach((ep,i)=>dzResign(f,'anchor',i,0));
 const r=dzAssess(f);
 has(r,'DZ_ROLE_KEY_OPERATOR_OR_CUSTODY_COLLISION');dzHold(r);
});
test('1DZ valid detached key substitution or copied Ed25519 signature is not an authentic anchor',()=>{
 for(const field of ['signature','publicKeyPem']){
  const f=dzFixture();
  f.args.epochs[0].observerPackets[0][field]=
   f.args.epochs[0].observerPackets[1][field];
  const r=dzAssess(f);
  has(r,'DZ_EPOCH_SIGNATURE_OR_SPKI_INVALID');dzHold(r);
 }
});
test('1DZ earlier witness signature, expired epoch or invalid observer disposition fails',()=>{
 for(const [field,value,code] of [
  ['expiresAt','2026-11-20T23:59:59.000Z','DZ_EPOCH_WITNESS_TIME_OR_EXPIRY_INVALID'],
  ['disposition','GO','DZ_SIGNED_CROSS_VIEW_EQUIVOCATION'],
  ['role','ATTACKER_ANCHOR_ROLE','DZ_EPOCH_OBSERVER_PACKET_INVALID']
 ]){
  const f=dzFixture();
  f.args.epochs[0].observerPackets[0].statement[field]=value;
  if(field!=='role')dzResign(f,'anchor',0,0);
  const r=dzAssess(f);has(r,code);dzHold(r);
 }
});
test('1DZ signed delete, unfreeze or shortened retention remains rejected',()=>{
 for(const [field,value,code] of [
  ['disposition','DELETE_UNFREEZE','DZ_CUSTODY_FINAL_ANCHOR_OR_HOLD_SCOPE_INVALID'],
  ['retentionUntil','2026-11-21T00:10:00.000Z','DZ_CUSTODY_RETENTION_CLAIM_OR_CLOCK_INVALID'],
  ['finalAnchorSha256','f'.repeat(64),'DZ_CUSTODY_FINAL_ANCHOR_OR_HOLD_SCOPE_INVALID'],
  ['finalSequence',100,'DZ_CUSTODY_FINAL_ANCHOR_OR_HOLD_SCOPE_INVALID'],
  ['sourceHeadSha','f'.repeat(40),'DZ_CUSTODY_FINAL_ANCHOR_OR_HOLD_SCOPE_INVALID']
 ]){
  const f=dzFixture();
  f.args.custodyPackets[0].statement[field]=value;dzResign(f,'custody',0);
  const r=dzAssess(f);has(r,code);dzHold(r);
 }
});
test('1DZ two re-signed custodians disagree on retention duration and cannot claim consensus',()=>{
 const f=dzFixture();
 f.args.custodyPackets[1].statement.retentionUntil='2027-02-01T00:00:00.000Z';
 dzResign(f,'custody',1);
 const r=dzAssess(f);
 assert.equal(r.mathematicallyVerifiedRetentionCustodySignatures,2);
 has(r,'DZ_CUSTODY_RETENTION_SPLIT_VIEW');dzHold(r);
});
test('1DZ cloned custody packet, missing signer and copied signature rejected',()=>{
 let f=dzFixture();
 f.args.custodyPackets[1]=clone(f.args.custodyPackets[0]);
 let r=dzAssess(f);
 has(r,'DZ_CUSTODY_ROLE_PACKET_INVALID');
 has(r,'DZ_CUSTODY_SIGNER_QUORUM_INCOMPLETE');dzHold(r);
 f=dzFixture();f.args.custodyPackets.pop();
 r=dzAssess(f);has(r,'DZ_TWO_CUSTODY_HOLD_RECEIPTS_REQUIRED');dzHold(r);
 f=dzFixture();
 f.args.custodyPackets[0].signature=f.args.custodyPackets[1].signature;
 r=dzAssess(f);has(r,'DZ_CUSTODY_SIGNATURE_OR_SPKI_INVALID');dzHold(r);
});
test('1DZ valid source witness but supplied epoch outside time or signed next nonce conflicts',()=>{
 for(const [field,value] of [
  ['observedAt','2026-11-20T23:59:00.000Z'],
  ['nonce','0'.repeat(64)]
 ]){
  const f=dzFixture(),ep=f.args.epochs[0];
  ep.record[field]=value;
  ep.observerPackets.forEach((p,i)=>{
   p.statement[field]=value;
   p.statement.anchorDigestSha256=anchorDigestDz(ep.record);
   dzResign(f,'anchor',0,i);
  });
  const r=dzAssess(f);
  has(r,'DZ_EPOCH_FORK_ROLLBACK_OR_SCOPE_MISMATCH');dzHold(r);
 }
});
test('1DZ historical DU signer or DY evidence source forgery cannot become valid newer anchor',()=>{
 const f=dzFixture();
 f.args.admissionCandidate.rehearsalCandidate.custodyCandidate
  .publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=dzAssess(f);
 has(r,'DZ_DY_FULL_HISTORY_UNVERIFIED');dzHold(r);
});
test('1DZ unexpected approval extension, cyclic and oversized original candidates fail closed',()=>{
 const f=dzFixture();
 let r=assessOfflineCrossEpochAnchorCustodyDz({...f.args,releaseApproved:true});
 has(r,'DZ_EXACT_BOUNDED_INPUT_REQUIRED');dzHold(r);
 const cycle=dzFixture();cycle.args.admissionCandidate.cyclic=cycle.args;
 r=dzAssess(cycle);has(r,'DZ_EXACT_BOUNDED_INPUT_REQUIRED');dzHold(r);
 const big=dzFixture();big.args.admissionCandidate.extraData='x'.repeat(2048*1024);
 r=dzAssess(big);has(r,'DZ_EXACT_BOUNDED_INPUT_REQUIRED');dzHold(r);
});
test('1DZ oversized signed epoch statement and unexpected retained object-lock approval denied',()=>{
 let f=dzFixture();
 f.args.epochs[0].record.kind='x'.repeat(9000);
 let r=dzAssess(f);
 has(r,'DZ_EPOCH_RECORD_SCHEMA_INVALID');dzHold(r);
 f=dzFixture();f.args.custodyPackets[0].statement.actualObjectLockVerified=true;
 r=dzAssess(f);
 has(r,'DZ_CUSTODY_ROLE_PACKET_INVALID');dzHold(r);
});
test('1DZ output is immutable, metadata-only and cannot leak archive, nonce, SPKI or signature',()=>{
 const f=dzFixture(),r=dzAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.evidenceBundleBase64,
  f.args.epochs[0].record.nonce,
  f.args.epochs[1].observerPackets[0].signature,
  f.args.custodyPackets[1].publicKeyPem,
  f.args.custodyPins[DZ_CUSTODY_ROLES[0]].keyId,
  f.args.admissionCandidate.decisionCase.incidentId
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);dzHold(r);
});

/* Phase 1EA: synthetic three-party gossip views and two HOLD-only
 * freeze-review signatures. NOT authenticated external source retrieval. */
import {EA_PEER_ROLES,EA_FREEZE_ROLES,
 candidateEpochViewEa,epochViewDigestEa,admissionClaimDigestEa,
 peerSigningBytesEa,peerQuorumDigestEa,freezeSigningBytesEa,
 assessOfflineGossipAdmissionBoundaryEa}
 from '../scripts/phase1ea-offline-gossip-admission-boundary.mjs';

function eaFixture(){
 const dz=dzFixture(),d=dz.args,
  c=d.admissionCandidate.decisionCase,
  e=d.admissionCandidate.rehearsalCandidate.custodyCandidate
   .publicationCandidate.expected;
 const last=d.epochs.at(-1).record;
 const previousGossipCursor=clone(d.previousAnchor);
 const admissionClaim={
  kind:'UNTRUSTED_OFFLINE_ADMISSION_PREFLIGHT',
  sourceType:'APPLICANT_OFFLINE_SUBMISSION',
  trustStatus:'NOT_AUTHENTICATED',
  providerAuthorized:false,legalAuthorityVerified:false,
  liveIssuerRevocationAuthenticated:false,remoteArchiveRetrieved:false,
  wormCasRetentionVerified:false,independentStagingApproved:false,
  releaseApproved:false,decision:'HOLD'
 };
 const peerPins={},freezePins={},privateKeys={},publicPems={};
 function key(role,i){
  const kp=pair();
  privateKeys[role]=kp.privateKey;publicPems[role]=kp.publicKeyPem;
  return {keyId:'key_ea_'+i+'_001',spkiSha256:kp.spkiSha256,
   operatorId:'operator_ea_'+i+'_001',
   custodianOrganizationId:'org_ea_'+i+'_001'};
 }
 const view=candidateEpochViewEa(d),viewSha=epochViewDigestEa(view);
 const peerPackets=EA_PEER_ROLES.map((role,i)=>{
  const pin=key(role,i),observedAt='2026-11-21T00:00:0'+(i+4)+'.000Z';
  peerPins[role]=pin;
  const statement={schemaVersion:1,kind:'UNTRUSTED_OFFLINE_EPOCH_GOSSIP',
   role,repository:REPO,incidentId:c.incidentId,
   organizationId:e.organizationId,sourceHeadSha:e.sourceHeadSha,
   mainBaseSha:e.mainBaseSha,
   previousSequence:d.previousAnchor.sequence,
   previousAnchorSha256:d.previousAnchor.digestSha256,
   finalSequence:last.sequence,
   finalAnchorSha256:anchorDigestDz(last),
   evidenceBundleSha256:last.evidenceBundleSha256,
   authorityInventorySha256:c.authorityInventorySha256,
   epochViewSha256:viewSha,challengeNonce:hash('ea_challenge_nonce_'+role),
   ...pin,observedAt,expiresAt:'2026-11-21T00:10:00.000Z',
   decision:'HOLD'};
  return {statement,viewEpochs:clone(view),publicKeyPem:publicPems[role],
   signature:sign(null,peerSigningBytesEa(role,statement),
    privateKeys[role]).toString('base64')};
 });
 const quorumSha=peerQuorumDigestEa(peerPackets.map(p=>p.statement)),
  claimSha=admissionClaimDigestEa(admissionClaim);
 const freezePackets=EA_FREEZE_ROLES.map((role,i)=>{
  const pin=key(role,i+3),observedAt='2026-11-21T00:00:0'+(i+7)+'.000Z';
  freezePins[role]=pin;
  const statement={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_GOSSIP_ADMISSION_FREEZE',
   role,repository:REPO,incidentId:c.incidentId,
   organizationId:e.organizationId,sourceHeadSha:e.sourceHeadSha,
   mainBaseSha:e.mainBaseSha,finalSequence:last.sequence,
   finalAnchorSha256:anchorDigestDz(last),
   evidenceBundleSha256:last.evidenceBundleSha256,
   epochViewSha256:viewSha,peerQuorumSha256:quorumSha,
   admissionClaimSha256:claimSha,reviewNonce:c.reviewNonce,
   ...pin,observedAt,expiresAt:'2026-11-21T00:10:00.000Z',
   disposition:'CONTINUE_FREEZE_NO_AUTHORITY'};
  return {statement,publicKeyPem:publicPems[role],
   signature:sign(null,freezeSigningBytesEa(role,statement),
    privateKeys[role]).toString('base64')};
 });
 return {args:{anchorCandidate:d,previousGossipCursor,admissionClaim,
  peerPins,peerPackets,freezePins,freezePackets,now:NOW},
  privateKeys,publicPems,dz};
}
function eaResign(f,kind,i){
 const packet=f.args[kind==='peer'?'peerPackets':'freezePackets'][i];
 const role=packet.statement.role;
 const bytes=kind==='peer'?peerSigningBytesEa:freezeSigningBytesEa;
 packet.signature=sign(null,bytes(role,packet.statement),
  f.privateKeys[role]).toString('base64');
}
function eaRebindQuorum(f){
 const next=peerQuorumDigestEa(EA_PEER_ROLES.map(r=>
  f.args.peerPackets.find(p=>p.statement.role===r).statement));
 f.args.freezePackets.forEach((p,i)=>{
  p.statement.peerQuorumSha256=next;eaResign(f,'freeze',i);
 });
}
const eaAssess=f=>assessOfflineGossipAdmissionBoundaryEa(f.args);
const eaHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualHttpsGossipOrPublicationRetrievalPerformed,false);
 assert.equal(r.independentlyAuthenticatedExternalPeerEnrollment,false);
 assert.equal(r.actualOffPlatformCasWormObjectLockOrDurableCursorVerified,false);
 assert.equal(r.corporateMcaProviderMandateAndExternalReviewAuthenticated,false);
 assert.equal(r.productionIncidentUnfreezeOrSourceActivationPossible,false);
};
test('1EA three synthetic gossip views and two freeze signatures agree but never authorize',()=>{
 const r=eaAssess(eaFixture());
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.priorDzToDuOriginalHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.threeSignedCandidatePeerViewsMathematicallyVerifiedOnly,3);
 assert.equal(r.epochVectorClaimsAgreeWithReverifiedSourceOnly,true);
 assert.equal(r.twoFrozenAdmissionReviewSignaturesMathematicallyVerifiedOnly,2);
 assert.equal(r.localGossipReplayAndForkCandidateInternallyConsistentOnly,true);
 eaHold(r);
});
test('1EA signed independently forked gossip epoch digest fails even if issuer re-signs',()=>{
 const f=eaFixture(),p=f.args.peerPackets[1];
 p.viewEpochs[1].anchorDigestSha256='e'.repeat(64);
 p.statement.epochViewSha256=epochViewDigestEa(p.viewEpochs);
 eaResign(f,'peer',1);eaRebindQuorum(f);
 const r=eaAssess(f);
 assert.equal(r.threeSignedCandidatePeerViewsMathematicallyVerifiedOnly,3);
 assert.equal(r.twoFrozenAdmissionReviewSignaturesMathematicallyVerifiedOnly,2);
 has(r,'EA_SIGNED_PEER_EPOCH_FORK_OR_REPLAY');eaHold(r);
});
test('1EA peer cannot splice a past signed entry into current epoch transcript',()=>{
 for(const change of [
  v=>{v[2]=clone(v[1]);},
  v=>{v.reverse();},
  v=>{v[1].previousDigestSha256='e'.repeat(64);},
  v=>{v[2].nonceSha256=v[0].nonceSha256;}
 ]){
  const f=eaFixture(),p=f.args.peerPackets[2];
  change(p.viewEpochs);
  const r=eaAssess(f);
  has(r,'EA_SIGNED_PEER_EPOCH_FORK_OR_REPLAY');eaHold(r);
 }
});
test('1EA claimed gossip epoch truncation or missing vector is never full source corroboration',()=>{
 const f=eaFixture(),p=f.args.peerPackets[0];
 p.viewEpochs.pop();
 let r=eaAssess(f);
 has(r,'EA_SIGNED_PEER_EPOCH_FORK_OR_REPLAY');eaHold(r);
 p.viewEpochs=null;
 r=eaAssess(f);
 has(r,'EA_PEER_EPOCH_VECTOR_SCHEMA_INVALID');eaHold(r);
});
test('1EA peer with self-signed final anchor SHA fork cannot impersonate original source',()=>{
 const f=eaFixture(),p=f.args.peerPackets[0];
 p.statement.finalAnchorSha256='f'.repeat(64);
 eaResign(f,'peer',0);eaRebindQuorum(f);
 const r=eaAssess(f);
 has(r,'EA_PEER_SIGNED_SOURCE_OR_HOLD_SCOPE_INVALID');eaHold(r);
});
test('1EA previous untrusted gossip cursor cannot be rewound, substituted or shifted',()=>{
 for(const [field,value] of [
  ['sequence',1],['digestSha256','f'.repeat(64)],
  ['observedAt','2026-11-20T23:59:59.000Z']]){
  const f=eaFixture();f.args.previousGossipCursor[field]=value;
  const r=eaAssess(f);
  has(r,'EA_GOSSIP_CURSOR_REPLAY_ROLLBACK_OR_SUBSTITUTION');eaHold(r);
 }
});
test('1EA copied candidate gossip roles and absent third source are not independent quorum',()=>{
 let f=eaFixture();f.args.peerPackets[2]=clone(f.args.peerPackets[0]);
 let r=eaAssess(f);
 has(r,'EA_PEER_ROLE_OR_PACKET_SCHEMA_INVALID');
 has(r,'EA_PEER_ROLE_QUORUM_INCOMPLETE');eaHold(r);
 f=eaFixture();f.args.peerPackets.pop();
 r=eaAssess(f);
 has(r,'EA_THREE_EXACT_PEER_PACKETS_REQUIRED');eaHold(r);
});
test('1EA current gossip peer cannot claim a retired DZ anchor SPKI even with valid signature',()=>{
 const f=eaFixture(),prior=DZ_ANCHOR_ROLES[0],
  role=EA_PEER_ROLES[0];
 const earlier=f.args.anchorCandidate.epochs[0].observerPackets[0];
 const old=f.args.anchorCandidate.anchorPins[prior];
 f.args.peerPins[role].spkiSha256=old.spkiSha256;
 f.args.peerPackets[0].statement.spkiSha256=old.spkiSha256;
 f.args.peerPackets[0].publicKeyPem=earlier.publicKeyPem;
 f.privateKeys[role]=f.dz.privateKeys[prior];eaResign(f,'peer',0);
 const r=eaAssess(f);
 has(r,'EA_SIGNER_OPERATOR_OR_ORGANIZATION_COLLISION');eaHold(r);
});
test('1EA collisions across peers and freeze signers do not confer organization independence',()=>{
 for(const field of ['keyId','spkiSha256','operatorId','custodianOrganizationId']){
  const f=eaFixture(),pin=f.args.peerPins[EA_PEER_ROLES[0]];
  f.args.freezePins[EA_FREEZE_ROLES[0]][field]=pin[field];
  f.args.freezePackets[0].statement[field]=pin[field];
  eaResign(f,'freeze',0);
  const r=eaAssess(f);
  has(r,'EA_SIGNER_OPERATOR_OR_ORGANIZATION_COLLISION');eaHold(r);
 }
});
test('1EA re-signed gossip GO, false source identity or wrong prior anchor scope is denied',()=>{
 for(const [field,value] of [
  ['decision','GO'],['kind','TRUSTED_EXTERNAL_PROVIDER_GOSSIP'],
  ['sourceHeadSha','f'.repeat(40)],
  ['previousAnchorSha256','f'.repeat(64)],
  ['evidenceBundleSha256','f'.repeat(64)]
 ]){
  const f=eaFixture(),p=f.args.peerPackets[1];
  p.statement[field]=value;eaResign(f,'peer',1);eaRebindQuorum(f);
  const r=eaAssess(f);
  has(r,'EA_PEER_SIGNED_SOURCE_OR_HOLD_SCOPE_INVALID');eaHold(r);
 }
});
test('1EA repeated original signed nonce and copied peer nonce fail replay test',()=>{
 for(const nonce of ['0'.repeat(64),hash('ea_challenge_nonce_'+EA_PEER_ROLES[0])]){
  const f=eaFixture(),p=f.args.peerPackets[1];
  p.statement.challengeNonce=nonce;eaResign(f,'peer',1);eaRebindQuorum(f);
  const r=eaAssess(f);
  has(r,'EA_REPLAYED_PEER_CHALLENGE_NONCE');eaHold(r);
 }
});
test('1EA copied Ed25519 signature or fake public key cannot pass gossip source',()=>{
 for(const field of ['signature','publicKeyPem']){
  const f=eaFixture();
  f.args.peerPackets[0][field]=f.args.peerPackets[1][field];
  const r=eaAssess(f);
  has(r,'EA_PEER_ED25519_OR_SPKI_INVALID');eaHold(r);
 }
});
test('1EA signed peer TLS/authority spoof extension cannot become authenticated online retrieval',()=>{
 const f=eaFixture();
 f.args.peerPackets[0].statement.validatedLiveTls=true;
 const r=eaAssess(f);
 has(r,'EA_PEER_ROLE_OR_PACKET_SCHEMA_INVALID');eaHold(r);
});
test('1EA expired, premature or future gossip peer receipts are quarantined',()=>{
 for(const [key,value] of [
  ['observedAt','2026-11-21T00:00:02.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z'],
  ['observedAt','2026-11-21T00:10:00.000Z']
 ]){
  const f=eaFixture();
  f.args.peerPackets[0].statement[key]=value;eaResign(f,'peer',0);
  const r=eaAssess(f);
  has(r,'EA_PEER_FRESHNESS_OR_EXPIRY_INVALID');eaHold(r);
 }
});
test('1EA self reported authenticated provider, MCA, issuer CRL and production GO cannot be admitted',()=>{
 for(const field of ['providerAuthorized','legalAuthorityVerified',
  'liveIssuerRevocationAuthenticated','remoteArchiveRetrieved',
  'wormCasRetentionVerified','independentStagingApproved',
  'releaseApproved']){
  const f=eaFixture();f.args.admissionClaim[field]=true;
  const r=eaAssess(f);
  has(r,'EA_SELF_APPROVAL_OR_ADMISSION_CLAIM_INVALID');eaHold(r);
 }
});
test('1EA sourceType TRUSTED_REMOTE and admission status VERIFIED are always rejected',()=>{
 for(const [field,value] of [
  ['sourceType','AUTHENTICATED_REMOTE'],
  ['trustStatus','INDEPENDENTLY_VERIFIED'],
  ['decision','UNFREEZE'],
  ['kind','REAL_EXTERNAL_APPROVAL']]){
  const f=eaFixture();f.args.admissionClaim[field]=value;
  const r=eaAssess(f);
  has(r,'EA_SELF_APPROVAL_OR_ADMISSION_CLAIM_INVALID');eaHold(r);
 }
});
test('1EA applicant cannot add providerApproved flag to exact source admission contract',()=>{
 const f=eaFixture();
 f.args.admissionClaim.providerApproved=true;
 const r=eaAssess(f);
 has(r,'EA_SELF_APPROVAL_OR_ADMISSION_CLAIM_INVALID');eaHold(r);
});
test('1EA signed quarantine freeze receipt cannot mutate review disposition',()=>{
 for(const [field,value] of [
  ['disposition','PRODUCTION_UNFREEZE'],
  ['kind','AUTHORIZED_EXTERNAL_RELEASE'],
  ['peerQuorumSha256','f'.repeat(64)],
  ['admissionClaimSha256','f'.repeat(64)],
  ['finalAnchorSha256','f'.repeat(64)]
 ]){
  const f=eaFixture();
  f.args.freezePackets[0].statement[field]=value;eaResign(f,'freeze',0);
  const r=eaAssess(f);
  has(r,'EA_FREEZE_SIGNED_SOURCE_OR_UNFREEZE_FORBIDDEN');eaHold(r);
 }
});
test('1EA cloned freeze role and missing reviewer do not count as dual custody',()=>{
 let f=eaFixture();f.args.freezePackets[1]=clone(f.args.freezePackets[0]);
 let r=eaAssess(f);
 has(r,'EA_FREEZE_REVIEW_ROLE_OR_PACKET_INVALID');
 has(r,'EA_FREEZE_REVIEW_QUORUM_INCOMPLETE');eaHold(r);
 f=eaFixture();f.args.freezePackets.pop();
 r=eaAssess(f);
 has(r,'EA_TWO_EXACT_FREEZE_REVIEW_RECEIPTS_REQUIRED');eaHold(r);
});
test('1EA freeze reviewer signature key substitution or operator pin drift remains denied',()=>{
 let f=eaFixture();
 f.args.freezePackets[0].signature=f.args.freezePackets[1].signature;
 let r=eaAssess(f);has(r,'EA_FREEZE_ED25519_OR_SPKI_INVALID');eaHold(r);
 f=eaFixture();
 f.args.freezePackets[0].statement.operatorId='rogue_freeze_operator';
 eaResign(f,'freeze',0);
 r=eaAssess(f);has(r,'EA_FREEZE_REVIEW_KEY_PIN_MISMATCH');eaHold(r);
});
test('1EA freeze HOLD must be signed later than all three claimed gossip timestamps',()=>{
 for(const [field,value] of [
  ['observedAt','2026-11-21T00:00:05.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z']
 ]){
  const f=eaFixture();
  f.args.freezePackets[1].statement[field]=value;eaResign(f,'freeze',1);
  const r=eaAssess(f);
  has(r,'EA_FREEZE_REVIEW_STALE_OR_PRE_GOSSIP');eaHold(r);
 }
});
test('1EA original signed multi-epoch DZ or older Legal history mutation never becomes genuine gossip',()=>{
 const f=eaFixture();
 f.args.anchorCandidate.admissionCandidate.rehearsalCandidate
  .custodyCandidate.publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=eaAssess(f);
 has(r,'EA_DZ_FULL_SOURCE_NOT_REVERIFIED');eaHold(r);
});
test('1EA unauthorized extra top-level release flag, cyclic and oversized JSON fail closed',()=>{
 let f=eaFixture();
 let r=assessOfflineGossipAdmissionBoundaryEa({
  ...f.args,actualAuthorityVerified:true});
 has(r,'EA_EXACT_BOUNDED_INPUT_REQUIRED');eaHold(r);
 f=eaFixture();f.args.anchorCandidate.self=f.args;
 r=eaAssess(f);has(r,'EA_EXACT_BOUNDED_INPUT_REQUIRED');eaHold(r);
 f=eaFixture();
 f.args.anchorCandidate.extra='x'.repeat(2560*1024);
 r=eaAssess(f);has(r,'EA_EXACT_BOUNDED_INPUT_REQUIRED');eaHold(r);
});
test('1EA malformed signed view payload and missing reference UTC are immutable HOLD not crash',()=>{
 let f=eaFixture();f.args.peerPackets[0].viewEpochs={at:42};
 let r=eaAssess(f);
 has(r,'EA_PEER_EPOCH_VECTOR_SCHEMA_INVALID');eaHold(r);
 f=eaFixture();f.args.now=null;
 r=eaAssess(f);
 has(r,'EA_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'EA_DZ_FULL_SOURCE_NOT_REVERIFIED');eaHold(r);
});
test('1EA mathematical agreement never exposes raw identities, keys, SHA, nonce or signed evidence',()=>{
 const f=eaFixture(),r=eaAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.peerPackets[0].signature,
  f.args.freezePackets[0].publicKeyPem,
  f.args.peerPins[EA_PEER_ROLES[0]].keyId,
  f.args.peerPackets[2].statement.challengeNonce,
  f.args.peerPackets[1].viewEpochs[0].anchorDigestSha256,
  f.args.anchorCandidate.evidenceBundleBase64
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);eaHold(r);
});

/* Phase 1EB — original 1EA chain plus two linked, applicant-provided
 * gossip runs with 6 independent-looking witnesses and two HOLD custodians.
 * No real external identity, clock, gossip, storage or incident unfreeze. */
import {EB_RUN_ROLES,EB_CUSTODY_ROLES,gossipHandoffDigestEb,
 runDigestEb,runPeerSigningBytesEb,custodySigningBytesEb,
 assessOfflineCrossRunGossipIncidentCustodyEb}
 from '../scripts/phase1eb-offline-cross-run-gossip-incident-custody.mjs';

function ebFixture(){
 const ea=eaFixture(),x=ea.args,dz=x.anchorCandidate,
  dy=dz.admissionCandidate,c=dy.decisionCase,
  e=dy.rehearsalCandidate.custodyCandidate.publicationCandidate.expected,
  final=dz.epochs.at(-1).record;
 const previousRunAnchor={sequence:final.sequence,
  digestSha256:gossipHandoffDigestEb(x),
  observedAt:'2026-11-21T00:00:09.000Z'};
 const viewSha=epochViewDigestEa(candidateEpochViewEa(dz));
 const peerPins={},custodyPins={},privateKeys={},publicPems={};
 function makePin(role,n){
  const kp=pair();privateKeys[role]=kp.privateKey;
  publicPems[role]=kp.publicKeyPem;
  return {keyId:'key_eb_'+n+'_001',spkiSha256:kp.spkiSha256,
   operatorId:'operator_eb_'+n+'_001',
   custodianOrganizationId:'org_eb_'+n+'_001'};
 }
 EB_RUN_ROLES.forEach((role,i)=>peerPins[role]=makePin(role,i));
 EB_CUSTODY_ROLES.forEach((role,i)=>custodyPins[role]=makePin(role,i+6));
 let priorSha=previousRunAnchor.digestSha256,priorSeq=previousRunAnchor.sequence;
 const runs=Array.from({length:2},(_,i)=>{
  const record={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_GOSSIP_REPLAY_FREEZE',repository:REPO,
   incidentId:c.incidentId,organizationId:e.organizationId,
   sourceHeadSha:e.sourceHeadSha,mainBaseSha:e.mainBaseSha,
   finalSequence:final.sequence,finalAnchorSha256:anchorDigestDz(final),
   evidenceBundleSha256:final.evidenceBundleSha256,
   epochViewSha256:viewSha,
   priorGossipHandoffSha256:previousRunAnchor.digestSha256,
   previousRunSequence:priorSeq,sequence:priorSeq+1,
   previousDigestSha256:priorSha,
   nonce:hash('eb_run_nonce_'+i),
   observedAt:'2026-11-21T00:00:'+(i===0?'10':'14')+'.000Z',
   decision:'HOLD'};
  const recordSha256=runDigestEb(record);
  const peerPackets=EB_RUN_ROLES.slice(i*3,i*3+3).map((role,j)=>{
   const statement={...record,role,...peerPins[role],
    recordSha256,expiresAt:'2026-11-21T00:10:00.000Z',
    observedAtPeer:'2026-11-21T00:00:'+
     String(i===0?11+j:15+j)+'.000Z',
    disposition:'OBSERVE_FROZEN_ONLY'};
   return {statement,publicKeyPem:publicPems[role],
    signature:sign(null,runPeerSigningBytesEb(role,statement),
     privateKeys[role]).toString('base64')};
  });
  priorSeq=record.sequence;priorSha=recordSha256;
  return {record,peerPackets};
 });
 const custodyPackets=EB_CUSTODY_ROLES.map((role,j)=>{
  const statement={schemaVersion:1,
   kind:'UNTRUSTED_OFFLINE_INCIDENT_REPLAY_RETENTION',
   role,repository:REPO,incidentId:c.incidentId,
   organizationId:e.organizationId,sourceHeadSha:e.sourceHeadSha,
   mainBaseSha:e.mainBaseSha,
   priorGossipHandoffSha256:previousRunAnchor.digestSha256,
   previousAnchorSha256:previousRunAnchor.digestSha256,
   firstRunSha256:runDigestEb(runs[0].record),
   finalRunSha256:runDigestEb(runs[1].record),
   finalSequence:runs[1].record.sequence,
   epochViewSha256:viewSha,evidenceBundleSha256:final.evidenceBundleSha256,
   challengeNonce:c.reviewNonce,
   ...custodyPins[role],
   observedAt:'2026-11-21T00:00:'+(18+j)+'.000Z',
   expiresAt:'2026-11-21T00:10:00.000Z',
   retentionUntil:'2027-01-01T00:00:00.000Z',
   disposition:'RETAIN_QUARANTINE_HOLD_NO_UNFREEZE'};
  return {statement,publicKeyPem:publicPems[role],
   signature:sign(null,custodySigningBytesEb(role,statement),
    privateKeys[role]).toString('base64')};
 });
 return {args:{gossipCandidate:x,previousRunAnchor,runs,peerPins,
  custodyPins,custodyPackets,now:NOW},ea,privateKeys};
}
function ebResign(f,kind,i,j=0){
 const p=kind==='peer'?f.args.runs[i].peerPackets[j]:
  f.args.custodyPackets[i];
 const role=p.statement.role,bytes=kind==='peer'?
  runPeerSigningBytesEb:custodySigningBytesEb;
 p.signature=sign(null,bytes(role,p.statement),
  f.privateKeys[role]).toString('base64');
}
const ebAssess=f=>assessOfflineCrossRunGossipIncidentCustodyEb(f.args);
const ebHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.realRemoteGossipAndAntiEquivocationGossipPerformed,false);
 assert.equal(r.externallyPersistedSignedHighwatermarkOrCasVerified,false);
 assert.equal(r.actualDurableWormRetentionDeleteDenialOrDrRestoreVerified,false);
 assert.equal(r.independentLegalSecurityProductionUnfreezeApproval,false);
 assert.equal(r.productionSourceActivationOrExternalEnrollmentPossible,false);
};
test('1EB two synthetic linked runs, six witnesses and two incident custodians remain HOLD',()=>{
 const r=ebAssess(ebFixture());
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.previousEaToDuFullCandidateReverifiedMathematicallyOnly,true);
 assert.equal(r.locallyLinkedSecondRunCount,2);
 assert.equal(r.mathematicallyVerifiedSixRunWitnessSignatures,6);
 assert.equal(r.mathematicallyVerifiedTwoIncidentRetentionSignatures,2);
 assert.equal(r.submittedCrossRunForkReplayAndCustodyInternallyConsistentOnly,true);
 ebHold(r);
});
test('1EB re-signed RUN1 or RUN2 decision GO cannot authorize incident recovery',()=>{
 for(const i of [0,1]){
  const f=ebFixture(),run=f.args.runs[i];
  run.record.decision='GO';
  const sha=runDigestEb(run.record);
  run.peerPackets.forEach((p,j)=>{
   p.statement.decision='GO';p.statement.recordSha256=sha;
   ebResign(f,'peer',i,j);
  });
  const r=ebAssess(f);
  has(r,'EB_RUN_ROLLBACK_FORK_REPLAY_OR_SCOPE_MISMATCH');ebHold(r);
 }
});
test('1EB signed second-run fork in final anchor or claimed source cannot pass',()=>{
 for(const [field,value] of [
  ['finalAnchorSha256','f'.repeat(64)],
  ['sourceHeadSha','f'.repeat(40)],
  ['epochViewSha256','f'.repeat(64)],
  ['evidenceBundleSha256','f'.repeat(64)],
  ['priorGossipHandoffSha256','f'.repeat(64)]
 ]){
  const f=ebFixture(),run=f.args.runs[1];
  run.record[field]=value;const digest=runDigestEb(run.record);
  run.peerPackets.forEach((p,j)=>{
   p.statement[field]=value;p.statement.recordSha256=digest;
   ebResign(f,'peer',1,j);
  });
  const r=ebAssess(f);
  has(r,'EB_RUN_ROLLBACK_FORK_REPLAY_OR_SCOPE_MISMATCH');ebHold(r);
 }
});
test('1EB re-signed second-run rollback, jump, anchor predecessor fork denied',()=>{
 for(const [field,value] of [
  ['sequence',5],['sequence',900],
  ['previousRunSequence',0],
  ['previousDigestSha256','e'.repeat(64)]
 ]){
  const f=ebFixture(),run=f.args.runs[1];
  run.record[field]=value;
  const digest=runDigestEb(run.record);
  run.peerPackets.forEach((p,j)=>{
   p.statement[field]=value;p.statement.recordSha256=digest;
   ebResign(f,'peer',1,j);
  });
  const r=ebAssess(f);
  has(r,'EB_RUN_ROLLBACK_FORK_REPLAY_OR_SCOPE_MISMATCH');ebHold(r);
 }
});
test('1EB re-ordered signed run packets or exact same run copied twice cannot pass',()=>{
 for(const mutate of [
  f=>f.args.runs.reverse(),
  f=>{f.args.runs[1]=clone(f.args.runs[0]);}
 ]){
  const f=ebFixture();mutate(f);
  const r=ebAssess(f);
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('EB_')));ebHold(r);
 }
});
test('1EB re-signed nonce reused from first run or old 1EA session denied',()=>{
 for(const nonce of ['0'.repeat(64),
  hash('eb_run_nonce_0'),
  hash('ea_challenge_nonce_'+EA_PEER_ROLES[0])]){
  const f=ebFixture(),run=f.args.runs[1];
  run.record.nonce=nonce;
  const digest=runDigestEb(run.record);
  run.peerPackets.forEach((p,j)=>{
   p.statement.nonce=nonce;p.statement.recordSha256=digest;
   ebResign(f,'peer',1,j);
  });
  const r=ebAssess(f);
  has(r,'EB_RUN_ROLLBACK_FORK_REPLAY_OR_SCOPE_MISMATCH');ebHold(r);
 }
});
test('1EB previous run anchor digest, sequence and timestamp cannot be switched',()=>{
 for(const [field,value] of [
  ['sequence',1],['digestSha256','f'.repeat(64)],
  ['observedAt','2026-11-21T00:00:07.000Z']]){
  const f=ebFixture();f.args.previousRunAnchor[field]=value;
  const r=ebAssess(f);
  has(r,'EB_PREVIOUS_GOSSIP_HANDOFF_ROLLBACK_OR_DRIFT');ebHold(r);
 }
});
test('1EB signed second-run observer can fork despite other two signatures',()=>{
 const f=ebFixture(),p=f.args.runs[1].peerPackets[1];
 p.statement.recordSha256='f'.repeat(64);ebResign(f,'peer',1,1);
 const r=ebAssess(f);
 assert.equal(r.mathematicallyVerifiedSixRunWitnessSignatures,6);
 has(r,'EB_SIGNED_INTER_RUN_PEER_FORK');ebHold(r);
});
test('1EB missing third witness and copy-pasted role are not independent run quorum',()=>{
 let f=ebFixture();f.args.runs[1].peerPackets.pop();
 let r=ebAssess(f);has(r,'EB_EXACT_THREE_PEERS_PER_RUN_REQUIRED');ebHold(r);
 f=ebFixture();f.args.runs[1].peerPackets[2]=
  clone(f.args.runs[1].peerPackets[0]);
 r=ebAssess(f);
 has(r,'EB_RUN_PEER_ROLE_OR_SCHEMA_INVALID');
 has(r,'EB_THREE_DISTINCT_PEERS_PER_RUN_REQUIRED');ebHold(r);
});
test('1EB synthetic old EA gossip key cannot become independently enrolled EB witness',()=>{
 const f=ebFixture(),old=EA_PEER_ROLES[0],now=EB_RUN_ROLES[0],
  prior=f.args.gossipCandidate.peerPins[old];
 f.args.peerPins[now].spkiSha256=prior.spkiSha256;
 const p=f.args.runs[0].peerPackets[0];
 p.statement.spkiSha256=prior.spkiSha256;
 p.publicKeyPem=f.args.gossipCandidate.peerPackets[0].publicKeyPem;
 f.privateKeys[now]=f.ea.privateKeys[old];ebResign(f,'peer',0,0);
 const r=ebAssess(f);
 has(r,'EB_CROSS_RUN_SIGNER_KEY_OR_ORGANIZATION_REUSE');ebHold(r);
});
test('1EB distinct new signers cannot reuse operator identity or organization across two runs',()=>{
 for(const field of ['keyId','spkiSha256','operatorId','custodianOrganizationId']){
  const f=ebFixture(),from=f.args.peerPins[EB_RUN_ROLES[0]],
   to=EB_RUN_ROLES[3];
  f.args.peerPins[to][field]=from[field];
  f.args.runs[1].peerPackets[0].statement[field]=from[field];
  ebResign(f,'peer',1,0);
  const r=ebAssess(f);
  has(r,'EB_CROSS_RUN_SIGNER_KEY_OR_ORGANIZATION_REUSE');ebHold(r);
 }
});
test('1EB signed peer key/pem or detached key pin substitution cannot be overlooked',()=>{
 for(const field of ['signature','publicKeyPem']){
  const f=ebFixture();
  f.args.runs[0].peerPackets[0][field]=
   f.args.runs[0].peerPackets[1][field];
  const r=ebAssess(f);
  has(r,'EB_RUN_PEER_SIGNATURE_OR_SPKI_INVALID');ebHold(r);
 }
 const f=ebFixture(),p=f.args.runs[0].peerPackets[0];
 p.statement.operatorId='rogue_operator_0001';ebResign(f,'peer',0,0);
 const r=ebAssess(f);has(r,'EB_RUN_PEER_DETACHED_PIN_MISMATCH');ebHold(r);
});
test('1EB witness signed GO and altered epoch nonce are never read as a consistent observation',()=>{
 for(const [field,value] of [
  ['disposition','UNFREEZE'],['nonce','f'.repeat(64)],
  ['recordSha256','f'.repeat(64)]
 ]){
  const f=ebFixture(),p=f.args.runs[0].peerPackets[2];
  p.statement[field]=value;ebResign(f,'peer',0,2);
  const r=ebAssess(f);
  has(r,'EB_SIGNED_INTER_RUN_PEER_FORK');ebHold(r);
 }
});
test('1EB early, expired or future signed cross-run observation fails chronology',()=>{
 for(const [field,value] of [
  ['observedAtPeer','2026-11-21T00:00:09.000Z'],
  ['observedAtPeer','2026-11-21T00:10:00.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z']
 ]){
  const f=ebFixture(),p=f.args.runs[0].peerPackets[0];
  p.statement[field]=value;ebResign(f,'peer',0,0);
  const r=ebAssess(f);
  has(r,'EB_RUN_PEER_TIME_OR_EXPIRY_INVALID');ebHold(r);
 }
});
test('1EB re-signed custody request to DELETE/GO or changed source anchor forbidden',()=>{
 for(const [field,value] of [
  ['disposition','PRODUCTION_UNFREEZE'],
  ['finalRunSha256','f'.repeat(64)],
  ['firstRunSha256','f'.repeat(64)],
  ['finalSequence',1000],
  ['previousAnchorSha256','f'.repeat(64)],
  ['sourceHeadSha','f'.repeat(40)],
  ['challengeNonce','f'.repeat(64)]
 ]){
  const f=ebFixture(),p=f.args.custodyPackets[0];
  p.statement[field]=value;ebResign(f,'custody',0);
  const r=ebAssess(f);
  has(r,'EB_CUSTODY_RUN_HANDOFF_OR_UNFREEZE_MISMATCH');ebHold(r);
 }
});
test('1EB signed shortened retention or conflicting second custody retention denied',()=>{
 let f=ebFixture();
 f.args.custodyPackets[0].statement.retentionUntil='2026-11-21T00:10:00.000Z';
 ebResign(f,'custody',0);
 let r=ebAssess(f);has(r,'EB_CUSTODY_TIME_OR_RETENTION_INVALID');ebHold(r);
 f=ebFixture();
 f.args.custodyPackets[1].statement.retentionUntil='2027-02-01T00:00:00.000Z';
 ebResign(f,'custody',1);
 r=ebAssess(f);
 assert.equal(r.mathematicallyVerifiedTwoIncidentRetentionSignatures,2);
 has(r,'EB_CUSTODY_RETENTION_SPLIT_VIEW');ebHold(r);
});
test('1EB cloned or missing Legal/Security custodians never count as both',()=>{
 let f=ebFixture();
 f.args.custodyPackets[1]=clone(f.args.custodyPackets[0]);
 let r=ebAssess(f);
 has(r,'EB_CUSTODY_ROLE_OR_SCHEMA_INVALID');
 has(r,'EB_CUSTODY_ROLE_QUORUM_INCOMPLETE');ebHold(r);
 f=ebFixture();f.args.custodyPackets.pop();
 r=ebAssess(f);
 has(r,'EB_EXACT_TWO_CUSTODY_HOLD_PACKETS_REQUIRED');ebHold(r);
});
test('1EB stale custody signature and copied Ed25519 key remain invalid',()=>{
 let f=ebFixture(),p=f.args.custodyPackets[0];
 p.statement.observedAt='2026-11-21T00:00:17.000Z';
 ebResign(f,'custody',0);
 let r=ebAssess(f);has(r,'EB_CUSTODY_TIME_OR_RETENTION_INVALID');ebHold(r);
 f=ebFixture();
 f.args.custodyPackets[0].signature=f.args.custodyPackets[1].signature;
 r=ebAssess(f);has(r,'EB_CUSTODY_SIGNATURE_OR_SPKI_INVALID');ebHold(r);
});
test('1EB original signed EA/DZ gossip mutation cannot be legitimized by new sessions',()=>{
 const f=ebFixture();
 f.args.gossipCandidate.anchorCandidate.admissionCandidate.rehearsalCandidate
  .custodyCandidate.publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=ebAssess(f);
 has(r,'EB_PREVIOUS_EA_ORIGINAL_HISTORY_NOT_REVERIFIED');ebHold(r);
});
test('1EB unexpected approval metadata, malformed source array and cyclic input fail closed',()=>{
 let f=ebFixture();
 let r=assessOfflineCrossRunGossipIncidentCustodyEb({...f.args,verifiedByMca:true});
 has(r,'EB_EXACT_BOUNDED_INPUT_REQUIRED');ebHold(r);
 f=ebFixture();f.args.gossipCandidate.anchorCandidate.epochs={at:42};
 r=ebAssess(f);
 has(r,'EB_PREVIOUS_EA_ORIGINAL_HISTORY_NOT_REVERIFIED');ebHold(r);
 f=ebFixture();f.args.gossipCandidate.cyclic=f.args;
 r=ebAssess(f);has(r,'EB_EXACT_BOUNDED_INPUT_REQUIRED');ebHold(r);
});
test('1EB oversized packet, forged signed schema field and missing UTC cannot grant release',()=>{
 let f=ebFixture();f.args.gossipCandidate.extra='x'.repeat(3072*1024);
 let r=ebAssess(f);has(r,'EB_EXACT_BOUNDED_INPUT_REQUIRED');ebHold(r);
 f=ebFixture();f.args.runs[0].record.externalGoVerified=true;
 r=ebAssess(f);has(r,'EB_RUN_RECORD_SCHEMA_OR_SIZE_INVALID');ebHold(r);
 f=ebFixture();f.args.now=null;
 r=ebAssess(f);
 has(r,'EB_EXPLICIT_UTC_CLOCK_REQUIRED');ebHold(r);
});
test('1EB output redacts original gossip bytes, signer IDs, nonce, evidence and PEM',()=>{
 const f=ebFixture(),r=ebAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.previousRunAnchor.digestSha256,
  f.args.runs[0].record.nonce,
  f.args.runs[1].peerPackets[0].signature,
  f.args.custodyPackets[0].publicKeyPem,
  f.args.peerPins[EB_RUN_ROLES[0]].keyId,
  f.args.gossipCandidate.anchorCandidate.evidenceBundleBase64
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);ebHold(r);
});

/* Phase 1EC — offline 12-gate authority handoff to claimed reviewers and
 * incident custodians. EVERY identity, evidence, clock, lock is synthetic. */
import {EC_AUTHORITY_GATES,EC_REVIEW_ROLES,EC_CUSTODY_ROLES,
 sourceReceiptDigestEc,authorityClaimsDigestEc,manifestDigestEc,
 reviewSigningBytesEc,reviewSetDigestEc,custodySigningBytesEc,
 assessOfflineExternalAuthorityHandoffEc}
 from '../scripts/phase1ec-offline-authority-handoff-custody.mjs';

function ecFixture(){
 const eb=ebFixture(),x=eb.args,
  dy=x.gossipCandidate.anchorCandidate.admissionCandidate,
  c=dy.decisionCase,original=dy.rehearsalCandidate.custodyCandidate
   .publicationCandidate.expected,run=x.runs.at(-1).record;
 const previousHandoffAnchor={sequence:run.sequence,
  digestSha256:sourceReceiptDigestEc(x),
  observedAt:'2026-11-21T00:00:19.000Z'};
 const authorityClaims=Object.fromEntries(EC_AUTHORITY_GATES.map(role=>[
  role,{state:'MISSING',evidenceSha256:'0'.repeat(64),
   issuerOrganizationClaim:null,submittedAt:null,validUntil:null}
 ]));
 const manifest={schemaVersion:1,kind:'APPLICANT_UNVERIFIED_AUTHORITY_HANDOFF_HOLD',
  repository:REPO,incidentId:c.incidentId,organizationId:original.organizationId,
  sourceHeadSha:original.sourceHeadSha,mainBaseSha:original.mainBaseSha,
  finalRunSequence:run.sequence,finalRunSha256:runDigestEb(run),
  ebCustodySourceSha256:previousHandoffAnchor.digestSha256,
  priorGossipHandoffSha256:x.previousRunAnchor.digestSha256,
  authorityClaimsSha256:authorityClaimsDigestEc(authorityClaims),
  previousHandoffSequence:previousHandoffAnchor.sequence,
  previousHandoffSha256:previousHandoffAnchor.digestSha256,
  sequence:previousHandoffAnchor.sequence+1,
  challengeNonce:hash('ec_application_handoff_challenge'),
  observedAt:'2026-11-21T00:00:20.000Z',decision:'HOLD'};
 const reviewPins={},custodyPins={},privateKeys={},publicPems={};
 const pinFor=(role,index)=>{
  const kp=pair();
  privateKeys[role]=kp.privateKey;publicPems[role]=kp.publicKeyPem;
  return {keyId:'key_ec_'+index+'_001',spkiSha256:kp.spkiSha256,
   operatorId:'operator_ec_'+index+'_001',
   custodianOrganizationId:'org_ec_'+index+'_001'};
 };
 const manifestSha256=manifestDigestEc(manifest);
 const reviewPackets=EC_REVIEW_ROLES.map((role,index)=>{
  const pin=pinFor(role,index);reviewPins[role]=pin;
  const statement={...manifest,role,...pin,manifestSha256,
   reviewObservedAt:'2026-11-21T00:00:'+(21+index)+'.000Z',
   expiresAt:'2026-11-21T00:10:00.000Z',
   disposition:'REVIEW_UNVERIFIED_HOLD_ONLY'};
  return {statement,publicKeyPem:publicPems[role],
   signature:sign(null,reviewSigningBytesEc(role,statement),
    privateKeys[role]).toString('base64')};
 });
 const reviewSetSha256=reviewSetDigestEc(reviewPackets.map(p=>p.statement));
 const custodyPackets=EC_CUSTODY_ROLES.map((role,index)=>{
  const pin=pinFor(role,index+2);custodyPins[role]=pin;
  const statement={...manifest,role,...pin,manifestSha256,reviewSetSha256,
   observedAtCustody:'2026-11-21T00:00:'+(23+index)+'.000Z',
   expiresAt:'2026-11-21T00:10:00.000Z',
   retentionUntil:x.custodyPackets[0].statement.retentionUntil,
   disposition:'RETAIN_UNVERIFIED_HOLD_NO_UNFREEZE'};
  return {statement,publicKeyPem:publicPems[role],
   signature:sign(null,custodySigningBytesEc(role,statement),
    privateKeys[role]).toString('base64')};
 });
 return {args:{incidentCandidate:x,previousHandoffAnchor,authorityClaims,
  manifest,reviewPins,reviewPackets,custodyPins,custodyPackets,now:NOW},
  privateKeys,eb};
}
function ecResign(f,kind,index){
 const packet=f.args[kind==='review'?'reviewPackets':'custodyPackets'][index],
  role=packet.statement.role,bytes=kind==='review'?
   reviewSigningBytesEc:custodySigningBytesEc;
 packet.signature=sign(null,bytes(role,packet.statement),
  f.privateKeys[role]).toString('base64');
}
function ecRebindReviewSet(f){
 const digest=reviewSetDigestEc(EC_REVIEW_ROLES.map(r=>
  f.args.reviewPackets.find(p=>p.statement.role===r).statement));
 f.args.custodyPackets.forEach((packet,index)=>{
  packet.statement.reviewSetSha256=digest;ecResign(f,'custody',index);
 });
}
const ecAssess=f=>assessOfflineExternalAuthorityHandoffEc(f.args);
const ecHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualExternalProviderOrMcaMandateVerified,false);
 assert.equal(r.issuerSignedLiveCrlOcspOrCcaRcaiEmudhraVerified,false);
 assert.equal(r.independentTlsEvidenceRetrievalOrSignedGossipPerformed,false);
 assert.equal(r.durableWormCasObjectLockAndIndependentDrVerified,false);
 assert.equal(r.productionSourceUnfreezeOrCredentialEnrollmentPossible,false);
};
test('1EC twelve absent authority gates and four synthetic HOLD signatures never approve',()=>{
 const r=ecAssess(ecFixture());
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.precedingEbToDuOriginalHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.exactTwelveApplicantOnlyGateClaims,12);
 assert.equal(r.mathematicallyVerifiedTwoReviewSignatures,2);
 assert.equal(r.mathematicallyVerifiedTwoCustodySignatures,2);
 assert.equal(r.candidateHandoffManifestCorrelatedMathematicallyOnly,true);
 ecHold(r);
});
test('1EC gate status VERIFIED APPROVED and self-asserted signed authority fail schema',()=>{
 for(const state of ['VERIFIED','APPROVED','PRODUCTION_READY']){
  const f=ecFixture();
  f.args.authorityClaims[EC_AUTHORITY_GATES[0]].state=state;
  const r=ecAssess(f);
  has(r,'EC_ORIGINAL_12_GATE_STATUS_OR_EVIDENCE_DRIFT');ecHold(r);
 }
});
test('1EC forged applicant provider evidence contradicts original DY gate history',()=>{
 const f=ecFixture(),g=EC_AUTHORITY_GATES[0];
 f.args.authorityClaims[g]={state:'PRESENT_UNVERIFIED',
  evidenceSha256:hash('synthetic-issuer-evidence'),issuerOrganizationClaim:'org_fixture_ca',
  submittedAt:NOW,validUntil:'2026-11-25T00:00:00.000Z'};
 const r=ecAssess(f);
 has(r,'EC_ORIGINAL_12_GATE_STATUS_OR_EVIDENCE_DRIFT');ecHold(r);
});
test('1EC single changed evidence digest or inserted unknown gate is not admitted',()=>{
 for(const edit of [
  claims=>{claims[EC_AUTHORITY_GATES[0]].evidenceSha256='f'.repeat(64);},
  claims=>{claims.UNLISTED_EXTERNAL_AUTHORITY={state:'MISSING',
   evidenceSha256:'0'.repeat(64),issuerOrganizationClaim:null,
   submittedAt:null,validUntil:null};},
  claims=>{claims[EC_AUTHORITY_GATES[1]].authVerified=true;}
 ]){
  const f=ecFixture();edit(f.args.authorityClaims);
  const r=ecAssess(f);
  has(r,'EC_ORIGINAL_12_GATE_STATUS_OR_EVIDENCE_DRIFT');ecHold(r);
 }
});
test('1EC handoff submitted claimant signer organization must be absent for missing evidence',()=>{
 const f=ecFixture();
 f.args.authorityClaims[EC_AUTHORITY_GATES[0]].issuerOrganizationClaim='org_forged_ca_001';
 const r=ecAssess(f);
 has(r,'EC_ORIGINAL_12_GATE_STATUS_OR_EVIDENCE_DRIFT');ecHold(r);
});
test('1EC previous source handoff anchor digest, sequence or clock substitution is rejected',()=>{
 for(const [field,value] of [
  ['sequence',1],['digestSha256','f'.repeat(64)],
  ['observedAt','2026-11-21T00:00:17.000Z']
 ]){
  const f=ecFixture();f.args.previousHandoffAnchor[field]=value;
  const r=ecAssess(f);
  has(r,'EC_PREVIOUS_INCIDENT_SOURCE_ANCHOR_INVALID');ecHold(r);
 }
});
test('1EC fake production GO or trusted source kind never yields approved handoff',()=>{
 for(const [field,value] of [
  ['decision','GO'],
  ['kind','INDEPENDENTLY_VERIFIED_AUTHORITY'],
  ['sourceHeadSha','f'.repeat(40)],
  ['ebCustodySourceSha256','f'.repeat(64)],
  ['priorGossipHandoffSha256','f'.repeat(64)],
  ['authorityClaimsSha256','f'.repeat(64)]
 ]){
  const f=ecFixture();f.args.manifest[field]=value;
  const r=ecAssess(f);
  has(r,'EC_HOLD_MANIFEST_SOURCE_OR_SEQUENCE_MISMATCH');ecHold(r);
 }
});
test('1EC re-signed manifest sequence jump, rollback, nonce replay and forged final run',()=>{
 for(const [field,value] of [
  ['sequence',3],['previousHandoffSequence',1],
  ['challengeNonce','0'.repeat(64)],
  ['challengeNonce',hash('eb_run_nonce_1')],
  ['finalRunSha256','f'.repeat(64)]
 ]){
  const f=ecFixture();f.args.manifest[field]=value;
  const r=ecAssess(f);
  has(r,'EC_HOLD_MANIFEST_SOURCE_OR_SEQUENCE_MISMATCH');ecHold(r);
 }
});
test('1EC copied reviewer role or missing second reviewer fails exact quorum',()=>{
 let f=ecFixture();
 f.args.reviewPackets[1]=clone(f.args.reviewPackets[0]);
 let r=ecAssess(f);
 has(r,'EC_REVIEW_ROLE_PACKET_INVALID');has(r,'EC_REVIEW_QUORUM_INCOMPLETE');ecHold(r);
 f=ecFixture();f.args.reviewPackets.pop();
 r=ecAssess(f);has(r,'EC_EXACT_TWO_REVIEW_PACKETS_REQUIRED');ecHold(r);
});
test('1EC wrong reviewer signing key/SPKI or cloned detached PEM cannot verify',()=>{
 for(const field of ['signature','publicKeyPem']){
  const f=ecFixture();
  f.args.reviewPackets[0][field]=f.args.reviewPackets[1][field];
  const r=ecAssess(f);
  has(r,'EC_REVIEW_SIGNATURE_OR_SPKI_INVALID');ecHold(r);
 }
});
test('1EC signed reviewer can never promote applicant case to authenticated approval',()=>{
 for(const [field,value] of [
  ['disposition','APPROVE_PRODUCTION'],
  ['manifestSha256','f'.repeat(64)],
  ['sourceHeadSha','f'.repeat(40)],
  ['authorityClaimsSha256','f'.repeat(64)]
 ]){
  const f=ecFixture();
  f.args.reviewPackets[1].statement[field]=value;
  ecResign(f,'review',1);ecRebindReviewSet(f);
  const r=ecAssess(f);
  assert.equal(r.mathematicallyVerifiedTwoReviewSignatures,2);
  has(r,'EC_REVIEW_SIGNED_SCOPE_OR_FALSE_APPROVAL');ecHold(r);
 }
});
test('1EC reviewer signed too early, after expiry or in future fails chronology',()=>{
 for(const [field,value] of [
  ['reviewObservedAt','2026-11-21T00:00:19.000Z'],
  ['reviewObservedAt','2026-11-21T00:10:00.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z']
 ]){
  const f=ecFixture();
  f.args.reviewPackets[0].statement[field]=value;
  ecResign(f,'review',0);ecRebindReviewSet(f);
  const r=ecAssess(f);
  has(r,'EC_REVIEW_CLOCK_OR_EXPIRY_INVALID');ecHold(r);
 }
});
test('1EC key ID SPKI operator and claimed organization cannot collide across reviewers',()=>{
 for(const field of ['keyId','spkiSha256','operatorId','custodianOrganizationId']){
  const f=ecFixture(),from=f.args.reviewPins[EC_REVIEW_ROLES[0]],
   role=EC_CUSTODY_ROLES[0];
  f.args.custodyPins[role][field]=from[field];
  f.args.custodyPackets[0].statement[field]=from[field];
  ecResign(f,'custody',0);
  const r=ecAssess(f);
  has(r,'EC_SIGNER_KEY_OPERATOR_OR_ORG_NOT_SEPARATED');ecHold(r);
 }
});
test('1EC new legal handoff custodian cannot reuse old EB retention signing key',()=>{
 const f=ecFixture(),from=EB_CUSTODY_ROLES[0],to=EC_CUSTODY_ROLES[0];
 const old=f.args.incidentCandidate.custodyPins[from],
  earlier=f.args.incidentCandidate.custodyPackets[0];
 f.args.custodyPins[to].spkiSha256=old.spkiSha256;
 f.args.custodyPackets[0].statement.spkiSha256=old.spkiSha256;
 f.args.custodyPackets[0].publicKeyPem=earlier.publicKeyPem;
 f.privateKeys[to]=f.eb.privateKeys[from];ecResign(f,'custody',0);
 const r=ecAssess(f);
 has(r,'EC_SIGNER_KEY_OPERATOR_OR_ORG_NOT_SEPARATED');ecHold(r);
});
test('1EC cloned or missing Legal/Security handoff custody is not a quorum',()=>{
 let f=ecFixture();
 f.args.custodyPackets[1]=clone(f.args.custodyPackets[0]);
 let r=ecAssess(f);
 has(r,'EC_CUSTODY_ROLE_PACKET_INVALID');has(r,'EC_CUSTODY_QUORUM_INCOMPLETE');ecHold(r);
 f=ecFixture();f.args.custodyPackets.pop();
 r=ecAssess(f);has(r,'EC_EXACT_TWO_CUSTODY_PACKETS_REQUIRED');ecHold(r);
});
test('1EC signed custody GO/UNFREEZE, source substitution and review quorum fork denied',()=>{
 for(const [field,value] of [
  ['disposition','UNFREEZE_PRODUCTION'],
  ['manifestSha256','f'.repeat(64)],
  ['reviewSetSha256','f'.repeat(64)],
  ['finalRunSha256','f'.repeat(64)],
  ['ebCustodySourceSha256','f'.repeat(64)]
 ]){
  const f=ecFixture();
  f.args.custodyPackets[0].statement[field]=value;ecResign(f,'custody',0);
  const r=ecAssess(f);
  has(r,'EC_CUSTODY_SIGNED_SOURCE_OR_UNFREEZE_FORBIDDEN');ecHold(r);
 }
});
test('1EC re-signed shorter retention, split custody and pre-review custody fail',()=>{
 for(const [field,value,code] of [
  ['retentionUntil','2026-11-22T00:00:00.000Z','EC_CUSTODY_TIME_OR_RETENTION_INVALID'],
  ['retentionUntil','2027-02-01T00:00:00.000Z','EC_CUSTODY_RETENTION_FORK'],
  ['observedAtCustody','2026-11-21T00:00:21.000Z','EC_CUSTODY_TIME_OR_RETENTION_INVALID'],
  ['expiresAt','2026-11-20T23:59:59.000Z','EC_CUSTODY_TIME_OR_RETENTION_INVALID']
 ]){
  const f=ecFixture();
  f.args.custodyPackets[1].statement[field]=value;ecResign(f,'custody',1);
  const r=ecAssess(f);
  has(r,code);ecHold(r);
 }
});
test('1EC signed custody stale signature and pin impersonation fail',()=>{
 let f=ecFixture();
 f.args.custodyPackets[0].signature=f.args.custodyPackets[1].signature;
 let r=ecAssess(f);has(r,'EC_CUSTODY_SIGNATURE_OR_SPKI_INVALID');ecHold(r);
 f=ecFixture();
 f.args.custodyPackets[0].statement.operatorId='rogue_ec_operator';
 ecResign(f,'custody',0);
 r=ecAssess(f);has(r,'EC_CUSTODY_DETACHED_PIN_INVALID');ecHold(r);
});
test('1EC tampered original EA-EB incident witness history remains rejected',()=>{
 const f=ecFixture();
 f.args.incidentCandidate.gossipCandidate.anchorCandidate
  .admissionCandidate.rehearsalCandidate.custodyCandidate
  .publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=ecAssess(f);
 has(r,'EC_ORIGINAL_EB_HISTORY_NOT_REVERIFIED');ecHold(r);
});
test('1EC user-supplied bogus authority flag, cyclic and oversized input fail closed',()=>{
 let f=ecFixture();
 let r=assessOfflineExternalAuthorityHandoffEc({...f.args,
  externalAuthorityAuthenticated:true});
 has(r,'EC_EXACT_BOUNDED_INPUT_REQUIRED');ecHold(r);
 f=ecFixture();f.args.incidentCandidate.selfReference=f.args;
 r=ecAssess(f);has(r,'EC_EXACT_BOUNDED_INPUT_REQUIRED');ecHold(r);
 f=ecFixture();f.args.incidentCandidate.excess='x'.repeat(3584*1024);
 r=ecAssess(f);has(r,'EC_EXACT_BOUNDED_INPUT_REQUIRED');ecHold(r);
});
test('1EC malformed original run vector and missing clock are denied without throwing',()=>{
 let f=ecFixture();f.args.incidentCandidate.runs={at:123};
 let r=ecAssess(f);
 has(r,'EC_ORIGINAL_EB_HISTORY_NOT_REVERIFIED');ecHold(r);
 f=ecFixture();f.args.now=null;
 r=ecAssess(f);
 has(r,'EC_EXPLICIT_UTC_CLOCK_REQUIRED');ecHold(r);
});
test('1EC redacted frozen result never returns private evidence source hashes, identities or keys',()=>{
 const f=ecFixture(),r=ecAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.previousHandoffAnchor.digestSha256,
  f.args.reviewPackets[0].signature,
  f.args.custodyPackets[0].publicKeyPem,
  f.args.manifest.challengeNonce,
  f.args.reviewPins[EC_REVIEW_ROLES[0]].keyId,
  f.args.incidentCandidate.runs[0].record.nonce
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);ecHold(r);
});

/* Phase 1ED: Strict disconnected authority-verification port contracts.
 * No real HTTP, official CA/MCA credentials, secrets manager, WORM/CAS
 * or production side effects: synthetic locally generated adapter receipts. */
import {ED_GATE_INTERFACE_CONTRACT,ED_RECEIPT_STATUSES,
 createDisconnectedAuthorityWorkOrdersEd,createDisconnectedTestReceiptEd,
 workOrderDigestEd,assessDisconnectedAuthorityVerificationPortEd}
 from '../scripts/phase1ed-disconnected-authority-verification-ports.mjs';

function edFixture(){
 const ec=ecFixture(),workOrders=createDisconnectedAuthorityWorkOrdersEd(ec.args);
 const receipts=workOrders.map((order,i)=>createDisconnectedTestReceiptEd(order,{
  adapterId:'test_adapter_gate_'+String(i).padStart(3,'0'),
  observedAt:'2026-11-21T00:00:'+String(i+25).padStart(2,'0')+'.000Z'
 }));
 return {args:{handoffCandidate:ec.args,workOrders:clone(workOrders),
  receipts:clone(receipts),now:NOW},ec,originalOrders:workOrders,
  originalReceipts:receipts};
}
const edAssess=f=>assessDisconnectedAuthorityVerificationPortEd(f.args);
const edHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.realProviderOrMcaMandateAuthenticated,false);
 assert.equal(r.liveIssuerSignedCrlOcspOrCcaRcaiEmudhraVerified,false);
 assert.equal(r.actualIndependentTlsEvidenceOrGossipObtained,false);
 assert.equal(r.realProtectedWormCasObjectLockOrDrAcceptanceVerified,false);
 assert.equal(r.independentSignerEnrollmentOrStagingReleaseApproved,false);
 assert.equal(r.productionSourceActivationOrCredentialEnrollmentPossible,false);
};
test('1ED all 12 disconnected work orders and receipts bind original chain but always HOLD',()=>{
 const f=edFixture(),r=edAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.priorEcToDuOriginalHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.exactApplicantOnlyPortWorkOrders,12);
 assert.equal(r.internallyCorrelatedDisconnectedTestReceipts,12);
 assert.equal(r.notExecutedReceiptCount,12);
 assert.equal(r.syntheticPortProtocolInternallyConsistentOnly,true);
 assert.equal(f.args.workOrders.length,12);
 assert.equal(f.args.receipts.length,12);
 edHold(r);
});
test('1ED port protocol exposes required checks for issuer CRL/OCSP and authenticated HTTPS',()=>{
 const rev=ED_GATE_INTERFACE_CONTRACT.LIVE_ISSUER_SIGNED_CRL_OCSP;
 const tls=ED_GATE_INTERFACE_CONTRACT.AUTHENTICATED_EXTERNAL_TLS_ARCHIVE_BYTES;
 assert.deepEqual([...rev.requiredChecks],
  ['ISSUER_SIGNATURE','SERIAL','NONCE','THIS_NEXT_UPDATE','REVOCATION_STATE']);
 assert.deepEqual([...tls.requiredChecks],
  ['TLS_HOSTNAME','CHAIN_AND_SPKI','BOUNDED_BYTES','NO_REDIRECT','SSRF_DENY']);
 assert.equal(Object.isFrozen(rev),true);
 assert.equal(Object.isFrozen(tls.requiredChecks),true);
 assert.equal(ED_RECEIPT_STATUSES.includes('VERIFIED'),false);
 assert.equal(ED_RECEIPT_STATUSES.includes('PRODUCTION_GO'),false);
});
test('1ED test-only constructor is frozen, never executes an adapter and accepts no GO status',()=>{
 const f=edFixture(),w=f.originalOrders[0],receipt=f.originalReceipts[0];
 assert.equal(Object.isFrozen(w),true);
 assert.equal(Object.isFrozen(receipt),true);
 assert.equal(Object.isFrozen(f.originalOrders),true);
 assert.equal(receipt.networkRequests,0);
 assert.equal(receipt.authoritiesAuthenticated,0);
 assert.equal(receipt.sideEffects,0);
 assert.throws(()=>createDisconnectedTestReceiptEd(w,{
  adapterId:'test_adapter_gate_000',status:'VERIFIED',
  observedAt:'2026-11-21T00:00:25.000Z'
 }),/ED_INVALID_DISCONNECTED_TEST_DOUBLE_INPUT/);
});
test('1ED duplicate or missing work order cannot create 12 source-scoped verifications',()=>{
 for(const edit of [
  f=>f.args.workOrders.pop(),
  f=>{f.args.workOrders[1]=clone(f.args.workOrders[0]);},
  f=>{f.args.workOrders.reverse();}
 ]){
  const f=edFixture();edit(f);
  const r=edAssess(f);
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('ED_')));edHold(r);
 }
});
test('1ED no independent provider approval may be self-reported via any test receipt status',()=>{
 for(const status of ['VERIFIED','APPROVED','PRODUCTION_GO',
  'SIMULATED_VERIFIED','REJECTED','AUTHENTICATED']){
  const f=edFixture();f.args.receipts[0].status=status;
  const r=edAssess(f);
  has(r,'ED_FAKE_VERIFIED_APPROVED_OR_STATUS_DRIFT');edHold(r);
 }
});
test('1ED a simulated UNVERIFIED status cannot overwrite original MISSING gate state',()=>{
 for(const status of ['SIMULATED_UNVERIFIED','SIMULATED_REJECTED']){
  const f=edFixture();f.args.receipts[2].status=status;
  const r=edAssess(f);
  has(r,'ED_FAKE_VERIFIED_APPROVED_OR_STATUS_DRIFT');edHold(r);
 }
});
test('1ED all-missing receipt may be SIMULATED_MISSING but never becomes external proof',()=>{
 const f=edFixture();
 f.args.receipts[5].status='SIMULATED_MISSING';
 const r=edAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.notExecutedReceiptCount,11);
 assert.equal(r.syntheticPortProtocolInternallyConsistentOnly,true);
 edHold(r);
});
test('1ED re-ordered, duplicate or missing fake adapters are denied',()=>{
 for(const edit of [
  f=>f.args.receipts.reverse(),
  f=>{f.args.receipts[0]=clone(f.args.receipts[1]);},
  f=>f.args.receipts.pop()
 ]){
  const f=edFixture();edit(f);
  const r=edAssess(f);
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('ED_')));edHold(r);
 }
});
test('1ED a duplicate or forged adapter identity cannot masquerade as independent actor',()=>{
 for(const value of ['test_adapter_gate_001','provider_mca_authorized',
  'test_adapter_0','test_adapter_$$$$']){
  const f=edFixture();f.args.receipts[0].adapterId=value;
  const r=edAssess(f);
  has(r,'ED_DUPLICATE_OR_FORGED_TEST_ADAPTER_ID');edHold(r);
 }
});
test('1ED response attempt to claim live network traffic, authority, writes or release GO rejected',()=>{
 for(const [field,value] of [
  ['networkRequests',1],['authoritiesAuthenticated',1],
  ['sideEffects',1],['executionMode','REAL_PROVIDER_API'],
  ['releaseDecision','GO'],['kind','AUTHENTICATED_VERIFIED_RECEIPT']
 ]){
  const f=edFixture();f.args.receipts[0][field]=value;
  const r=edAssess(f);
  has(r,'ED_DISCONNECTED_RESPONSE_SCOPE_OR_FALSE_AUTHORITY');edHold(r);
 }
});
test('1ED signed origin replay attempt from one work order to another is rejected',()=>{
 for(const [field,value] of [
  ['workOrderSha256','f'.repeat(64)],
  ['requestNonce','f'.repeat(64)],
  ['gate','PROVIDER_WRITTEN_AGREEMENT'],
  ['observedEvidenceSha256','e'.repeat(64)],
  ['portType','REVOCATION_STATUS']
 ]){
  const f=edFixture();
  assert.notEqual(f.args.receipts[2][field],value);
  f.args.receipts[2][field]=value;
  const r=edAssess(f);
  has(r,'ED_DISCONNECTED_RESPONSE_SCOPE_OR_FALSE_AUTHORITY');edHold(r);
 }
});
test('1ED cloned and replayed nonce is rejected even when source receipts correlate',()=>{
 const f=edFixture();
 f.args.receipts[5].requestNonce=f.args.receipts[3].requestNonce;
 const r=edAssess(f);
 has(r,'ED_REPLAYED_REQUEST_NONCE');
 has(r,'ED_DISCONNECTED_RESPONSE_SCOPE_OR_FALSE_AUTHORITY');edHold(r);
});
test('1ED work order source or previous manifest hash substitution fails exact binding',()=>{
 for(const [field,value] of [
  ['sourceHeadSha','f'.repeat(40)],
  ['manifestSha256','f'.repeat(64)],
  ['authorityClaimsSha256','f'.repeat(64)],
  ['expectedEvidenceSha256','e'.repeat(64)],
  ['handoffSequence',99],
  ['requestNonce','f'.repeat(64)]
 ]){
  const f=edFixture();f.args.workOrders[4][field]=value;
  const r=edAssess(f);
  has(r,'ED_WORK_ORDER_SOURCE_SCOPE_OR_PORT_DRIFT');edHold(r);
 }
});
test('1ED per-gate required checks must match exact machine-readable verified-authority contract',()=>{
 for(const edit of [
  w=>w.requiredChecks.pop(),
  w=>w.requiredChecks.reverse(),
  w=>w.requiredChecks.push('ASSUME_VERIFIED'),
  w=>{w.portType='SELF_VERIFIED_PROVIDER';}
 ]){
  const f=edFixture();edit(f.args.workOrders[3]);
  const r=edAssess(f);
  has(r,'ED_WORK_ORDER_SOURCE_SCOPE_OR_PORT_DRIFT');edHold(r);
 }
});
test('1ED work order cannot permit live IO, external source thaw, or extra approval fields',()=>{
 for(const edit of [
  w=>{w.executionPolicy='ALLOW_EXTERNAL_TLS';},
  w=>{w.decision='GO';},
  w=>{w.providerApproved=true;},
  w=>{w.kind='PRODUCTION_PROVIDER_AUTHORIZED';}
 ]){
  const f=edFixture();edit(f.args.workOrders[0]);
  const r=edAssess(f);
  has(r,'ED_WORK_ORDER_SOURCE_SCOPE_OR_PORT_DRIFT');edHold(r);
 }
});
test('1ED time future, stale, expired and nonmonotonic test receipts fail closed',()=>{
 for(const [field,value] of [
  ['observedAt','2026-11-21T00:00:21.000Z'],
  ['observedAt','2026-11-21T00:10:00.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z'],
  ['expiresAt','2026-11-21T00:00:25.000Z'],
  ['observedAt','2026-11-21T00:00:27.000Z']
 ]){
  const f=edFixture();f.args.receipts[0][field]=value;
  const r=edAssess(f);
  has(r,'ED_TEST_RECEIPT_TIME_OR_EXPIRY_INVALID');edHold(r);
 }
});
test('1ED entire prior Phase 1EC source-signed history is re-evaluated on every assessment',()=>{
 const f=edFixture();
 f.args.handoffCandidate.incidentCandidate.gossipCandidate.anchorCandidate
  .admissionCandidate.rehearsalCandidate.custodyCandidate
  .publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=edAssess(f);
 has(r,'ED_ORIGINAL_EC_AUTHORITY_HANDOFF_NOT_REVERIFIED');edHold(r);
});
test('1ED changed original 12 gate authority status never inherits old passing ports',()=>{
 const f=edFixture();
 f.args.handoffCandidate.authorityClaims.PROVIDER_WRITTEN_AGREEMENT.state='VERIFIED';
 const r=edAssess(f);
 has(r,'ED_ORIGINAL_EC_AUTHORITY_HANDOFF_NOT_REVERIFIED');edHold(r);
});
test('1ED forged source handshake and signed original manifest GO never get a test receipt greenlight',()=>{
 for(const edit of [
  ec=>{ec.manifest.decision='GO';},
  ec=>{ec.manifest.sourceHeadSha='f'.repeat(40);},
  ec=>{ec.custodyPackets[0].statement.disposition='UNFREEZE_PRODUCTION';}
 ]){
  const f=edFixture();edit(f.args.handoffCandidate);
  const r=edAssess(f);
  has(r,'ED_ORIGINAL_EC_AUTHORITY_HANDOFF_NOT_REVERIFIED');edHold(r);
 }
});
test('1ED unexpected approval extension, invalid order shape and wrong receipts scope fail',()=>{
 let f=edFixture();
 let r=assessDisconnectedAuthorityVerificationPortEd({...f.args,
  realProviderVerified:true});
 has(r,'ED_EXACT_BOUNDED_INPUT_REQUIRED');edHold(r);
 f=edFixture();f.args.workOrders[1].realProviderApproved=true;
 r=edAssess(f);
 has(r,'ED_WORK_ORDER_SOURCE_SCOPE_OR_PORT_DRIFT');edHold(r);
 f=edFixture();f.args.receipts[0].officialIssuerSignatureValid=true;
 r=edAssess(f);has(r,'ED_RECEIPT_EXACT_SCHEMA_REQUIRED');edHold(r);
});
test('1ED cyclic JSON, excessively large payload and malformed clock fail closed',()=>{
 let f=edFixture();f.args.handoffCandidate.circular=f.args;
 let r=edAssess(f);has(r,'ED_EXACT_BOUNDED_INPUT_REQUIRED');edHold(r);
 f=edFixture();f.args.handoffCandidate.overflow='x'.repeat(4096*1024);
 r=edAssess(f);has(r,'ED_EXACT_BOUNDED_INPUT_REQUIRED');edHold(r);
 f=edFixture();f.args.now='not-a-utc';
 r=edAssess(f);
 has(r,'ED_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'ED_ORIGINAL_EC_AUTHORITY_HANDOFF_NOT_REVERIFIED');edHold(r);
});
test('1ED redacted frozen report contains no local signer, source hash, adapter ID or nonce',()=>{
 const f=edFixture(),r=edAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.workOrders[0].requestNonce,
  f.args.receipts[0].adapterId,
  f.args.workOrders[0].sourceHeadSha,
  f.args.handoffCandidate.reviewPackets[0].signature,
  f.args.handoffCandidate.manifest.challengeNonce,
  f.args.workOrders[3].manifestSha256
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);edHold(r);
});

/* Phase 1EE: pinned V1 ONLY / disconnected port-specific simulated faults.
 * This is not a real provider call, authenticated CA status or release vote. */
import {EE_SUPPORTED_PROTOCOL_VERSION,EE_PORT_FAILURE_CLASSES,
 compatibilityDigestEe,receiptDigestEe,sourceBundleDigestEe,
 createDisconnectedFailurePlansEe,planDigestEe,failureDigestEe,
 assessDisconnectedVersionFailureTaxonomyEe}
 from '../scripts/phase1ee-disconnected-version-failure-taxonomy.mjs';

function eeFixture(){
 const ed=edFixture(),p=ed.args,
  plans=createDisconnectedFailurePlansEe(p);
 let previousSha=sourceBundleDigestEe(p);
 const failureEvents=plans.map((plan,i)=>{
  const event={
   schemaVersion:1,kind:'APPLICANT_SIMULATED_ADAPTER_FAULT_HOLD',
   gate:plan.gate,planSha256:planDigestEe(plan),
   sequence:i+1,previousFailureSha256:previousSha,
   faultCode:'NOT_ATTEMPTED',simulated:true,
   networkRequests:0,authoritiesAuthenticated:0,sideEffects:0,
   retryPolicy:'HOLD_MANUAL_AUTH_REVIEW',
   observedAt:'2026-11-21T00:00:'+String(i+38)+'.000Z',
   expiresAt:'2026-11-21T00:10:00.000Z',
   disposition:'REMAINS_QUARANTINED',releaseDecision:'HOLD'
  };
  previousSha=failureDigestEe(event);
  return event;
 });
 return {args:{previousPortCandidate:p,plans:clone(plans),
  failureEvents:clone(failureEvents),now:NOW},
  source:ed,generatedPlans:plans};
}
const eeAssess=f=>assessDisconnectedVersionFailureTaxonomyEe(f.args);
function eeResignSuffix(f,changedIndex){
 let prev=changedIndex===0?sourceBundleDigestEe(f.args.previousPortCandidate):
  failureDigestEe(f.args.failureEvents[changedIndex-1]);
 for(let i=changedIndex;i<12;i++){
  f.args.failureEvents[i].previousFailureSha256=prev;
  prev=failureDigestEe(f.args.failureEvents[i]);
 }
}
const eeHold=r=>{
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.externalAdapterOrNetworkInvocationPerformed,false);
 assert.equal(r.genuineExternalProviderMcaCcaRcaiEmudhraAuthorityVerified,false);
 assert.equal(r.realIssuerSignedCrlOcspOrTlsSourceVerified,false);
 assert.equal(r.independentDurableCasWormGossipOrDrAccepted,false);
 assert.equal(r.independentLegalSecurityReviewerStagingReleaseAuthorized,false);
 assert.equal(r.mockFailureDiagnosisCanNeverUnfreezeIncident,true);
};
test('1EE strict V1 plans and 12 chained NOT_ATTEMPTED mock failures remain release HOLD',()=>{
 const f=eeFixture(),r=eeAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.precedingEdToDuOriginalHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.exactlyPinnedV1ProtocolPlans,12);
 assert.equal(r.linkedMockFailureEventsMathematicallyConsistentOnly,12);
 assert.equal(r.notAttemptedLocalAdapterCount,12);
 assert.equal(r.syntheticVersionAndFailureTranscriptConsistentOnly,true);
 assert.equal(EE_SUPPORTED_PROTOCOL_VERSION,1);
 eeHold(r);
});
test('1EE all 12 gate-specific simulated failure categories are pinned and immutable',()=>{
 const f=eeFixture();
 assert.equal(Object.keys(EE_PORT_FAILURE_CLASSES).length,12);
 assert.equal(Object.isFrozen(EE_PORT_FAILURE_CLASSES),true);
 for(const p of f.args.plans){
  const codes=EE_PORT_FAILURE_CLASSES[p.gate];
  assert.equal(codes.length,2);assert.equal(Object.isFrozen(codes),true);
  assert.equal(codes[0],'NOT_ATTEMPTED');
  assert.ok(codes[1].startsWith('SIMULATED_'));
  assert.equal(codes.includes('VERIFIED'),false);
  assert.equal(codes.includes('PRODUCTION_RELEASE'),false);
 }
 assert.equal(Object.isFrozen(f.generatedPlans),true);
});
test('1EE 12 gate-specific locally injected failures may diagnose only, never grant GO',()=>{
 const f=eeFixture();
 f.args.failureEvents.forEach((r,i)=>
  r.faultCode=EE_PORT_FAILURE_CLASSES[f.args.plans[i].gate][1]);
 eeResignSuffix(f,0);
 const r=eeAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.notAttemptedLocalAdapterCount,0);
 assert.equal(r.syntheticVersionAndFailureTranscriptConsistentOnly,true);
 eeHold(r);
});
test('1EE version negotiation rejects downgrade, upgrade, or broad negotiated range',()=>{
 for(const [field,value] of [
  ['requestedVersion',0],['requestedVersion',2],
  ['minimumAcceptedVersion',0],['maximumAcceptedVersion',2]
 ]){
  const f=eeFixture();
  assert.notEqual(f.args.plans[0][field],value);
  f.args.plans[0][field]=value;
  const r=eeAssess(f);
  has(r,'EE_VERSION_DOWNGRADE_UPGRADE_OR_SCOPE_FORK');eeHold(r);
 }
});
test('1EE silent fallback, alternate live adapter mode or fake compatibility V2 denied',()=>{
 for(const [field,value] of [
  ['fallbackPolicy','PREFER_LEGACY'],
  ['negotiation','NEGOTIATE_LATEST'],
  ['adapterExecution','HTTPS_PROVIDER_LIVE'],
  ['compatibilitySha256','f'.repeat(64)]
 ]){
  const f=eeFixture();
  assert.notEqual(f.args.plans[3][field],value);
  f.args.plans[3][field]=value;
  const r=eeAssess(f);
  has(r,'EE_VERSION_DOWNGRADE_UPGRADE_OR_SCOPE_FORK');eeHold(r);
 }
});
test('1EE source manifest, work order or ED receipt hash mismatch rejects plan handoff',()=>{
 for(const [field,value] of [
  ['sourceBundleSha256','f'.repeat(64)],
  ['receiptSha256','f'.repeat(64)],
  ['workOrderSha256','f'.repeat(64)]
 ]){
  const f=eeFixture();
  assert.notEqual(f.args.plans[5][field],value);
  f.args.plans[5][field]=value;
  const r=eeAssess(f);
  has(r,'EE_VERSION_DOWNGRADE_UPGRADE_OR_SCOPE_FORK');eeHold(r);
 }
});
test('1EE re-ordered, duplicated, truncated or inserted future-version plan is denied',()=>{
 for(const edit of [
  x=>x.plans.reverse(),
  x=>{x.plans[1]=clone(x.plans[0]);},
  x=>x.plans.pop(),
  x=>{x.plans.push(clone(x.plans[0]));}
 ]){
  const f=eeFixture();edit(f.args);
  const r=eeAssess(f);
  assert.ok(r.anomalyCodes.some(code=>code.startsWith('EE_')));eeHold(r);
 }
});
test('1EE a locally simulated TLS failure is invalid on an unrelated CRL/OCSP port',()=>{
 const f=eeFixture(),e=f.args.failureEvents[3];
 e.faultCode='SIMULATED_TLS_SPKI_MISMATCH';
 eeResignSuffix(f,3);
 const r=eeAssess(f);
 has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
});
test('1EE generic network timeout, issuer authenticated and positive provider results denied',()=>{
 for(const code of ['VERIFIED','GO','PROVIDER_LICENSE_APPROVED',
  'SIMULATED_NETWORK_TIMEOUT','SIMULATED_ISSUER_VALID']){
  const f=eeFixture(),e=f.args.failureEvents[0];
  e.faultCode=code;eeResignSuffix(f,0);
  const r=eeAssess(f);
  has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
 }
});
test('1EE failure response cannot claim live calls, authority, side effects or source unfreeze',()=>{
 for(const [field,value] of [
  ['simulated',false],['networkRequests',1],
  ['authoritiesAuthenticated',1],['sideEffects',1],
  ['retryPolicy','AUTO_PROVIDER_RETRY'],
  ['disposition','UNFREEZE_SOURCE'],['releaseDecision','GO']
 ]){
  const f=eeFixture(),e=f.args.failureEvents[0];
  assert.notEqual(e[field],value);
  e[field]=value;eeResignSuffix(f,0);
  const r=eeAssess(f);
  has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
 }
});
test('1EE copy/paste of a successful-looking failure event is detected as replay',()=>{
 for(const edit of [
  f=>{f.args.failureEvents[1]=clone(f.args.failureEvents[0]);},
  f=>{f.args.failureEvents.reverse();},
  f=>{f.args.failureEvents[2].sequence=3+1;},
  f=>{f.args.failureEvents[4].previousFailureSha256='f'.repeat(64);}
 ]){
  const f=eeFixture();edit(f);
  const r=eeAssess(f);
  has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
 }
});
test('1EE attacker rehashes downstream events but cannot hide wrong source-root anchor',()=>{
 const f=eeFixture();
 f.args.failureEvents[0].previousFailureSha256='f'.repeat(64);
 eeResignSuffix(f,1);
 const r=eeAssess(f);
 has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
});
test('1EE changed fault transcript and recalculated full SHA suffix cannot spoof another gate',()=>{
 const f=eeFixture();
 f.args.failureEvents[4].gate=f.args.failureEvents[5].gate;
 eeResignSuffix(f,4);
 const r=eeAssess(f);
 has(r,'EE_FAILURE_SCOPE_REPLAY_UNSUPPORTED_CLASS_OR_FALSE_AUTHORITY');eeHold(r);
});
test('1EE truncated and duplicated failure events fail exact 12-gate chain',()=>{
 for(const edit of [
  x=>x.failureEvents.pop(),
  x=>x.failureEvents.push(clone(x.failureEvents[0]))
 ]){
  const f=eeFixture();edit(f.args);
  const r=eeAssess(f);
  has(r,'EE_EXACT_TWELVE_FAILURE_EVENTS_REQUIRED');eeHold(r);
 }
});
test('1EE failed event later than expiry, earlier than receipt, future or nonmonotonic rejected',()=>{
 for(const [field,value] of [
  ['observedAt','2026-11-21T00:00:36.000Z'],
  ['observedAt','2026-11-21T00:10:00.000Z'],
  ['expiresAt','2026-11-20T23:59:59.000Z'],
  ['expiresAt','2026-11-21T00:00:38.000Z'],
  ['observedAt','2026-11-21T00:00:40.000Z']
 ]){
  const f=eeFixture(),e=f.args.failureEvents[0];
  assert.notEqual(e[field],value);
  e[field]=value;eeResignSuffix(f,0);
  const r=eeAssess(f);
  has(r,'EE_FAILURE_EVENT_ORDER_FRESHNESS_OR_EXPIRY_INVALID');eeHold(r);
 }
});
test('1EE original 1ED fake VERIFIED status mutation invalidates every negotiation',()=>{
 const f=eeFixture();
 f.args.previousPortCandidate.receipts[0].status='VERIFIED';
 const r=eeAssess(f);
 has(r,'EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');eeHold(r);
});
test('1EE old source work order with changed signer or evidence SHA cannot be reused',()=>{
 for(const edit of [
  ed=>{ed.workOrders[0].sourceHeadSha='f'.repeat(40);},
  ed=>{ed.workOrders[2].manifestSha256='f'.repeat(64);},
  ed=>{ed.handoffCandidate.manifest.decision='GO';}
 ]){
  const f=eeFixture();edit(f.args.previousPortCandidate);
  const r=eeAssess(f);
  has(r,'EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');eeHold(r);
 }
});
test('1EE signed original DU witness history tampering still fails closed in V1 layer',()=>{
 const f=eeFixture();
 f.args.previousPortCandidate.handoffCandidate.incidentCandidate
  .gossipCandidate.anchorCandidate.admissionCandidate.rehearsalCandidate
  .custodyCandidate.publicationCandidate.history.epochs[0]
  .checkpointObservations[0].manifest.decision='GO';
 const r=eeAssess(f);
 has(r,'EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');eeHold(r);
});
test('1EE extra approved flag and malformed failure packet never become compatible V1',()=>{
 let f=eeFixture();
 f.args.plans[0].productionReady=true;
 let r=eeAssess(f);
 has(r,'EE_VERSION_DOWNGRADE_UPGRADE_OR_SCOPE_FORK');eeHold(r);
 f=eeFixture();f.args.failureEvents[0].issuerApproved=true;
 r=eeAssess(f);has(r,'EE_FAILURE_EVENT_SCHEMA_INVALID');eeHold(r);
});
test('1EE cyclic, oversized, malformed ancestor, missing UTC and unexpected top flag fail',()=>{
 let f=eeFixture();
 let r=assessDisconnectedVersionFailureTaxonomyEe({...f.args,authenticated:true});
 has(r,'EE_EXACT_BOUNDED_INPUT_REQUIRED');eeHold(r);
 f=eeFixture();f.args.previousPortCandidate.self=f.args;
 r=eeAssess(f);has(r,'EE_EXACT_BOUNDED_INPUT_REQUIRED');eeHold(r);
 f=eeFixture();f.args.previousPortCandidate.extra='z'.repeat(4608*1024);
 r=eeAssess(f);has(r,'EE_EXACT_BOUNDED_INPUT_REQUIRED');eeHold(r);
 f=eeFixture();f.args.previousPortCandidate.receipts={notArray:1};
 r=eeAssess(f);has(r,'EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');eeHold(r);
 f=eeFixture();f.args.now=null;
 r=eeAssess(f);
 has(r,'EE_EXPLICIT_UTC_CLOCK_REQUIRED');
 has(r,'EE_ORIGINAL_ED_HISTORY_NOT_REVERIFIED');eeHold(r);
});
test('1EE protocol binding changes when actual original receipt record changes',()=>{
 const f=eeFixture(),d=compatibilityDigestEe();
 assert.match(d,/^[a-f0-9]{64}$/);
 assert.equal(d,compatibilityDigestEe());
 const first=receiptDigestEe(f.args.previousPortCandidate.receipts[0]);
 const copy=clone(f.args.previousPortCandidate.receipts[0]);
 copy.status='SIMULATED_MISSING';
 assert.notEqual(receiptDigestEe(copy),first);
 assert.equal(failureDigestEe(f.args.failureEvents[0]).length,64);
 assert.equal(planDigestEe(f.args.plans[0]).length,64);
});
test('1EE report never leaks applicant adapter IDs, private signatures, source digest or nonce',()=>{
 const f=eeFixture(),r=eeAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.previousPortCandidate.receipts[0].adapterId,
  f.args.failureEvents[0].previousFailureSha256,
  f.args.plans[0].sourceBundleSha256,
  f.args.previousPortCandidate.handoffCandidate.reviewPackets[0].signature,
  f.args.previousPortCandidate.workOrders[0].requestNonce
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);eeHold(r);
});


/* Phase 1EF: local-only source-bound incident quarantine escalation records. */
import {EF_INDEPENDENT_AUTHORITY_ROLES,
 failureTranscriptDigestEf,quarantineCaseDigestEf,
 createOfflineQuarantineCasesEf,assessOfflineQuarantineEscalationEf}
 from '../scripts/phase1ef-disconnected-quarantine-escalation.mjs';
function efFixture(){
 const f=eeFixture();
 return {args:{previousFailureCandidate:f.args,
  cases:clone(createOfflineQuarantineCasesEf(f.args)),now:NOW}};
}
const efAssess=f=>assessOfflineQuarantineEscalationEf(f.args);
function efHold(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualIndependentAuthorityCasesClosed,0);
 assert.equal(r.independentReviewerOrProviderAuthenticated,false);
 assert.equal(r.externalIssuerOrLegalEvidenceVerified,false);
 assert.equal(r.externalNetworkOrAdapterExecutionPerformed,false);
 assert.equal(r.durableOffPlatformCaseOrAuditLogWritten,false);
 assert.equal(r.localCasesCannotCloseOrUnfreezeProduction,true);
}
test('1EF 12 source-linked local quarantine cases never complete genuine gate approvals',()=>{
 const f=efFixture(),r=efAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.fullOriginalEeToDuHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.exactApplicantControlledQuarantineCases,12);
 assert.equal(r.notAttemptedAuthorityGates,12);
 assert.equal(r.injectedSimulatedFaultCases,0);
 assert.equal(r.syntheticEscalationTranscriptConsistentOnly,true);
 assert.equal(Object.keys(EF_INDEPENDENT_AUTHORITY_ROLES).length,12);
 assert.equal(Object.isFrozen(EF_INDEPENDENT_AUTHORITY_ROLES),true);
 efHold(r);
});
test('1EF all 12 correctly injected negative fault classes still require external authority',()=>{
 const f=eeFixture();
 f.args.failureEvents.forEach((e,i)=>e.faultCode=
  EE_PORT_FAILURE_CLASSES[f.args.plans[i].gate][1]);
 eeResignSuffix(f,0);
 const cases=createOfflineQuarantineCasesEf(f.args);
 const r=assessOfflineQuarantineEscalationEf({
  previousFailureCandidate:f.args,cases,now:NOW});
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.injectedSimulatedFaultCases,12);
 assert.equal(r.notAttemptedAuthorityGates,0);
 assert.ok(cases.every(c=>c.classification==='INJECTED_SIMULATED_FAULT_NOT_AUTHORITY'));
 efHold(r);
});
test('1EF falsely CLOSED, GO, approved or verified applicant case is rejected',()=>{
 for(const [field,value] of [
  ['caseStatus','CLOSED'],['releaseDecision','GO'],
  ['reviewerAuthenticated',true],['remoteEvidenceVerified',true],
  ['issuerOrLegalApprovalVerified',true],
  ['closurePolicy','AUTOMATIC_APPROVAL']
 ]){
  const f=efFixture();f.args.cases[0][field]=value;
  const r=efAssess(f);
  has(r,'EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');efHold(r);
 }
});
test('1EF auto-retry, nonzero external IO and fake independent custodian rejected',()=>{
 for(const [field,value] of [
  ['retryPolicy','AUTO_RETRY'],['networkRequests',1],['sideEffects',1],
  ['requiredIndependentAuthorityRole','SELF_APPROVED_APP_AUTHOR'],
  ['classification','VERIFIED_EXTERNAL_APPROVAL']
 ]){
  const f=efFixture();f.args.cases[4][field]=value;
  has(efAssess(f),'EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');
 }
});
test('1EF wrong incident source, plan, event, previous case or transcript root denied',()=>{
 for(const field of [
  'sourceBundleSha256','failureTranscriptSha256','versionPlanSha256',
  'faultEventSha256','previousCaseSha256'
 ]){
  const f=efFixture();f.args.cases[3][field]='f'.repeat(64);
  has(efAssess(f),'EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');
 }
});
test('1EF gate swap, missing/duplicate case, reorder or changed sequence denied',()=>{
 for(const edit of [
  c=>c[2].gate=c[1].gate,c=>c.pop(),
  c=>c.push(clone(c[0])),c=>c.reverse(),
  c=>{c[7]=clone(c[6]);},c=>{c[5].sequence=3;}
 ]){
  const f=efFixture();edit(f.args.cases);
  const r=efAssess(f);
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('EF_')));efHold(r);
 }
});
test('1EF rehashing a fabricated locally consistent case cannot bypass original source binding',()=>{
 const f=efFixture();f.args.cases[0].faultCode='SIMULATED_PROVIDER_LICENSE_ABSENT';
 let prior=quarantineCaseDigestEf(f.args.cases[0]);
 for(let i=1;i<12;i++){
  f.args.cases[i].previousCaseSha256=prior;
  prior=quarantineCaseDigestEf(f.args.cases[i]);
 }
 has(efAssess(f),'EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');
});
test('1EF previous EE v0/GO or forged ED real issuer VERIFIED never passes upstream check',()=>{
 for(const edit of [
  ee=>{ee.plans[0].requestedVersion=0;},
  ee=>{ee.failureEvents[0].releaseDecision='GO';},
  ee=>{ee.previousPortCandidate.receipts[3].status='VERIFIED';}
 ]){
  const f=efFixture();edit(f.args.previousFailureCandidate);
  const r=efAssess(f);has(r,'EF_ORIGINAL_EE_HISTORY_NOT_REVERIFIED');
  efHold(r);
 }
});
test('1EF independent case generator rejects altered original signed source and 1EE negotiation',()=>{
 const f=eeFixture();
 f.args.previousPortCandidate.handoffCandidate.manifest.decision='GO';
 assert.throws(()=>createOfflineQuarantineCasesEf(f.args),
  /EF_FULL_ORIGINAL_EE_HISTORY_NOT_REVERIFIED/);
 const g=eeFixture();g.args.plans[0].fallbackPolicy='ALLOW_LEGACY';
 assert.throws(()=>createOfflineQuarantineCasesEf(g.args),
  /EF_FULL_ORIGINAL_EE_HISTORY_NOT_REVERIFIED/);
});
test('1EF exact schema rejects extra production approval fields and root-time disagreement',()=>{
 let f=efFixture();f.args.cases[0].approved=true;
 has(efAssess(f),'EF_QUARANTINE_SCOPE_REPLAY_FALSE_CLOSURE_OR_AUTHORITY');
 f=efFixture();f.args.authorized=true;
 has(efAssess(f),'EF_EXACT_BOUNDED_INPUT_REQUIRED');
 f=efFixture();f.args.now='2026-11-21T00:00:01.000Z';
 has(efAssess(f),'EF_ORIGINAL_EE_HISTORY_NOT_REVERIFIED');
});
test('1EF malformed, cyclic or oversized object fails closed without uncaught exception',()=>{
 let f=efFixture();f.args.cases[0].self=f.args;
 has(efAssess(f),'EF_EXACT_BOUNDED_INPUT_REQUIRED');
 f=efFixture();f.args.cases[0].extra='x'.repeat(4800*1024);
 has(efAssess(f),'EF_EXACT_BOUNDED_INPUT_REQUIRED');
 assert.throws(()=>quarantineCaseDigestEf({approved:true}),
  /EF_EXACT_QUARANTINE_CASE_REQUIRED/);
});
test('1EF generated quarantine tickets and redacted report are frozen and do not expose source identifiers',()=>{
 const ee=eeFixture(),cases=createOfflineQuarantineCasesEf(ee.args);
 assert.equal(Object.isFrozen(cases),true);
 assert.ok(cases.every(Object.isFrozen));
 assert.match(failureTranscriptDigestEf(ee.args),/^[0-9a-f]{64}$/);
 const r=assessOfflineQuarantineEscalationEf({
  previousFailureCandidate:ee.args,cases,now:NOW});
 const s=JSON.stringify(r);
 for(const secret of [
  cases[0].sourceBundleSha256,cases[0].failureTranscriptSha256,
  cases[3].faultEventSha256,ee.args.failureEvents[0].planSha256,
  ee.args.previousPortCandidate.receipts[0].adapterId
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);
 efHold(r);
});



/* Phase 1EG: source-bound unsent manual authority handoff; never a live workflow. */
import {EG_MANUAL_EVIDENCE_REQUEST_TYPES,manualRequestDigestEg,
 createUnsentManualHandoffEg,assessUnsentManualHandoffEg}
 from '../scripts/phase1eg-unsent-manual-authority-handoff.mjs';
function egFixture(){
 const ef=efFixture();
 return {args:{previousQuarantineCandidate:ef.args,
  requests:clone(createUnsentManualHandoffEg(ef.args)),now:NOW}};
}
const egAssess=f=>assessUnsentManualHandoffEg(f.args);
function egHold(r){
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.equal(r.actualRequestsSent,0);
 assert.equal(r.actualIndependentReviewersAuthenticated,0);
 assert.equal(r.externalIssuerLegalOrProviderEvidenceVerified,false);
 assert.equal(r.independentRemoteCustodyOrAuditStorageVerified,false);
 assert.equal(r.autoRetryOrExternalIOPerformed,false);
 assert.equal(r.manualHandoffCannotActivateOrCloseCases,true);
}
test('1EG twelve unsent human-authority requests preserve permanent HARD HOLD',()=>{
 const f=egFixture(),r=egAssess(f);
 assert.deepEqual(r.anomalyCodes,[]);
 assert.equal(r.fullOriginalEfToDuHistoryReverifiedMathematicallyOnly,true);
 assert.equal(r.applicantControlledUnsentRequestsValidated,12);
 assert.equal(Object.keys(EG_MANUAL_EVIDENCE_REQUEST_TYPES).length,12);
 assert.ok(f.args.requests.every(x=>x.requestState==='NOT_SENT_NOT_APPROVED'));
 egHold(r);
});
test('1EG deterministic request digests and predecessor link across all 12 gates',()=>{
 const f=egFixture(),requests=f.args.requests;
 assert.equal(requests[0].previousRequestSha256,
  requests[0].failureTranscriptSha256);
 for(let i=1;i<12;i++)
  assert.equal(requests[i].previousRequestSha256,
   manualRequestDigestEg(requests[i-1]));
 assert.deepEqual(requests,createUnsentManualHandoffEg(f.args.previousQuarantineCandidate));
 egHold(egAssess(f));
});
test('1EG forged approved, dispatched, closed or verified case never becomes sent',()=>{
 for(const [field,value] of [
  ['requestState','APPROVED'],['requestDispatched',true],
  ['caseClosed',true],['reviewerAuthenticated',true],
  ['externalEvidenceVerified',true],['releaseDecision','GO']
 ]){
  const f=egFixture();f.args.requests[0][field]=value;
  has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
  egHold(egAssess(f));
 }
});
test('1EG no automatic retries, external I/O, or removal of manual review',()=>{
 for(const [field,value] of [
  ['autoRetryAllowed',true],['networkRequests',1],
  ['sideEffects',1],['manualIndependentAuthorityRequired',false]
 ]){
  const f=egFixture();f.args.requests[3][field]=value;
  has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
 }
});
test('1EG cannot substitute reviewer role, external request type or gate order',()=>{
 for(const [field,value] of [
  ['gate','LIVE_ISSUER_SIGNED_CRL_OCSP'],
  ['requiredIndependentAuthorityRole','APPLICANT_AUTHOR'],
  ['requestType','EXECUTE_LIVE_PROVIDER_CALL'],['sequence',11]
 ]){
  const f=egFixture();f.args.requests[2][field]=value;
  has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
 }
});
test('1EG swapped, cloned, missing and extra request records are denied',()=>{
 for(const edit of [
  r=>r.reverse(),r=>{r[1]=clone(r[0]);},
  r=>r.pop(),r=>r.push(clone(r[0]))
 ]){
  const f=egFixture();edit(f.args.requests);
  const r=egAssess(f);
  assert.ok(r.anomalyCodes.some(x=>x.startsWith('EG_')));egHold(r);
 }
});
test('1EG source/fault/case hash scope changes cannot silently rebind',()=>{
 for(const field of [
  'failureTranscriptSha256','quarantineCaseSha256','previousRequestSha256'
 ]){
  const f=egFixture();f.args.requests[4][field]='f'.repeat(64);
  has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
 }
});
test('1EG attacker rehashing the entire downstream request chain still fails',()=>{
 const f=egFixture();f.args.requests[0].requestType=
  'SIGNED_PROVIDER_LICENSE_REVIEW_WRONG';
 let digest=null;
 for(let i=1;i<12;i++){
  if(i===1){f.args.requests[0].requestType='SIGNED_PROVIDER_LICENSE_REVIEW';}
  if(i===1){f.args.requests[0].quarantineCaseSha256='f'.repeat(64);}
  digest=manualRequestDigestEg(f.args.requests[i-1]);
  f.args.requests[i].previousRequestSha256=digest;
 }
 has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
});
test('1EG upstream EF forged case closure and EE downgrade invalidate every request',()=>{
 for(const edit of [
  f=>{f.args.previousQuarantineCandidate.cases[0].caseStatus='CLOSED';},
  f=>{f.args.previousQuarantineCandidate.previousFailureCandidate.plans[0].requestedVersion=0;}
 ]){
  const f=egFixture();edit(f);
  has(egAssess(f),'EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED');
  egHold(egAssess(f));
 }
});
test('1EG generator refuses applicant-only fake independent evidence',()=>{
 const f=efFixture();
 f.args.cases[0].reviewerAuthenticated=true;
 assert.throws(()=>createUnsentManualHandoffEg(f.args),
  /EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED/);
});
test('1EG extra production fields, cyclic graph and malformed input fail closed',()=>{
 let f=egFixture();f.args.approved=true;
 has(egAssess(f),'EG_EXACT_BOUNDED_INPUT_REQUIRED');
 f=egFixture();f.args.requests[0].trustedAuthority=true;
 has(egAssess(f),'EG_UNSENT_REQUEST_REPLAY_SCOPE_OR_FALSE_AUTHORITY');
 f=egFixture();f.args.requests[0].self=f.args;
 has(egAssess(f),'EG_EXACT_BOUNDED_INPUT_REQUIRED');
 f=egFixture();f.args.requests[0].extra='x'.repeat(5000*1024);
 has(egAssess(f),'EG_EXACT_BOUNDED_INPUT_REQUIRED');
 assert.throws(()=>manualRequestDigestEg({approved:true}),
  /EG_EXACT_UNSENT_REQUEST_REQUIRED/);
});
test('1EG strict clock and changed original EE source are refused',()=>{
 let f=egFixture();f.args.now='2026-11-21T00:00:01.000Z';
 has(egAssess(f),'EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED');
 f=egFixture();
 f.args.previousQuarantineCandidate.previousFailureCandidate
  .previousPortCandidate.receipts[3].status='VERIFIED';
 has(egAssess(f),'EG_ORIGINAL_EF_HISTORY_NOT_REVERIFIED');
});
test('1EG output is frozen, redacted and does not disclose request scope hashes',()=>{
 const f=egFixture(),r=egAssess(f),s=JSON.stringify(r);
 for(const secret of [
  f.args.requests[0].quarantineCaseSha256,
  f.args.requests[0].failureTranscriptSha256,
  f.args.previousQuarantineCandidate.cases[0].sourceBundleSha256,
  f.args.previousQuarantineCandidate.previousFailureCandidate
   .previousPortCandidate.receipts[0].adapterId
 ])assert.equal(s.includes(secret),false);
 assert.equal(Object.isFrozen(r),true);
 assert.equal(Object.isFrozen(r.anomalyCodes),true);
 const generated=createUnsentManualHandoffEg(f.args.previousQuarantineCandidate);
 assert.equal(Object.isFrozen(generated),true);
 assert.ok(generated.every(Object.isFrozen));
 egHold(r);
});
