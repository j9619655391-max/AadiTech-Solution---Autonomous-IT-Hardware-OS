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
