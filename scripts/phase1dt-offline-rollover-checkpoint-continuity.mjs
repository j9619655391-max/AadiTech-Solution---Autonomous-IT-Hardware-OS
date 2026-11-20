import {Buffer} from 'node:buffer';
import {assessCrossSignedWitnessRolloverCandidate}
 from './phase1ds-offline-witness-key-rollover.mjs';
import {assessKeyIdBoundWitnessV2Candidate,V2_ROLES}
 from './phase1dr-offline-keyid-bound-witness-v2.mjs';
import {REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';

// Phase 1DT is an OFFLINE mathematical cross-envelope check. No live keys,
// signed external observations, independent publisher, authority or state writes.
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const INPUTS=['transitionCandidates','checkpointObservations','expected',
 'previousIdentityPins','comparisonPins','now'];
const CTX=['organizationId','sourceHeadSha','mainBaseSha',
 'registrarSpkiSha256','registryEvidenceSha256',
 'appointmentDigestSha256','nonce'];
const SAFE_DS=new Set(['DS_DUPLICATE_NOT_INDEPENDENT_PUBLICATION']);
const SAFE_DR=new Set(['DR_DUPLICATE_IS_NOT_INDEPENDENT_PUBLICATION']);
function validContextPinning(expected,comparisonPins){
 return OWN(expected)&&EXACT(comparisonPins,CTX)&&
  ['organizationId','sourceHeadSha','mainBaseSha'].every(k=>
   comparisonPins[k]===expected[k]);
}
function completeMathematicalSet(observations,count,unique,anomalies,allowed){
 return Array.isArray(observations)&&observations.length>=2&&
  observations.length<=8&&count===observations.length&&unique===1&&
  anomalies.every(x=>allowed.has(x));
}
/**
 * Connect a fully mathematically four-way cross-signed 1DS transition to
 * actual signed-by-the-next-keys 1DR v2 candidate bytes, rather than trusting
 * its claimed next checkpoint digest alone. Every evidence input, clock and
 * predecessor remains caller-provided and independently UNAUTHENTICATED.
 *
 * Duplicate candidate packets may establish a matching mathematical digest,
 * NEVER independent publication. No output can approve enrollment or release.
 */
export function assessOfflineRolloverCheckpointContinuity(args={}){
 const errors=new Set();
 const validArgs=EXACT(args,INPUTS);
 if(!validArgs)errors.add('DT_EXACT_INPUT_SCHEMA_REQUIRED');
 const {transitionCandidates=null,checkpointObservations=null,
  expected=null,previousIdentityPins=null,comparisonPins=null,now=null}
  =OWN(args)?args:{};
 const pinned=validContextPinning(expected,comparisonPins);
 if(!pinned)errors.add('DT_CROSS_ENVELOPE_SOURCE_PINS_MISMATCH');
 const ds=assessCrossSignedWitnessRolloverCandidate({
  candidates:transitionCandidates,expected,previousIdentityPins,now
 });
 const dsOK=completeMathematicalSet(transitionCandidates,
  ds.mathematicallyVerifiedFourSignatureCandidatesOnly,
  ds.distinctCrossSignedTransitionDigestsOnly,ds.anomalyCodes,SAFE_DS);
 if(!dsOK)errors.add('DT_TRANSITION_FOUR_WAY_OR_FORK_INVALID');
 if(ds.anomalyCodes.includes('DS_INCIDENT_RECOVERY_NEEDS_INDEPENDENT_AUTHORITY'))
  errors.add('DT_RECOVERY_REQUIRES_INDEPENDENT_MANDATE');
 if(ds.anomalyCodes.includes('DS_CROSS_SIGNED_TRANSITION_FORK_QUARANTINE'))
  errors.add('DT_SIGNED_ROLLOVER_FORK_QUARANTINE');
 const cpRange=Array.isArray(checkpointObservations)&&
  checkpointObservations.length>=2&&checkpointObservations.length<=8;
 if(!cpRange)errors.add('DT_TWO_TO_EIGHT_CHECKPOINT_PACKETS_REQUIRED');
 let dr=null,drOK=false,keyIdMatch=false,digestMatch=false;
 if(dsOK&&pinned&&cpRange&&validArgs){
  const candidate=transitionCandidates[0];
  const nextIds=Object.fromEntries(V2_ROLES.map(role=>[
   role,candidate.identities[role].next
  ]));
  const pins={
   legalWitnessSpkiSha256:nextIds.LEGAL_WITNESS.spkiSha256,
   registryWitnessSpkiSha256:nextIds.REGISTRY_WITNESS.spkiSha256
  };
  const prev=OWN(expected)?{
   sequence:expected.previousSequence,
   checkpointSha256:expected.previousCheckpointSha256
  }:null;
  dr=assessKeyIdBoundWitnessV2Candidate({
   observations:checkpointObservations,comparisonPins,witnessPins:pins,
   previousCheckpoint:prev,now
  });
  drOK=completeMathematicalSet(checkpointObservations,
   dr.verifiedV2DualSignedPacketsMathematicallyOnly,
   dr.distinctV2CheckpointDigestsOnly,dr.anomalyCodes,SAFE_DR);
  if(!drOK)errors.add('DT_NEXT_V2_DUAL_SIGNATURES_OR_FORK_INVALID');
  if(dr.signedManifestForkObservedOnly||
     dr.signedWitnessIdentityForkObservedOnly)
   errors.add('DT_NEXT_V2_SIGNED_FORK_QUARANTINE');
  // V2 signatures bind key IDs, but DR normally pins SPKI only. Here the
  // new key IDs MUST equal the four-way signed 1DS identities as well.
  keyIdMatch=drOK&&checkpointObservations.every(o=>
   V2_ROLES.every(role=>
    o.witnesses[role].keyId===nextIds[role].keyId&&
    o.witnesses[role].spkiSha256===nextIds[role].spkiSha256
   ));
  if(!keyIdMatch)errors.add('DT_NEXT_SIGNED_KEY_ID_OR_SPKI_UNBOUND');
  digestMatch=drOK&&checkpointObservations.every(o=>
   o.claimedCheckpointSha256===expected.nextCandidateCheckpointSha256
  );
  if(!digestMatch)errors.add('DT_SIGNED_NEXT_CHECKPOINT_DIGEST_MISMATCH');
 }
 if(ds.anomalyCodes.includes('DS_DUPLICATE_NOT_INDEPENDENT_PUBLICATION')||
    dr?.anomalyCodes.includes('DR_DUPLICATE_IS_NOT_INDEPENDENT_PUBLICATION'))
  errors.add('DT_REPLAYED_RECEIPTS_NOT_INDEPENDENT_PUBLICATION');
 const linked=validArgs&&pinned&&dsOK&&drOK&&keyIdMatch&&digestMatch&&
  !errors.has('DT_RECOVERY_REQUIRES_INDEPENDENT_MANDATE');
 return Object.freeze({
  phase:'1DT',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_SIGNED_ROLLOVER_CHECKPOINT_CONTINUITY_HARD_HOLD',
  repository:REPO,
  checkedSourceHeadSha:pinned?expected.sourceHeadSha:null,
  fourWayTransitionSignaturesMathematicallyVerifiedOnly:
   ds.mathematicallyVerifiedFourSignatureCandidatesOnly,
  nextV2CheckpointsMathematicallyVerifiedOnly:
   dr?.verifiedV2DualSignedPacketsMathematicallyOnly??0,
  signedTransitionAndNextV2CheckpointLinkedMathematicallyOnly:linked,
  nextV2KeyIdAndSpkiEqualCrossSignedTransitionOnly:keyIdMatch,
  claimedNextCheckpointDigestCryptographicallyCorroboratedOnly:digestMatch,
  signedForkOrInvalidEvidenceQuarantined:!linked,
  duplicatePacketsNotIndependentPublication:true,
  independentlyAuthenticatedLegalOrRegistryKeys:false,
  independentlyPublishedNextCheckpointVerified:false,
  externalTrustedClockPreviousHeadAndRevocationVerified:false,
  independentIncidentRecoveryMandateVerified:false,
  signedExternalWormCasDrAndStagingVerified:false,
  originalOfficerGithubSessionReverified:false,
  historicalV1V2AndDSDomainsUnchanged:true,
  privateKeysNoncesSignaturesAndRawKeyIdsExcludedFromOutput:true,
  mutationOrKeyEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
