import {Buffer} from 'node:buffer';
import {assessOfflineRolloverCheckpointContinuity}
 from './phase1dt-offline-rollover-checkpoint-continuity.mjs';
import {V2_ROLES} from './phase1dr-offline-keyid-bound-witness-v2.mjs';
import {REPO} from './phase1cx-pinned-external-source-highwatermark.mjs';

// Phase 1DU: mathematical, bounded, offline history only. The entire history,
// first predecessor, clocks, key origins and observers remain applicant supplied.
const OWN=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.getPrototypeOf(x)===Object.prototype;
const EXACT=(x,fields)=>OWN(x)&&Object.keys(x).length===fields.length&&
 fields.every(k=>Object.hasOwn(x,k));
const TOP=['epochs','now'];
const EPOCH=['transitionCandidates','checkpointObservations','expected',
 'previousIdentityPins','comparisonPins'];
function bounded(x,max){try{
 const s=JSON.stringify(x);
 return typeof s==='string'&&Buffer.byteLength(s,'utf8')<=max;
}catch{return false;}}
const identity=x=>OWN(x)&&typeof x.keyId==='string'&&
 typeof x.spkiSha256==='string'?{
 keyId:x.keyId,spkiSha256:x.spkiSha256
}:null;
const sameIdentity=(a,b)=>a!==null&&b!==null&&
 a.keyId===b.keyId&&a.spkiSha256===b.spkiSha256;
function epochRecord(e){
 const rot=e.transitionCandidates?.[0],cp=e.checkpointObservations?.[0];
 if(!OWN(rot)||!OWN(cp)||!OWN(e.expected)||!OWN(rot.manifest)||
    !OWN(cp.manifest)||!OWN(cp.witnesses)||!OWN(e.previousIdentityPins))
  return null;
 const next={};
 const previous={};
 for(const role of V2_ROLES){
  next[role]=identity(cp.witnesses[role]);
  previous[role]=identity(e.previousIdentityPins[role]);
  if(!next[role]||!previous[role])return null;
 }
 return {sequence:cp.manifest.sequence,digest:cp.claimedCheckpointSha256,
  transitionDigest:rot.claimedTransitionSha256,
  rotationNonce:rot.manifest.rotationNonce,
  checkpointNonce:cp.manifest.nonce,
  rotationIssuedAt:rot.manifest.issuedAt,
  checkpointIssuedAt:cp.manifest.issuedAt,
  source:e.expected.sourceHeadSha,main:e.expected.mainBaseSha,
  organization:e.expected.organizationId,next,previous,
  expected:e.expected};
}
/**
 * Reverify 2-6 individually dual-signed, four-way rollover->v2 checkpoint
 * steps using the unchanged Phase 1DT verifier, then require an unbroken
 * sequential predecessor digest and exact previous keyId/SPKI continuity.
 * No epoch packet or Phase 1DT summary is accepted as pre-verified.
 */
export function assessOfflineMultiEpochRolloverChain(args={}){
 const errors=new Set();
 const valid=EXACT(args,TOP);
 if(!valid)errors.add('DU_EXACT_TOP_LEVEL_INPUT_REQUIRED');
 const epochs=OWN(args)?args.epochs:null,now=OWN(args)?args.now:null;
 const range=Array.isArray(epochs)&&epochs.length>=2&&epochs.length<=6;
 if(!range)errors.add('DU_TWO_TO_SIX_EPOCHS_REQUIRED');
 if(!bounded(args,512*1024))errors.add('DU_INPUT_TOO_LARGE_OR_UNSERIALIZABLE');
 const usable=valid&&range&&!errors.has('DU_INPUT_TOO_LARGE_OR_UNSERIALIZABLE');
 let verified=0,previous=null;
 const checkpoints=new Set(),transitions=new Set(),
  rotationNonces=new Set(),checkpointNonces=new Set();
 if(usable)for(let index=0;index<epochs.length;index++){
  const epoch=epochs[index];
  if(!EXACT(epoch,EPOCH)){
   errors.add('DU_EPOCH_SCHEMA_INVALID');previous=null;continue;
  }
  let result;
  try{
   result=assessOfflineRolloverCheckpointContinuity({...epoch,now});
  }catch{
   errors.add('DU_EPOCH_CRYPTO_EVALUATION_FAILED');previous=null;continue;
  }
  if(!result.signedTransitionAndNextV2CheckpointLinkedMathematicallyOnly||
     !result.nextV2KeyIdAndSpkiEqualCrossSignedTransitionOnly||
     !result.claimedNextCheckpointDigestCryptographicallyCorroboratedOnly){
   errors.add('DU_EPOCH_SIGNATURES_OR_SIGNED_FORK_INVALID');
   previous=null;continue;
  }
  const record=epochRecord(epoch);
  if(!record){errors.add('DU_EPOCH_VERIFIED_RECORD_UNAVAILABLE');
   previous=null;continue;}
  verified++;
  if(checkpoints.has(record.digest)||transitions.has(record.transitionDigest))
   errors.add('DU_REPLAYED_CHECKPOINT_OR_TRANSITION');
  if(rotationNonces.has(record.rotationNonce)||
     checkpointNonces.has(record.checkpointNonce))
   errors.add('DU_CROSS_EPOCH_SIGNED_NONCE_REUSE');
  checkpoints.add(record.digest);transitions.add(record.transitionDigest);
  rotationNonces.add(record.rotationNonce);
  checkpointNonces.add(record.checkpointNonce);
  if(index>0){
   if(!previous){
    errors.add('DU_PREDECESSOR_EPOCH_NOT_VERIFIED');
   }else{
    if(record.expected.previousSequence!==previous.sequence||
       record.sequence!==previous.sequence+1||
       record.expected.previousCheckpointSha256!==previous.digest)
     errors.add('DU_NONCONTIGUOUS_SEQUENCE_OR_PREDECESSOR');
    if(!V2_ROLES.every(role=>sameIdentity(
      record.previous[role],previous.next[role])))
     errors.add('DU_PREDECESSOR_SIGNED_KEY_ID_OR_SPKI_MISMATCH');
    if(record.source!==previous.source||record.main!==previous.main||
       record.organization!==previous.organization)
     errors.add('DU_SOURCE_OR_ORGANIZATION_CHANGED');
    if(typeof record.rotationIssuedAt!=='string'||
       record.rotationIssuedAt<=previous.rotationIssuedAt||
       typeof record.checkpointIssuedAt!=='string'||
       record.checkpointIssuedAt<previous.checkpointIssuedAt)
     errors.add('DU_SIGNED_EPOCH_TIME_ORDER_INVALID');
   }
  }
  previous=record;
 }
 const linked=usable&&verified===epochs.length&&errors.size===0;
 return Object.freeze({
  phase:'1DU',schemaVersion:1,
  kind:'UNTRUSTED_OFFLINE_MULTI_EPOCH_ROLLOVER_HISTORY_HARD_HOLD',
  repository:REPO,
  inputEpochCount:range?epochs.length:0,
  independentlyReverifiedEpochsMathematicallyOnly:verified,
  consecutiveSignedRolloverCheckpointsLinkedMathematicallyOnly:linked,
  signedHistoryForkReplayRollbackOrIdentityDriftQuarantined:!linked,
  applicantSuppliedInitialCheckpointNotExternallyAnchored:true,
  applicantSuppliedHistoryIsNotIndependentPublication:true,
  independentLegalRegistryMandatesAndWitnessKeyCustodyVerified:false,
  trustedTimeExternalWormCasTransparencyAndRevocationVerified:false,
  liveMcaCcaRcaiEmudhraAndStagingVerified:false,
  originalOfficerGithubSessionReverified:false,
  privateKeysPemSignaturesRawKeyIdsAndNoncesExcludedFromOutput:true,
  productionMutationOrKeyEnrollmentPossible:false,
  anomalyCodes:Object.freeze([...errors].sort()),
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD'
 });
}
