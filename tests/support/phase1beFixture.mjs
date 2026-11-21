import {sign} from 'node:crypto';
import {bdFixture,h} from './phase1bdFixture.mjs';
import {assessPhase1BdEvidenceReview} from '../../scripts/lib/phase1BdEvidenceReview.mjs';
import {phase1BeFreezeSigningBytes,BE_FREEZE_PURPOSE}
 from '../../scripts/lib/phase1BeRevocationFreeze.mjs';

function signature(actor,bytes){
 return {pin:{...actor.pin},signature:{
  sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
  signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')
 }};
}
export function beFixture(logRef='be-revocation-checkpoint-001'){
 const bdEvidence=bdFixture(logRef),a=bdEvidence.azPacket.archive,
  witness=bdEvidence.witnessEnrollments,old=bdEvidence.recoveryAttestations;
 const bdReviewSha256=assessPhase1BdEvidenceReview(bdEvidence).reviewDigestSha256;
 const body={
  schemaVersion:1,purpose:BE_FREEZE_PURPOSE,logRef,
  incidentRef:'be-incident-witness-001',
  azPacketSha256:witness[0].body.packetSha256,bdReviewSha256,
  revokedWitnessRef:witness[0].body.witnessRef,
  revokedKeySpkiSha256:witness[0].pin.publicKeySha256,
  survivingWitnessRef:witness[1].body.witnessRef,
  survivingKeySpkiSha256:witness[1].pin.publicKeySha256,
  checkpointReceiptSha256:a.checkpointReceiptSha256,
  archiveObjectSha256:a.archiveObjectSha256,
  storageObjectVersionSha256:a.objectVersionIdSha256,
  revocationNoticeSha256:h(811),
  previousRevocationSnapshotSha256:old[0].body.revocationSnapshotSha256,
  claimedObjectLockDenialReceiptSha256:
   bdEvidence.storageReceipt.body.deleteDenialReceiptSha256,
  claimedEncryptedRestoreTelemetrySha256:old[0].body.telemetryReceiptSha256,
  detectedAt:'2026-11-16T17:54:00.000Z',
  freezeEffectiveAt:'2026-11-16T17:55:00.000Z',
  expiresAt:'2026-11-16T18:30:00.000Z',
  reason:'SUSPECTED_WITNESS_KEY_COMPROMISE',
  quarantineRequired:true,outboundHeld:true,releaseDecision:'HOLD'
 };
 const result={bdEvidence,body,survivingWitnessSignature:null,
  governanceSignatures:[],now:bdEvidence.now};
 // Synthetic signing helpers must never become accepted evidence fields.
 Object.defineProperty(result,'resign',{value:function(){
  const bytes=phase1BeFreezeSigningBytes(this.body);
  this.survivingWitnessSignature=signature(bdEvidence.actors[1],bytes);
  this.governanceSignatures=bdEvidence.actors.slice(3).map(x=>signature(x,bytes));
  return this;
 }});
 return result.resign();
}
