import {createHash,sign} from 'node:crypto';
import {bcFixture} from './phase1bcFixture.mjs';
import {phase1AzAssessReadiness} from '../../scripts/lib/phase1AzExternalReadiness.mjs';
import {assessPhase1BcWitnessCustody} from '../../scripts/lib/phase1BcWitnessCustody.mjs';
import {BD_ROTATION_PURPOSE,phase1BdRotationSigningBytes} from '../../scripts/lib/phase1BdAuthorityRotation.mjs';

export const now=new Date('2026-11-16T18:00:00.000Z');
const digest=x=>createHash('sha256').update(x).digest('hex');
const publicPin=actor=>({role:actor.pin.role,
 reviewerRef:actor.pin.sourceRef,authorityRef:actor.pin.authorityRef,
 keyId:actor.pin.keyId,publicKeyPem:actor.pin.publicKeyPem,
 publicKeySha256:actor.pin.publicKeySha256});
const signature=(actor,bytes)=>({
 reviewerRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
 signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')
});
const witnessSigned=(f,bytes)=>f.actors.slice(0,2).map((actor,i)=>({
 witnessRef:f.azPacket.witnesses[i].witnessRef,
 signature:signature(actor,bytes)
}));
export function bdRotationFixture(logRef='bd-rotation-checkpoint-001'){
 const old=bcFixture(logRef),replacement=bcFixture(logRef);
 const oldAz=phase1AzAssessReadiness(old.azPacket,{now});
 replacement.azPacket.revision=2;
 replacement.azPacket.previousPacketSha256=oldAz.packetSha256;
 const previous=old.make(2,3),next=replacement.make(3,5);
 const o=assessPhase1BcWitnessCustody(previous);
 const n=assessPhase1BcWitnessCustody(next);
 const newer=phase1AzAssessReadiness(replacement.azPacket,{now});
 const envelope={
  schemaVersion:1,purpose:BD_ROTATION_PURPOSE,logRef,
  previousPacketSha256:oldAz.packetSha256,
  replacementPacketSha256:newer.packetSha256,
  previousEvidenceSha256:o.evidenceSha256,
  replacementEvidenceSha256:n.evidenceSha256,
  previousPinSetSha256:o.pinSetSha256,
  replacementPinSetSha256:n.pinSetSha256,
  handoverTreeSize:o.newTreeSize,handoverRootSha256:o.newRootSha256,
  replacementTreeSize:n.newTreeSize,replacementRootSha256:n.newRootSha256,
  archiveObjectSha256:old.azPacket.archive.archiveObjectSha256,
  claimedObjectLockAuditSha256:digest('UNVERIFIED_WORM_CLAIM_1'),
  claimedEncryptedDrAuditSha256:digest('UNVERIFIED_RESTORE_CLAIM_1'),
  issuedAt:'2026-11-16T17:50:00.000Z',
  effectiveAt:'2026-11-16T17:55:00.000Z',
  expiresAt:'2026-11-16T18:20:00.000Z',
  reason:'KEY_ROTATION_CANDIDATE',releaseDecision:'HOLD'
 };
 const result={previous,replacement:next,envelope,
  previousWitnessSignatures:[],replacementWitnessSignatures:[],
  reviews:[],now,old,replacementFixture:replacement,
  resign(){
   const bytes=phase1BdRotationSigningBytes(this.envelope);
   this.previousWitnessSignatures=witnessSigned(old,bytes);
   this.replacementWitnessSignatures=witnessSigned(replacement,bytes);
   this.reviews=old.actors.slice(3).map(actor=>({
    pin:publicPin(actor),signature:signature(actor,bytes)
   }));
   return this;
  }
 };
 return result.resign();
}
