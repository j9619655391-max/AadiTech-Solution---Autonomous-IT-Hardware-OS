import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {AZ_PURPOSE,phase1AzAssessReadiness} from '../../scripts/lib/phase1AzExternalReadiness.mjs';
import {BB_PURPOSE,phase1BbSignedBytes} from '../../scripts/lib/phase1BbEvidenceIntake.mjs';

export const now=new Date('2026-11-16T18:00:00.000Z');
export const h=n=>n.toString(16).padStart(64,'0');
const sha=b=>createHash('sha256').update(b).digest('hex');
function signer(role,ref,auth){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const pin={role,sourceRef:ref,authorityRef:auth,keyId:'key-'+ref,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:sha(publicKey.export({format:'der',type:'spki'}))};
 return {privateKey,pin};
}
export function fixture(logRef='checkpoint-log-001'){
 const actors=[
  signer('WITNESS','witness-first-001','witness-admin-001'),
  signer('WITNESS','witness-second-002','witness-admin-002'),
  signer('STORAGE_AUDITOR','storage-observer-003','storage-admin-003'),
  signer('SECURITY','security-reviewer-004','security-admin-004'),
  signer('OPERATIONS','operations-reviewer-005','operations-admin-005'),
  signer('OWNER','owner-reviewer-006','owner-admin-006')
 ];
 const azPacket={schemaVersion:1,purpose:AZ_PURPOSE,revision:1,
  previousPacketSha256:null,
  witnesses:actors.slice(0,2).map((s,i)=>({
   witnessRef:s.pin.sourceRef,organizationRef:'witness-org-'+(i+1).toString().padStart(3,'0'),
   administrativeAuthorityRef:s.pin.authorityRef,
   publicKeySpkiSha256:s.pin.publicKeySha256,contractSha256:h(i+1),
   publisherPolicySha256:h(i+21),scope:'CHECKPOINT_WITNESS_ONLY',
   state:'CANDIDATE_UNVERIFIED'})),
  archive:{logRef,checkpointReceiptSha256:h(31),archiveObjectSha256:h(32),
   storageAccountSha256:h(33),objectVersionIdSha256:h(34),
   retentionPolicySha256:h(35),encryptionKeyIdentifierSha256:h(36),
   claimedLockMode:'COMPLIANCE',legalHoldEvidenceSha256:h(37),
   createdAt:'2026-11-01T00:00:00.000Z',
   retentionUntil:'2027-05-01T00:00:00.000Z',
   minimumRetentionDays:90,externalStorageState:'NOT_VERIFIED'},
  recovery:{incidentRef:'incident-dr-001',sourceCheckpointReceiptSha256:h(31),
   restoredCheckpointReceiptSha256:h(31),
   sourceManifestSha256:h(38),restoredManifestSha256:h(38),
   archiveObjectSha256:h(32),revocationSnapshotSha256:h(39),
   startedAt:'2026-11-15T16:00:00.000Z',
   completedAt:'2026-11-15T16:05:00.000Z',measuredRpoMs:500,
   rtoObjectiveMs:600000,rpoObjectiveMs:2000,
   encryptedRestoreState:'NOT_EXTERNALLY_VERIFIED',outboundHeld:true},
  approvers:actors.slice(3).map((s,i)=>({
   role:s.pin.role,reviewerRef:s.pin.sourceRef,authorityRef:s.pin.authorityRef,
   reviewRecordSha256:h(41+i)})),releaseDecision:'HOLD'};
 const packetSha256=phase1AzAssessReadiness(azPacket,{now}).packetSha256;
 assert.match(packetSha256,/^[0-9a-f]{64}$/);
 const records=actors.map((actor,i)=>{
  const role=actor.pin.role;
  const subjectSha256=role==='WITNESS'?azPacket.archive.checkpointReceiptSha256:
   role==='STORAGE_AUDITOR'?azPacket.archive.archiveObjectSha256:
    azPacket.recovery.restoredManifestSha256;
  const evidenceSha256=role==='WITNESS'?azPacket.witnesses[i].publisherPolicySha256:
   role==='STORAGE_AUDITOR'?azPacket.archive.legalHoldEvidenceSha256:
    azPacket.approvers[i-3].reviewRecordSha256;
  const body={schemaVersion:1,purpose:BB_PURPOSE,packetSha256,logRef,
   sourceRole:role,sourceRef:actor.pin.sourceRef,authorityRef:actor.pin.authorityRef,
   keyId:actor.pin.keyId,publicKeySha256:actor.pin.publicKeySha256,
   challengeSha256:h(100+i),subjectSha256,evidenceSha256,
   issuedAt:'2026-11-16T17:30:00.000Z',expiresAt:'2026-11-16T18:30:00.000Z',
   authorityState:'CANDIDATE_UNVERIFIED',releaseDecision:'HOLD'};
  const signature={sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
   signatureBase64:sign(null,phase1BbSignedBytes(body),actor.privateKey).toString('base64')};
  return {body,pin:actor.pin,signature};
 });
 return {azPacket,records,actors,now};
}
