import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixture as bbFixture,h,now} from './phase1bbFixture.mjs';
import {assessPhase1BbEvidenceIntake} from '../../scripts/lib/phase1BbEvidenceIntake.mjs';
import {phase1BdWitnessBytes,phase1BdStorageBytes,phase1BdRecoveryBytes,
 BD_WITNESS_PURPOSE,BD_STORAGE_PURPOSE,BD_RECOVERY_PURPOSE}
 from '../../scripts/lib/phase1BdEvidenceReview.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
const attest=(body,actor,bytes)=>({
 body,pin:{...actor.pin},
 signature:{sourceRef:actor.pin.sourceRef,keyId:actor.pin.keyId,
  signatureBase64:sign(null,bytes(body),actor.privateKey).toString('base64')}
});
function storageActor(){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const sourceRef='storage-provider-001',authorityRef='storage-provider-authority-001';
 return {privateKey,pin:{
  role:'STORAGE_PROVIDER',sourceRef,authorityRef,keyId:'key-'+sourceRef,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:digest(publicKey.export({format:'der',type:'spki'}))
 }};
}
export function bdFixture(){
 const base=bbFixture();
 const {azPacket,records,actors}=base;
 const batch=assessPhase1BbEvidenceIntake({azPacket,records,now}).batchSha256;
 const packetSha=records[0].body.packetSha256,a=azPacket.archive;
 const witnessEnrollments=actors.slice(0,2).map((who,i)=>{
  const registered=azPacket.witnesses[i];
  const body={schemaVersion:1,purpose:BD_WITNESS_PURPOSE,
   packetSha256:packetSha,batchSha256:batch,
   witnessRef:registered.witnessRef,organizationRef:registered.organizationRef,
   administrativeAuthorityRef:registered.administrativeAuthorityRef,
   publicKeySha256:registered.publicKeySpkiSha256,
   enrollmentReceiptSha256:h(201+i),independentChannelReceiptSha256:h(211+i),
   custodyPolicySha256:registered.publisherPolicySha256,
   rotationSequence:1,validFrom:'2026-11-16T16:00:00.000Z',
   validUntil:'2027-01-16T16:00:00.000Z',
   revocationState:'CANDIDATE_UNVERIFIED',releaseDecision:'HOLD'};
  return attest(body,who,phase1BdWitnessBytes);
 });
 const provider=storageActor();
 const storageBody={schemaVersion:1,purpose:BD_STORAGE_PURPOSE,
  packetSha256:packetSha,batchSha256:batch,
  logRef:a.logRef,archiveObjectSha256:a.archiveObjectSha256,
  storageAccountSha256:a.storageAccountSha256,
  objectVersionIdSha256:a.objectVersionIdSha256,
  retentionPolicySha256:a.retentionPolicySha256,
  legalHoldEvidenceSha256:a.legalHoldEvidenceSha256,
  encryptionKeyIdentifierSha256:a.encryptionKeyIdentifierSha256,
  providerCreateReceiptSha256:h(301),providerPolicyReceiptSha256:h(302),
  deleteDenialReceiptSha256:h(303),overwriteDenialReceiptSha256:h(304),
  readbackReceiptSha256:h(305),observedAt:'2026-11-16T17:00:00.000Z',
  retentionUntil:a.retentionUntil,complianceLock:true,deleteDenied:true,
  overwriteDenied:true,releaseDecision:'HOLD'};
 const storageReceipt=attest(storageBody,provider,phase1BdStorageBytes);
 const r=azPacket.recovery;
 const drBody={schemaVersion:1,purpose:BD_RECOVERY_PURPOSE,
  packetSha256:packetSha,batchSha256:batch,logRef:a.logRef,
  incidentRef:r.incidentRef,checkpointReceiptSha256:a.checkpointReceiptSha256,
  encryptedBackupSha256:h(401),sourceManifestSha256:r.sourceManifestSha256,
  restoredManifestSha256:r.restoredManifestSha256,
  revocationSnapshotSha256:r.revocationSnapshotSha256,
  kmsRecoveryReceiptSha256:h(402),isolatedRestoreReceiptSha256:h(403),
  telemetryReceiptSha256:h(404),failureAt:r.startedAt,
  latestRecoveredAt:'2026-11-15T15:59:59.500Z',completedAt:r.completedAt,
  rtoObjectiveMs:r.rtoObjectiveMs,rpoObjectiveMs:r.rpoObjectiveMs,
  isolatedStaging:true,mfaReverified:true,revocationRechecked:true,
  outboundHeld:true,releaseDecision:'HOLD'};
 const recoveryAttestations=actors.slice(3).map(who=>
  attest({...drBody},who,phase1BdRecoveryBytes));
 return {azPacket,bbRecords:records,witnessEnrollments,
  storageReceipt,recoveryAttestations,now,actors,provider,batch};
}
export {h};
