import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixture as priorFixture,now,h} from './support/phase1bbFixture.mjs';
import {BB_PURPOSE} from '../scripts/lib/phase1BbEvidenceIntake.mjs';
import {
 BC_ISSUER_PURPOSE,BC_STORAGE_PURPOSE,BC_RECOVERY_PURPOSE,
 phase1BcIssuerBytes,phase1BcStorageBytes,phase1BcRecoveryBytes,
 assessPhase1BcOfflineAdapter
} from '../scripts/lib/phase1BcExternalAdapterProtocol.mjs';

const digest=b=>createHash('sha256').update(b).digest('hex');
function actor(role,sourceRef,authorityRef){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {privateKey,pin:{role,sourceRef,authorityRef,keyId:'key-'+sourceRef,
  publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:digest(publicKey.export({format:'der',type:'spki'}))}};
}
const detached=(body,who,bytes)=>({
 body,pin:who.pin,signature:{
  sourceRef:who.pin.sourceRef,keyId:who.pin.keyId,
  signatureBase64:sign(null,bytes(body),who.privateKey).toString('base64')
 }});
function fixture(){
 const f=priorFixture(),p=f.azPacket;
 const issuers=[actor('ISSUER','challenge-issuer-001','challenge-authority-001'),
  actor('ISSUER','challenge-issuer-002','challenge-authority-002')];
 const packetSha256=f.records[0].body.packetSha256;
 const challengeIssuances=f.records.map((r,i)=>{
  const b=r.body;
  const body={schemaVersion:1,purpose:BC_ISSUER_PURPOSE,
   packetSha256,challengeSha256:b.challengeSha256,sourceRole:b.sourceRole,
   sourceRef:b.sourceRef,issuerRef:issuers[i%2].pin.sourceRef,
   issuedAt:'2026-11-16T17:25:00.000Z',
   expiresAt:'2026-11-16T17:35:00.000Z',releaseDecision:'HOLD'};
  return detached(body,issuers[i%2],phase1BcIssuerBytes);
 });
 const storageActor=actor('STORAGE_PROVIDER','provider-storage-001','provider-storage-authority-001');
 const a=p.archive;
 const storageBody={schemaVersion:1,purpose:BC_STORAGE_PURPOSE,
  packetSha256,logRef:a.logRef,archiveObjectSha256:a.archiveObjectSha256,
  objectVersionIdSha256:a.objectVersionIdSha256,
  retentionPolicySha256:a.retentionPolicySha256,
  legalHoldEvidenceSha256:a.legalHoldEvidenceSha256,
  providerRequestSha256:h(91),providerResponseSha256:h(92),
  observedAt:'2026-11-16T17:20:00.000Z',retentionUntil:a.retentionUntil,
  versioned:true,lockMode:'COMPLIANCE',deleteDenied:true,
  overwriteDenied:true,releaseDecision:'HOLD'};
 const storageReceipt=detached(storageBody,storageActor,phase1BcStorageBytes);
 const rec=p.recovery;
 const recoveryBody={schemaVersion:1,purpose:BC_RECOVERY_PURPOSE,
  packetSha256,logRef:a.logRef,checkpointReceiptSha256:a.checkpointReceiptSha256,
  encryptedBackupSha256:h(93),backupManifestSha256:rec.sourceManifestSha256,
  restoredManifestSha256:rec.restoredManifestSha256,
  revocationSnapshotSha256:rec.revocationSnapshotSha256,
  failureAt:rec.startedAt,latestRecoveredAt:'2026-11-15T15:59:59.500Z',
  completedAt:rec.completedAt,
  rtoObjectiveMs:rec.rtoObjectiveMs,rpoObjectiveMs:rec.rpoObjectiveMs,
  isolatedRestore:true,mfaReverified:true,revocationRechecked:true,
  dispatchHeld:true,releaseDecision:'HOLD'};
 const reviewers=f.actors.slice(3).map(a=>({privateKey:a.privateKey,pin:{
  role:a.pin.role,sourceRef:a.pin.sourceRef,authorityRef:a.pin.authorityRef,
  keyId:a.pin.keyId,publicKeyPem:a.pin.publicKeyPem,
  publicKeySha256:a.pin.publicKeySha256
 }}));
 const recoveryReceipts=reviewers.map(a=>detached({...recoveryBody},a,phase1BcRecoveryBytes));
 return {azPacket:p,bbRecords:f.records,challengeIssuances,storageReceipt,
  recoveryReceipts,now,issuers,storageActor,reviewers};
}
const check=f=>assessPhase1BcOfflineAdapter(f);
test('six offline issuer receipts plus Object Lock and DR signatures remain permanently untrusted and held',()=>{
 const r=check(fixture());
 assert.equal(r.offlineEvidenceConsistent,true,r.blockerCodes.join(','));
 assert.equal(r.issuerSignatureCount,6);
 assert.equal(r.recoverySignatureCount,3);
 assert.equal(r.claimedIssuerOrganizations,2);
 assert.match(r.internalBatchSha256,/^[0-9a-f]{64}$/);
 for(const key of ['externalProviderAuthorized','independentIssuerKeyCustodyVerified',
  'providerObjectLockVerified','independentEncryptedRestoreVerified',
  'productionReleaseAuthorized'])assert.equal(r[key],false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('zero-input and incomplete publisher manifests are never promoted',()=>{
 const r=check();
 assert.equal(r.offlineEvidenceConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.ok(r.blockerCodes.includes('INCOMPLETE_ADAPTER_EVIDENCE'));
 const f=fixture();f.challengeIssuances.pop();
 assert.ok(check(f).blockerCodes.includes('INCOMPLETE_ADAPTER_EVIDENCE'));
});
test('cross-signed issuer challenges reject tampering and forged Ed25519 signatures',()=>{
 const f=fixture();
 f.challengeIssuances[0].signature.signatureBase64=Buffer.alloc(64,9).toString('base64');
 const r=check(f);
 assert.ok(r.blockerCodes.includes('ISSUER_SIGNATURE_INVALID'));
 assert.equal(r.offlineEvidenceConsistent,false);
 const g=fixture();g.challengeIssuances[0].body.challengeSha256=h(992);
 assert.ok(check(g).blockerCodes.includes('CHALLENGE_NOT_BOUND_TO_SIGNED_RESPONSE'));
});
test('issuer must challenge before the response and while its signed nonce is valid',()=>{
 const f=fixture();
 f.challengeIssuances[1].body.issuedAt='2026-11-16T17:34:00.000Z';
 f.challengeIssuances[1].body.expiresAt='2026-11-16T17:39:00.000Z';
 assert.ok(check(f).blockerCodes.includes('CHALLENGE_NOT_VALID_DURING_SIGNED_RESPONSE'));
 const g=fixture();
 g.challengeIssuances[2].body.expiresAt='2026-11-16T17:29:00.000Z';
 assert.ok(check(g).blockerCodes.includes('CHALLENGE_NOT_VALID_DURING_SIGNED_RESPONSE'));
});
test('two independent claimed issuer organizations and three receipts per issuer required',()=>{
 const f=fixture();
 for(let i=1;i<f.challengeIssuances.length;i+=2){
  f.challengeIssuances[i].pin.authorityRef=f.challengeIssuances[0].pin.authorityRef;
 }
 const r=check(f);
 assert.ok(r.blockerCodes.includes('TWO_INDEPENDENT_ISSUER_QUORUM_UNAVAILABLE'));
 assert.equal(r.independentIssuerKeyCustodyVerified,false);
 const g=fixture();
 g.challengeIssuances[0].pin.authorityRef=g.bbRecords[0].body.authorityRef;
 assert.ok(check(g).blockerCodes.includes('ISSUER_WITNESS_COMMON_CONTROL'));
});
test('storage deletion/overwrite claims, retention and object version substitutions fail closed',()=>{
 for(const change of [
  {deleteDenied:false},{overwriteDenied:false},{lockMode:'GOVERNANCE'},
  {versioned:false},{releaseDecision:'GO'}
 ]){
  const f=fixture();Object.assign(f.storageReceipt.body,change);
  assert.throws(()=>check(f));
 }
 const f=fixture();
 f.storageReceipt.body.objectVersionIdSha256=h(802);
 const r=check(f);
 assert.ok(r.blockerCodes.includes('OBJECT_LOCK_RECEIPT_BINDING_MISMATCH'));
 assert.ok(r.blockerCodes.includes('OBJECT_LOCK_PROVIDER_SIGNER_UNTRUSTED'));
});
test('provider storage signer cannot share administrative custody with issuers or witnesses',()=>{
 const f=fixture();
 f.storageReceipt.pin.authorityRef=f.issuers[0].pin.authorityRef;
 const r=check(f);
 assert.ok(r.blockerCodes.includes('OBJECT_LOCK_PROVIDER_SIGNER_UNTRUSTED'));
 assert.equal(r.providerObjectLockVerified,false);
});
test('DR signed manifests must match predecessor recovery, revocation and measured RTO/RPO',()=>{
 for(const change of [
  {backupManifestSha256:h(803)},{revocationSnapshotSha256:h(804)},
  {completedAt:'2026-11-15T16:11:00.000Z'},
  {latestRecoveredAt:'2026-11-15T15:59:40.000Z'}
 ]){
  const f=fixture();
  Object.assign(f.recoveryReceipts[0].body,change);
  const r=check(f);
  assert.equal(r.offlineEvidenceConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.ok(r.blockerCodes.some(x=>['RECOVERY_RECEIPT_NOT_BOUND_TO_BACKUP_AND_REVOCATION',
   'RECOVERY_RTO_RPO_NOT_CORROBORATED'].includes(x)));
 }
});
test('three independent DR roles must match registered AZ reviewer identities',()=>{
 const f=fixture();
 f.recoveryReceipts[1].pin.authorityRef=f.recoveryReceipts[0].pin.authorityRef;
 const r=check(f);
 assert.ok(r.blockerCodes.includes('RECOVERY_APPROVER_AUTHORITY_COLLISION'));
 const g=fixture();g.recoveryReceipts[2].signature.signatureBase64=Buffer.alloc(64,8).toString('base64');
 assert.ok(check(g).blockerCodes.includes('RECOVERY_APPROVER_SIGNATURE_INVALID'));
});
test('malformed fields, signed role escalation and raw credential injection are rejected',()=>{
 const f=fixture();
 assert.throws(()=>phase1BcIssuerBytes({...f.challengeIssuances[0].body,
  credentials:'SHOULD_NOT_BE_READ'}));
 assert.throws(()=>phase1BcIssuerBytes({...f.challengeIssuances[0].body,
  releaseDecision:'GO'}));
 assert.throws(()=>phase1BcStorageBytes({...f.storageReceipt.body,secretKey:'PRIVATE'}));
 assert.throws(()=>phase1BcRecoveryBytes({...f.recoveryReceipts[0].body,
  dispatchHeld:false}));
 assert.throws(()=>phase1BcRecoveryBytes({...f.recoveryReceipts[0].body,
  releaseDecision:'GO'}));
});
test('issuer signing is domain-separated from storage and DR receipts',()=>{
 const f=fixture();
 assert.notDeepEqual(phase1BcIssuerBytes(f.challengeIssuances[0].body),
  phase1BcStorageBytes(f.storageReceipt.body));
 assert.notDeepEqual(phase1BcRecoveryBytes(f.recoveryReceipts[0].body),
  phase1BcStorageBytes(f.storageReceipt.body));
});
