import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {bdFixture,h} from './support/phase1bdFixture.mjs';
import {assessPhase1BdEvidenceReview,phase1BdWitnessBytes,
 phase1BdStorageBytes,phase1BdRecoveryBytes}
 from '../scripts/lib/phase1BdEvidenceReview.mjs';
const check=f=>assessPhase1BdEvidenceReview(f);
const reSign=(entry,actor,bytes)=>{
 entry.signature.signatureBase64=sign(null,bytes(entry.body),actor.privateKey).toString('base64');
};
test('candidate witness, storage, and DR signatures can agree mathematically but never authenticate external authority',()=>{
 const r=check(bdFixture());
 assert.equal(r.offlineEvidenceConsistent,true,r.blockerCodes.join(','));
 assert.match(r.reviewDigestSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.candidateWitnessSignaturesChecked,2);
 assert.equal(r.candidateDrSignaturesChecked,3);
 assert.equal(r.candidateProviderSignatureChecked,true);
 for(const x of ['independentAuthorityAuthenticated','authorizedIssuerKeyEnrollment',
  'independentlyVerifiedObjectLock','realEncryptedRestoreWitnessed',
  'productionReleaseAuthorized'])assert.equal(r[x],false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('missing review dossier always HARD HOLD with stable missing-evidence fields',()=>{
 const v=check();
 assert.equal(v.offlineEvidenceConsistent,false);
 assert.equal(v.reviewDigestSha256,null);
 assert.ok(v.blockerCodes.includes('INCOMPLETE_EXTERNAL_REVIEW_DOSSIER'));
 assert.equal(v.productionReleaseAuthorized,false);
 const f=bdFixture();
 assert.ok(check({...f,recoveryAttestations:f.recoveryAttestations.slice(0,2)})
  .blockerCodes.includes('INCOMPLETE_EXTERNAL_REVIEW_DOSSIER'));
});
test('witness proof-of-possession is checked against Phase 1AZ and Phase 1BB candidate pins',()=>{
 const f=bdFixture();
 f.witnessEnrollments[0].signature.signatureBase64=Buffer.alloc(64,1).toString('base64');
 const r=check(f);
 assert.ok(r.blockerCodes.includes('WITNESS_PROOF_OF_POSSESSION_INVALID'));
 assert.equal(r.offlineEvidenceConsistent,false);
 const g=bdFixture();
 g.witnessEnrollments[1].body.publicKeySha256=h(102);
 const v=check(g);
 assert.ok(v.blockerCodes.includes('WITNESS_ENROLLMENT_OR_PIN_MISMATCH'));
});
test('duplicate witness signing authority and reused key ID are rejected',()=>{
 const f=bdFixture();
 f.witnessEnrollments[1].pin.authorityRef=f.witnessEnrollments[0].pin.authorityRef;
 f.witnessEnrollments[1].pin.keyId=f.witnessEnrollments[0].pin.keyId;
 const r=check(f);
 assert.ok(r.blockerCodes.includes('WITNESS_COMMON_CONTROL_OR_DUPLICATE_ENROLLMENT'));
 assert.equal(r.authorizedIssuerKeyEnrollment,false);
});
test('unapproved witness rotation or revocation promotion is structurally rejected',()=>{
 const f=bdFixture();
 assert.throws(()=>phase1BdWitnessBytes({...f.witnessEnrollments[0].body,
  rotationSequence:2}),/unapproved witness key rotation/);
 assert.throws(()=>phase1BdWitnessBytes({...f.witnessEnrollments[0].body,
  revocationState:'ACTIVE_AUTHENTICATED'}),/unapproved witness key rotation/);
 assert.throws(()=>phase1BdWitnessBytes({...f.witnessEnrollments[0].body,
  releaseDecision:'GO'}));
});
test('out-of-band channel claim tampering changes digest but cannot create authority',()=>{
 const f=bdFixture(),original=check(f);
 f.witnessEnrollments[0].body.independentChannelReceiptSha256=h(502);
 const r=check(f);
 assert.equal(r.offlineEvidenceConsistent,false);
 assert.notEqual(r.reviewDigestSha256,original.reviewDigestSha256);
 assert.equal(r.independentAuthorityAuthenticated,false);
});
test('provider receipt cannot substitute object version, policy or storage account',()=>{
 for(const key of ['objectVersionIdSha256','storageAccountSha256',
  'retentionPolicySha256','archiveObjectSha256','legalHoldEvidenceSha256']){
  const f=bdFixture();
  f.storageReceipt.body[key]=h(509);
  const r=check(f);
  assert.ok(r.blockerCodes.includes('OBJECT_LOCK_VERSION_POLICY_BINDING_MISMATCH'));
  assert.equal(r.independentlyVerifiedObjectLock,false);
 }
});
test('delete success, missing compliance lock, or unauthorized retention are never accepted',()=>{
 const f=bdFixture();
 for(const x of [{deleteDenied:false},{overwriteDenied:false},{complianceLock:false},
  {releaseDecision:'GO'}]){
  assert.throws(()=>phase1BdStorageBytes({...f.storageReceipt.body,...x}));
 }
 const g=bdFixture();
 g.storageReceipt.body.retentionUntil='2026-12-01T00:00:00.000Z';
 assert.ok(check(g).blockerCodes.includes('OBJECT_LOCK_PROVIDER_CHRONOLOGY_INVALID'));
});
test('compromised storage provider signature and common authority reject candidate claims',()=>{
 const f=bdFixture();
 f.storageReceipt.signature.signatureBase64=Buffer.alloc(64,5).toString('base64');
 assert.ok(check(f).blockerCodes.includes('OBJECT_LOCK_PROVIDER_CANDIDATE_SIGNATURE_INVALID'));
 const g=bdFixture();
 g.storageReceipt.pin.authorityRef=g.bbRecords[0].body.authorityRef;
 assert.ok(check(g).blockerCodes.includes('OBJECT_LOCK_PROVIDER_CANDIDATE_SIGNATURE_INVALID'));
});
test('DR source-restored manifest and revocation mismatches cannot be witnessed as acceptable',()=>{
 const f=bdFixture();
 f.recoveryAttestations[0].body.restoredManifestSha256=h(602);
 let r=check(f);
 assert.ok(r.blockerCodes.includes('RECOVERY_MANIFEST_CHECKPOINT_OR_EVENT_MISMATCH'));
 const g=bdFixture();
 g.recoveryAttestations[1].body.revocationSnapshotSha256=h(603);
 r=check(g);
 assert.ok(r.blockerCodes.includes('RECOVERY_MANIFEST_CHECKPOINT_OR_EVENT_MISMATCH'));
});
test('three signed observers must attest the same encrypted backup, KMS and telemetry evidence',()=>{
 const f=bdFixture(),e=f.recoveryAttestations[2];
 e.body.encryptedBackupSha256=h(703);
 reSign(e,f.actors[5],phase1BdRecoveryBytes);
 const r=check(f);
 assert.ok(r.blockerCodes.includes('RECOVERY_OBSERVERS_DISAGREE_ON_EVIDENCE'));
 assert.equal(r.candidateDrSignaturesChecked,3);
 assert.equal(r.realEncryptedRestoreWitnessed,false);
 const g=bdFixture(),k=g.recoveryAttestations[1];
 k.body.telemetryReceiptSha256=h(704);
 reSign(k,g.actors[4],phase1BdRecoveryBytes);
 assert.ok(check(g).blockerCodes.includes('RECOVERY_OBSERVERS_DISAGREE_ON_EVIDENCE'));
});
test('wrong RPO or RTO cannot be fixed by resubmitting a signed claim',()=>{
 const f=bdFixture(),e=f.recoveryAttestations[0];
 e.body.latestRecoveredAt='2026-11-15T15:50:00.000Z';
 reSign(e,f.actors[3],phase1BdRecoveryBytes);
 const r=check(f);
 assert.ok(r.blockerCodes.includes('RECOVERY_RTO_RPO_UNCORROBORATED'));
 assert.equal(r.offlineEvidenceConsistent,false);
 const g=bdFixture(),x=g.recoveryAttestations[2];
 x.body.completedAt='2026-11-15T16:30:00.000Z';
 reSign(x,g.actors[5],phase1BdRecoveryBytes);
 assert.ok(check(g).blockerCodes.includes('RECOVERY_RTO_RPO_UNCORROBORATED'));
});
test('unauthorized security key substitution or repeated reviewer roles fail closed',()=>{
 const f=bdFixture(),item=f.recoveryAttestations[0];
 const attacker=generateKeyPairSync('ed25519');
 item.pin.publicKeyPem=attacker.publicKey.export({format:'pem',type:'spki'}).toString();
 item.pin.publicKeySha256=createHash('sha256').update(
  attacker.publicKey.export({format:'der',type:'spki'})).digest('hex');
 item.signature.signatureBase64=sign(null,phase1BdRecoveryBytes(item.body),
  attacker.privateKey).toString('base64');
 const r=check(f);
 assert.ok(r.blockerCodes.includes('UNAUTHORIZED_RECOVERY_SIGNER_SUBSTITUTION'));
 const g=bdFixture();
 g.recoveryAttestations[1].pin.role='SECURITY';
 assert.ok(check(g).blockerCodes.includes('RECOVERY_REVIEWER_DUPLICATE_ROLE_OR_AUTHORITY'));
});
test('raw credentials, unknown authority promotion, and oversized evidence are not accepted',()=>{
 const f=bdFixture();
 assert.throws(()=>phase1BdWitnessBytes({...f.witnessEnrollments[0].body,
  privateKey:'SECRET'}));
 assert.throws(()=>phase1BdStorageBytes({...f.storageReceipt.body,
  apiToken:'NOT_ALLOWED'}));
 assert.throws(()=>phase1BdRecoveryBytes({...f.recoveryAttestations[0].body,
  productionReleaseAuthorized:true}));
 assert.throws(()=>check({...f,secret:'x'.repeat(52000)}));
});
