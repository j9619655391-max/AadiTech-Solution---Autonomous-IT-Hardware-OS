import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {AZ_PURPOSE,phase1AzAssessReadiness} from '../scripts/lib/phase1AzExternalReadiness.mjs';
import {BB_PURPOSE,assessPhase1BbEvidenceIntake,phase1BbSignedBytes}
 from '../scripts/lib/phase1BbEvidenceIntake.mjs';

const now=new Date('2026-11-16T18:00:00.000Z');
const h=n=>n.toString(16).padStart(64,'0');
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
const assess=x=>assessPhase1BbEvidenceIntake(x);
test('six signed local fixture records are internally consistent but never externally authenticated',()=>{
 const f=fixture(),r=assess(f);
 assert.equal(r.internalEvidenceConsistent,true,r.blockerCodes.join(','));
 assert.equal(r.signedClaimsChecked,6);
 assert.equal(r.challengeDigests.length,6);
 assert.match(r.batchSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.independentSourcesAuthenticated,false);
 assert.equal(r.independentChallengeIssuanceVerified,false);
 assert.equal(r.keyCustodyAuthenticated,false);
 assert.equal(r.externalImmutabilityVerified,false);
 assert.equal(r.realDRWitnessed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('deterministic signed batch commitment is invariant under record order, not under tamper',()=>{
 const a=fixture();
 const first=assess(a);
 assert.equal(assess({...a,records:[...a.records].reverse()}).batchSha256,first.batchSha256);
 const bad=fixture();bad.records[0].body.evidenceSha256=h(700);
 const r=assess(bad);
 assert.notEqual(r.batchSha256,first.batchSha256);
 assert.equal(r.internalEvidenceConsistent,false);
 assert.ok(r.blockerCodes.includes('EVIDENCE_DIGEST_OR_SUBJECT_MISMATCH'));
});
test('zero evidence and incomplete quorum cannot produce an ingestion authorization',()=>{
 const empty=assess();
 assert.equal(empty.batchSha256,null);
 assert.equal(empty.productionReleaseAuthorized,false);
 assert.ok(empty.blockerCodes.includes('MISSING_SIX_DOMAIN_EVIDENCE_RECORDS'));
 const f=fixture();
 const incomplete=assess({...f,records:f.records.slice(0,5)});
 assert.equal(incomplete.internalEvidenceConsistent,false);
 assert.equal(incomplete.productionReleaseBlocked,true);
});
test('forged detached signature or unregistered key swap blocked',()=>{
 const f=fixture();f.records[0].signature.signatureBase64=Buffer.alloc(64,1).toString('base64');
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('INVALID_DETACHED_EVIDENCE_SIGNATURE'));
 assert.equal(r.internalEvidenceConsistent,false);
 const swap=fixture();swap.records[0].body.publicKeySha256=h(200);
 const r2=assess(swap);
 assert.ok(r2.blockerCodes.includes('WITNESS_ENROLLMENT_PIN_NOT_MATCHED'));
 assert.ok(r2.blockerCodes.includes('INVALID_DETACHED_EVIDENCE_SIGNATURE'));
});
test('cross-signer nonce replay and claimed administrative overlap are denied',()=>{
 const f=fixture();f.records[1].body.challengeSha256=f.records[0].body.challengeSha256;
 f.records[1].body.authorityRef=f.records[0].body.authorityRef;
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('REPLAYED_CHALLENGE_OR_SHARED_AUTHORITY'));
 assert.equal(r.internalEvidenceConsistent,false);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('source evidence hash must match Phase 1AZ witness policy, storage hold and each review',()=>{
 for(const index of [0,2,3,4,5]){
  const f=fixture();
  f.records[index].body.evidenceSha256=h(201+index);
  const r=assess(f);
  assert.ok(r.blockerCodes.includes('EVIDENCE_DIGEST_OR_SUBJECT_MISMATCH'));
  assert.equal(r.internalEvidenceConsistent,false);
 }
});
test('AZ digest and log substitutions cannot cross over between evidence packets',()=>{
 const f=fixture();f.records[0].body.packetSha256=h(300);
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('PACKET_OR_LOG_BINDING_MISMATCH'));
 const g=fixture();g.records[1].body.logRef='different-checkpoint-log';
 assert.ok(assess(g).blockerCodes.includes('PACKET_OR_LOG_BINDING_MISMATCH'));
});
test('role smuggling, credential/raw proof injection and GO switches fail on exact schema',()=>{
 const f=fixture();
 for(const change of [
  {...f.records[0].body,privateKey:'SECRET'},
  {...f.records[0].body,signedUrl:'https://example.invalid/secret'},
  {...f.records[0].body,releaseDecision:'GO'},
  {...f.records[0].body,authorityState:'AUTHENTICATED'},
  {...f.records[0].body,sourceRole:'PROVIDER_ADMIN'},
  {...f.records[0].body,subjectSha256:'0'.repeat(64)},
  {...f.records[0].body,expiresAt:'2026-11-17T18:00:00.000Z'}
 ])assert.throws(()=>phase1BbSignedBytes(change));
});
test('expired, future, and duplicate reviewer identities quarantine internal batch',()=>{
 for(const change of [
  {expiresAt:'2026-11-16T17:45:00.000Z'},
  {issuedAt:'2026-11-16T20:00:00.000Z',expiresAt:'2026-11-16T20:30:00.000Z'},
  {sourceRef:'witness-first-001'}
 ]){
  const f=fixture();
  Object.assign(f.records[1].body,change);
  const r=assess(f);
  assert.equal(r.internalEvidenceConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
