import test from 'node:test';
import assert from 'node:assert/strict';
import {phase1AzAssessReadiness,AZ_PURPOSE} from '../scripts/lib/phase1AzExternalReadiness.mjs';
const d=n=>n.toString(16).padStart(64,'0');
const now=new Date('2026-11-16T17:00:00.000Z');
function packet(){
 return {schemaVersion:1,purpose:AZ_PURPOSE,revision:1,previousPacketSha256:null,
  witnesses:[
   {witnessRef:'witness-ref-001',organizationRef:'witness-org-001',
    administrativeAuthorityRef:'witness-admin-001',publicKeySpkiSha256:d(1),
    contractSha256:d(2),publisherPolicySha256:d(3),scope:'CHECKPOINT_WITNESS_ONLY',
    state:'CANDIDATE_UNVERIFIED'},
   {witnessRef:'witness-ref-002',organizationRef:'witness-org-002',
    administrativeAuthorityRef:'witness-admin-002',publicKeySpkiSha256:d(4),
    contractSha256:d(5),publisherPolicySha256:d(6),scope:'CHECKPOINT_WITNESS_ONLY',
    state:'CANDIDATE_UNVERIFIED'}],
  archive:{logRef:'checkpoint-log-001',checkpointReceiptSha256:d(11),
   archiveObjectSha256:d(12),storageAccountSha256:d(13),objectVersionIdSha256:d(14),
   retentionPolicySha256:d(15),encryptionKeyIdentifierSha256:d(16),
   claimedLockMode:'COMPLIANCE',legalHoldEvidenceSha256:d(17),
   createdAt:'2026-11-01T00:00:00.000Z',retentionUntil:'2027-05-01T00:00:00.000Z',
   minimumRetentionDays:90,externalStorageState:'NOT_VERIFIED'},
  recovery:{incidentRef:'incident-test-001',sourceCheckpointReceiptSha256:d(11),
   restoredCheckpointReceiptSha256:d(11),sourceManifestSha256:d(20),
   restoredManifestSha256:d(20),archiveObjectSha256:d(12),
   revocationSnapshotSha256:d(21),startedAt:'2026-11-15T10:00:00.000Z',
   completedAt:'2026-11-15T10:10:00.000Z',
   measuredRpoMs:2000,rtoObjectiveMs:900000,rpoObjectiveMs:3000,
   encryptedRestoreState:'NOT_EXTERNALLY_VERIFIED',outboundHeld:true},
  approvers:[
   {role:'SECURITY',reviewerRef:'reviewer-sec-001',authorityRef:'authority-sec-001',reviewRecordSha256:d(31)},
   {role:'OPERATIONS',reviewerRef:'reviewer-ops-002',authorityRef:'authority-ops-002',reviewRecordSha256:d(32)},
   {role:'OWNER',reviewerRef:'reviewer-owner-003',authorityRef:'authority-owner-003',reviewRecordSha256:d(33)}],
  releaseDecision:'HOLD'};
}
const evalPacket=(p)=>phase1AzAssessReadiness(p,{now});
test('no evidence returns HOLD and explicit missing-evidence blocker',()=>{
 const r=evalPacket(null);
 assert.equal(r.packetInspected,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.ok(r.blockerCodes.includes('NO_ONBOARDING_PACKET'));
});
test('internally consistent digest-only packet cannot create independent external approvals',()=>{
 const p=packet(),r=evalPacket(p);
 assert.equal(r.internalEvidenceConsistent,true);
 assert.equal(r.selfDeclaredWitnessCandidateCount,2);
 assert.equal(r.externallyAuthenticated,false);
 assert.equal(r.immutableStorageVerified,false);
 assert.equal(r.realDRRestoreVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.match(r.packetSha256,/^[0-9a-f]{64}$/);
 assert.equal(evalPacket(structuredClone(p)).packetSha256,r.packetSha256);
});
test('malicious GO flags, secrets, raw documents, access endpoints and unsupported states rejected',()=>{
 for(const modified of [
  {...packet(),releaseDecision:'GO'},
  {...packet(),productionReleaseAuthorized:true},
  {...packet(),sandboxCredentials:'SECRET'},
  {...packet(),archive:{...packet().archive,signedUrl:'https://example.invalid/secret'}},
  {...packet(),archive:{...packet().archive,claimedLockMode:'GOVERNANCE'}},
  {...packet(),archive:{...packet().archive,externalStorageState:'VERIFIED'}},
  {...packet(),archive:{...packet().archive,objectVersionIdSha256:'0'.repeat(64)}},
  {...packet(),witnesses:[{...packet().witnesses[0],state:'ACTIVE'},packet().witnesses[1]]},
  {...packet(),witnesses:[{...packet().witnesses[0],scope:'PRODUCTION_RELEASE'},packet().witnesses[1]]},
  {...packet(),recovery:{...packet().recovery,encryptedRestoreState:'VERIFIED'}},
  {...packet(),recovery:{...packet().recovery,outboundHeld:false}}
 ])assert.throws(()=>evalPacket(modified));
});
test('witness quorum must have distinct claimed organizations administrative controls and keys',()=>{
 const original=packet();
 for(const changed of [
  {...original.witnesses[1],organizationRef:original.witnesses[0].organizationRef},
  {...original.witnesses[1],administrativeAuthorityRef:original.witnesses[0].administrativeAuthorityRef},
  {...original.witnesses[1],publicKeySpkiSha256:original.witnesses[0].publicKeySpkiSha256},
  {...original.witnesses[1],witnessRef:original.witnesses[0].witnessRef}
 ])assert.throws(()=>evalPacket({...packet(),witnesses:[original.witnesses[0],changed]}));
 assert.throws(()=>evalPacket({...packet(),witnesses:[original.witnesses[0]]}));
});
test('archive retention shortened, zero digest, noncanonical timestamp and future publication rejected',()=>{
 const p=packet();
 for(const changed of [
  {...p.archive,retentionUntil:'2026-11-10T00:00:00.000Z'},
  {...p.archive,minimumRetentionDays:1000},
  {...p.archive,retentionPolicySha256:'ABC'},
  {...p.archive,createdAt:'2026-11-01'},
  {...p.archive,createdAt:'2028-11-01T00:00:00.000Z'}
 ]){
  const verdict=()=>evalPacket({...packet(),archive:changed});
  if(changed.createdAt==='2028-11-01T00:00:00.000Z'){
   const r=verdict();
   assert.equal(r.internalEvidenceConsistent,false);
   assert.ok(r.blockerCodes.includes('FUTURE_ARCHIVE_CLAIM'));
  }else assert.throws(verdict);
 }
});
test('recovery digest tampering, RTO breach and measured RPO breach block internal consistency',()=>{
 const p=packet();
 for(const change of [
  {sourceCheckpointReceiptSha256:d(99)},{restoredCheckpointReceiptSha256:d(98)},
  {archiveObjectSha256:d(97)},{restoredManifestSha256:d(96)},
  {rtoObjectiveMs:1},{rpoObjectiveMs:1}
 ]){
  const r=evalPacket({...p,recovery:{...p.recovery,...change}});
  assert.equal(r.internalEvidenceConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.productionReleaseBlocked,true);
  assert.ok(r.blockerCodes.some(b=>b==='RESTORE_DIGEST_OR_ARCHIVE_BINDING_MISMATCH'||
   b==='CLAIMED_RECOVERY_OBJECTIVES_EXCEEDED'));
 }
});
test('reject self-approval duplicate signer authority and forged reviewer roles',()=>{
 const p=packet();
 for(const changed of [
  {...p.approvers[1],reviewerRef:p.approvers[0].reviewerRef},
  {...p.approvers[1],authorityRef:p.approvers[0].authorityRef},
  {...p.approvers[1],role:'OWNER'},
  {...p.approvers[1],reviewRecordSha256:'x'}
 ])assert.throws(()=>evalPacket({...packet(),approvers:[p.approvers[0],changed,p.approvers[2]]}));
});
test('revision rollback/invalid predecessor rejected; canonical lineage fingerprint differs on evidence changes',()=>{
 const p=packet(),initial=evalPacket(p);
 assert.throws(()=>evalPacket({...p,revision:0}));
 assert.throws(()=>evalPacket({...p,revision:2}));
 assert.throws(()=>evalPacket({...p,previousPacketSha256:d(45)}));
 const next={...p,revision:2,previousPacketSha256:initial.packetSha256};
 const r=evalPacket(next);
 assert.equal(r.revision,2);
 assert.notEqual(r.packetSha256,initial.packetSha256);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.notEqual(evalPacket({...p,archive:{...p.archive,archiveObjectSha256:d(58)},
  recovery:{...p.recovery,archiveObjectSha256:d(58)}}).packetSha256,initial.packetSha256);
});
test('recovery beyond current time and invalid measured values fail closed',()=>{
 const p=packet();
 assert.throws(()=>evalPacket({...p,recovery:{...p.recovery,completedAt:'2027-11-15T10:10:00.000Z'}}));
 assert.throws(()=>evalPacket({...p,recovery:{...p.recovery,measuredRpoMs:-1}}));
 assert.throws(()=>phase1AzAssessReadiness(p,{now:new Date('invalid')}));
});
