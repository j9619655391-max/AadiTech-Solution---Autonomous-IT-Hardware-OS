import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {AZ_PURPOSE,phase1AzAssessReadiness} from '../scripts/lib/phase1AzExternalReadiness.mjs';
import {
 BA_WITNESS_PURPOSE,BA_STORAGE_PURPOSE,BA_DR_PURPOSE,
 phase1BaWitnessBytes,phase1BaStorageBytes,phase1BaRestoreBytes,
 assessPhase1BaExternalAcceptance
} from '../scripts/lib/phase1BaAcceptanceEvidence.mjs';
import {ANCHOR_PURPOSE,phase1AyInclusionLeafHash} from '../scripts/lib/phase1AyWitnessArchiveRecovery.mjs';
const now=new Date('2026-11-16T18:00:00.000Z');
const h=n=>n.toString(16).padStart(64,'0');
function actor(role,name,authority){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const publicKeyPem=publicKey.export({format:'pem',type:'spki'}).toString();
 return {privateKey,pin:{role,reviewerRef:name,authorityRef:authority,
  keyId:'key-'+name,publicKeyPem,
  publicKeySha256:createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')}};
}
const detached=(bytes,actor)=>({reviewerRef:actor.pin.reviewerRef,keyId:actor.pin.keyId,
 signatureBase64:sign(null,bytes,actor.privateKey).toString('base64')});
const hash=b=>createHash('sha256').update(b).digest();
function packet(witnesses,reviewers){
 return {schemaVersion:1,purpose:AZ_PURPOSE,revision:1,previousPacketSha256:null,
  witnesses:witnesses.map((w,i)=>({witnessRef:'witness-ref-00'+(i+1),
   organizationRef:'witness-org-00'+(i+1),
   administrativeAuthorityRef:w.pin.authorityRef,
   publicKeySpkiSha256:w.pin.publicKeySha256,contractSha256:h(2+i),
   publisherPolicySha256:h(4+i),scope:'CHECKPOINT_WITNESS_ONLY',
   state:'CANDIDATE_UNVERIFIED'})),
  archive:{logRef:'checkpoint-log-001',checkpointReceiptSha256:h(11),
   archiveObjectSha256:h(12),storageAccountSha256:h(13),
   objectVersionIdSha256:h(14),retentionPolicySha256:h(15),
   encryptionKeyIdentifierSha256:h(16),claimedLockMode:'COMPLIANCE',
   legalHoldEvidenceSha256:h(17),createdAt:'2026-11-01T00:00:00.000Z',
   retentionUntil:'2027-05-01T00:00:00.000Z',minimumRetentionDays:90,
   externalStorageState:'NOT_VERIFIED'},
  recovery:{incidentRef:'incident-dr-001',sourceCheckpointReceiptSha256:h(11),
   restoredCheckpointReceiptSha256:h(11),sourceManifestSha256:h(20),
   restoredManifestSha256:h(20),archiveObjectSha256:h(12),
   revocationSnapshotSha256:h(21),startedAt:'2026-11-15T10:00:00.000Z',
   completedAt:'2026-11-15T10:10:00.000Z',measuredRpoMs:3000,
   rtoObjectiveMs:900000,rpoObjectiveMs:5000,
   encryptedRestoreState:'NOT_EXTERNALLY_VERIFIED',outboundHeld:true},
  approvers:reviewers.map((x,i)=>({role:['SECURITY','OPERATIONS','OWNER'][i],
   reviewerRef:x.pin.reviewerRef,authorityRef:x.pin.authorityRef,
   reviewRecordSha256:h(31+i)})),releaseDecision:'HOLD'};
}
function fixture(){
 const witnesses=[actor('WITNESS','witness-signer-001','witness-admin-001'),
  actor('WITNESS','witness-signer-002','witness-admin-002')];
 const reviewers=[
  actor('SECURITY','security-approver-001','security-admin-001'),
  actor('OPERATIONS','operations-approver-002','operations-admin-002'),
  actor('OWNER','owner-approver-003','owner-admin-003')];
 const storageActor=actor('STORAGE','storage-observer-001','storage-admin-001');
 const azPacket=packet(witnesses,reviewers);
 const packetSha256=phase1AzAssessReadiness(azPacket,{now}).packetSha256;
 const shared={schemaVersion:1,packetSha256,logRef:azPacket.archive.logRef,
  checkpointReceiptSha256:azPacket.archive.checkpointReceiptSha256,
  archiveObjectSha256:azPacket.archive.archiveObjectSha256};
 const baseWitness={...shared,purpose:BA_WITNESS_PURPOSE,
  treeSize:1,leafIndex:0,rootSha256:h(999),
  observedAt:'2026-11-16T17:00:00.000Z',
  expiresAt:'2026-11-16T19:00:00.000Z',releaseDecision:'HOLD'};
 const anchor={schemaVersion:1,purpose:ANCHOR_PURPOSE,
  logRef:shared.logRef,checkpointReceiptSha256:shared.checkpointReceiptSha256,
  archiveObjectSha256:shared.archiveObjectSha256,treeSize:1,leafIndex:0,
  rootSha256:h(999),issuedAt:baseWitness.observedAt,
  expiresAt:baseWitness.expiresAt,releaseDecision:'HOLD'};
 const root=hash(Buffer.concat([Buffer.from([0]),phase1AyInclusionLeafHash(anchor)])).toString('hex');
 const observations=witnesses.map((w,i)=>{
  const b={...baseWitness,witnessRef:azPacket.witnesses[i].witnessRef,
   organizationRef:azPacket.witnesses[i].organizationRef,
   administrativeAuthorityRef:w.pin.authorityRef,rootSha256:root};
  return {body:b,pin:w.pin,signature:detached(phase1BaWitnessBytes(b),w),
   inclusionProofSha256:[]};
 });
 const s={...shared,purpose:BA_STORAGE_PURPOSE,
  storageAccountSha256:azPacket.archive.storageAccountSha256,
  objectVersionIdSha256:azPacket.archive.objectVersionIdSha256,
  retentionPolicySha256:azPacket.archive.retentionPolicySha256,
  encryptionKeyIdentifierSha256:azPacket.archive.encryptionKeyIdentifierSha256,
  retentionUntil:azPacket.archive.retentionUntil,
  observedAt:'2026-11-16T17:00:00.000Z',objectLockMode:'COMPLIANCE',
  retentionEnabled:true,versioningEnabled:true,legalHoldEnabled:true,
  deleteProbeResult:'DENIED',deleteProbeReceiptSha256:h(99),releaseDecision:'HOLD'};
 const storage={body:s,pin:storageActor.pin,
  signature:detached(phase1BaStorageBytes(s),storageActor)};
 const b={...shared,purpose:BA_DR_PURPOSE,sourceManifestSha256:h(20),
  restoredManifestSha256:h(20),revocationSnapshotSha256:h(21),
  encryptedBackupSha256:h(24),failureAt:'2026-11-15T10:00:00.000Z',
  recoveryCompleteAt:'2026-11-15T10:10:00.000Z',
  latestRecoveredAt:'2026-11-15T09:59:57.000Z',
  rtoObjectiveMs:900000,rpoObjectiveMs:5000,
  keysRecovered:true,restoreIsolationConfirmed:true,mfaReverified:true,
  revocationRechecked:true,dispatchHeld:true,releaseDecision:'HOLD'};
 const restore={body:b,signatures:reviewers.map(a=>detached(phase1BaRestoreBytes(b),a)),
  pins:reviewers.map(a=>a.pin)};
 return {azPacket,witnesses:observations,storage,restore,now};
}
const assess=f=>assessPhase1BaExternalAcceptance(f);
test('synthetic cross-source signed evidence can be consistent but never authenticated externally',()=>{
 const r=assess(fixture());
 assert.equal(r.offlineClaimsConsistent,true);
 assert.equal(r.cryptographicallyValidWitnesses,2);
 assert.equal(r.claimedMeasuredRtoMs,600000);
 assert.equal(r.claimedMeasuredRpoMs,3000);
 assert.equal(r.externallyAuthenticated,false);
 assert.equal(r.wormStorageVerified,false);
 assert.equal(r.actualEncryptedRestoreVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('missing all external evidence remains quarantined HOLD',()=>{
 const r=assessPhase1BaExternalAcceptance();
 assert.equal(r.offlineClaimsConsistent,false);
 assert.equal(r.incidentQuarantineRequired,true);
 assert.ok(r.blockerCodes.includes('MISSING_REQUIRED_EXTERNAL_EVIDENCE'));
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
});
test('fake witness administrative key substitution fails AZ public SPKI binding',()=>{
 const f=fixture();const attacker=actor('WITNESS','witness-attacker-003','witness-admin-001');
 const entry=f.witnesses[0];
 entry.pin=attacker.pin;
 entry.signature=detached(phase1BaWitnessBytes(entry.body),attacker);
 const r=assess(f);
 assert.equal(r.offlineClaimsConsistent,false);
 assert.ok(r.blockerCodes.includes('WITNESS_ENROLLMENT_BINDING_MISMATCH'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('altered signed tree head, checkpoint and invalid Merkle path are blocked',()=>{
 for(const mutate of [
  f=>{f.witnesses[0].body.rootSha256=h(77);},
  f=>{f.witnesses[0].inclusionProofSha256=[h(88)];},
  f=>{f.witnesses[1].body.checkpointReceiptSha256=h(44);}
 ]){
  const f=fixture();mutate(f);
  const r=assess(f);
  assert.equal(r.offlineClaimsConsistent,false);
  assert.ok(r.blockerCodes.some(x=>['INVALID_WITNESS_SIGNATURE','INVALID_WITNESS_MERKLE_INCLUSION',
   'WITNESS_ENROLLMENT_BINDING_MISMATCH','WITNESS_CHECKPOINT_EQUIVOCATION'].includes(x)));
 }
});
test('two signers with one admin/duplicate key do not establish a witness quorum',()=>{
 const f=fixture();
 f.witnesses[1].pin.authorityRef=f.witnesses[0].pin.authorityRef;
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('COMMON_CONTROL_OR_DUPLICATE_WITNESS'));
 assert.equal(r.offlineClaimsConsistent,false);
});
test('self-claimed Object Lock deletion denial can be inspected, never taken as provider proof',()=>{
 const r=assess(fixture());
 assert.equal(r.offlineClaimsConsistent,true);
 assert.equal(r.wormStorageVerified,false);
 assert.ok(r.blockerCodes.includes('OBJECT_LOCK_ENFORCEMENT_NOT_INDEPENDENTLY_OBSERVED'));
 for(const change of [
  {deleteProbeResult:'SUCCEEDED'},
  {objectLockMode:'GOVERNANCE'},
  {legalHoldEnabled:false},
  {versioningEnabled:false},
  {retentionEnabled:false}
 ]){
  const f=fixture();Object.assign(f.storage.body,change);
  const x=assess(f);
  assert.ok(x.blockerCodes.includes('OBJECT_LOCK_DELETE_DENIAL_NOT_PROVEN'));
  assert.equal(x.productionReleaseAuthorized,false);
 }
});
test('retention and object version binding tampering fails',()=>{
 const f=fixture();
 f.storage.body.objectVersionIdSha256=h(777);
 const r=assess(f);
 assert.ok(r.blockerCodes.includes('STORAGE_POLICY_OR_VERSION_BINDING_MISMATCH'));
 assert.ok(r.blockerCodes.includes('INVALID_STORAGE_ATTESTATION_SIGNATURE'));
});
test('DR completion and recovered time derive RTO and RPO independently of submitted measurements',()=>{
 for(const change of [
  {latestRecoveredAt:'2026-11-15T09:50:00.000Z'},
  {recoveryCompleteAt:'2026-11-15T10:30:00.000Z'},
  {latestRecoveredAt:'2026-11-15T10:01:00.000Z'},
  {dispatchHeld:false},{mfaReverified:false},{revocationRechecked:false}
 ]){
  const f=fixture();Object.assign(f.restore.body,change);
  const r=assess(f);
  assert.equal(r.offlineClaimsConsistent,false);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('forged recovery signature or self-approved reviewer roles fail closed',()=>{
 const f=fixture();
 f.restore.signatures[0].signatureBase64=Buffer.alloc(64,7).toString('base64');
 let r=assess(f);
 assert.ok(r.blockerCodes.includes('INVALID_RECOVERY_ATTESTATION_SIGNATURE'));
 const same=fixture();
 same.restore.pins[1].authorityRef=same.restore.pins[0].authorityRef;
 r=assess(same);
 assert.ok(r.blockerCodes.includes('NONINDEPENDENT_RECOVERY_OBSERVERS'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('reject unrecognized release flags and hidden credential fields before signing',()=>{
 const f=fixture();
 assert.throws(()=>phase1BaWitnessBytes({...f.witnesses[0].body,apiToken:'SECRET'}));
 assert.throws(()=>phase1BaStorageBytes({...f.storage.body,releaseDecision:'GO'}));
 assert.throws(()=>phase1BaRestoreBytes({...f.restore.body,productionReleaseAuthorized:true}));
 assert.throws(()=>phase1BaRestoreBytes({...f.restore.body,privateKey:'PRIVATE'}));
});

test('Phase 1BA CI preflight accepts only zero-input release HOLD',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const script=fileURLToPath(new URL('../scripts/phase1ba-acceptance-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[script,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',GITHUB_ACTIONS:'true',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const ok=run(['--ci-hold']);
 assert.equal(ok.status,0,ok.stderr);
 const parsed=JSON.parse(ok.stdout);
 assert.equal(parsed.productionReleaseAuthorized,false);
 assert.equal(parsed.productionReleaseBlocked,true);
 assert.equal(parsed.releaseDecision,'HOLD');
 assert.equal(parsed.independentWitnessAdministrationVerified,false);
 assert.equal(parsed.realObjectLockDeletionDenialVerified,false);
 for(const args of [[],['--approve'],['--ci-hold','--credentials','SECRET'],
   ['--external-evidence','/tmp/sensitive'],['--enable-production']]){
  const rejected=run(args);
  assert.equal(rejected.status,2);
  assert.equal(rejected.stdout,'');
  assert.match(rejected.stderr,/HOLD/);
  assert.ok(!rejected.stderr.includes('SECRET'));
  assert.ok(!rejected.stderr.includes('/tmp/sensitive'));
 }
});
