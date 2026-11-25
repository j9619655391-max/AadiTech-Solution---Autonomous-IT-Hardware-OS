import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {phase1AzAssessReadiness,AZ_PURPOSE} from '../scripts/lib/phase1AzExternalReadiness.mjs';
import {ANCHOR_PURPOSE,RECOVERY_PURPOSE,phase1AyInclusionLeafHash,
 phase1AyAnchorSigningBytes,phase1AyRecoverySigningBytes
} from '../scripts/lib/phase1AyWitnessArchiveRecovery.mjs';
import {BA_PROBE_PURPOSE,phase1BaProbeSigningBytes,
 assessPhase1BaIndependentAcceptance} from '../scripts/lib/phase1BaIndependentAcceptance.mjs';
const now=new Date('2026-11-16T17:00:00.000Z');
const h=n=>n.toString(16).padStart(64,'0');
const sha=x=>createHash('sha256').update(x).digest('hex');
function actor(n,role,authorityRef){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 return {privateKey,pin:{role,reviewerRef:'assessor-'+n,keyId:'assessment-key-'+n,
  authorityRef,publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
  publicKeySha256:sha(publicKey.export({format:'der',type:'spki'}))}};
}
const signature=(data,actor)=>({reviewerRef:actor.pin.reviewerRef,keyId:actor.pin.keyId,
 signatureBase64:sign(null,data,actor.privateKey).toString('base64')});
function dossier(){
 return {schemaVersion:1,purpose:AZ_PURPOSE,revision:1,previousPacketSha256:null,
  witnesses:[
   {witnessRef:'external-witness-001',organizationRef:'witness-entity-001',
    administrativeAuthorityRef:'witness-admin-001',publicKeySpkiSha256:h(1),
    contractSha256:h(2),publisherPolicySha256:h(3),
    scope:'CHECKPOINT_WITNESS_ONLY',state:'CANDIDATE_UNVERIFIED'},
   {witnessRef:'external-witness-002',organizationRef:'witness-entity-002',
    administrativeAuthorityRef:'witness-admin-002',publicKeySpkiSha256:h(4),
    contractSha256:h(5),publisherPolicySha256:h(6),
    scope:'CHECKPOINT_WITNESS_ONLY',state:'CANDIDATE_UNVERIFIED'}],
  archive:{logRef:'checkpoint-log-001',checkpointReceiptSha256:h(11),
   archiveObjectSha256:h(12),storageAccountSha256:h(13),
   objectVersionIdSha256:h(14),retentionPolicySha256:h(15),
   encryptionKeyIdentifierSha256:h(16),claimedLockMode:'COMPLIANCE',
   legalHoldEvidenceSha256:h(17),createdAt:'2026-11-01T00:00:00.000Z',
   retentionUntil:'2027-05-01T00:00:00.000Z',minimumRetentionDays:90,
   externalStorageState:'NOT_VERIFIED'},
  recovery:{incidentRef:'restore-incident-001',
   sourceCheckpointReceiptSha256:h(11),restoredCheckpointReceiptSha256:h(11),
   sourceManifestSha256:h(20),restoredManifestSha256:h(20),
   archiveObjectSha256:h(12),revocationSnapshotSha256:h(21),
   startedAt:'2026-11-15T12:00:00.000Z',completedAt:'2026-11-15T12:05:00.000Z',
   measuredRpoMs:150,rtoObjectiveMs:600000,rpoObjectiveMs:500,
   encryptedRestoreState:'NOT_EXTERNALLY_VERIFIED',outboundHeld:true},
  approvers:[
   {role:'SECURITY',reviewerRef:'security-reviewer-001',authorityRef:'security-admin-001',reviewRecordSha256:h(31)},
   {role:'OPERATIONS',reviewerRef:'operations-reviewer-002',authorityRef:'operations-admin-002',reviewRecordSha256:h(32)},
   {role:'OWNER',reviewerRef:'owner-reviewer-003',authorityRef:'owner-admin-003',reviewRecordSha256:h(33)}],
  releaseDecision:'HOLD'};
}
function fixture(){
 const azPacket=dossier(),a=azPacket.archive,r=azPacket.recovery;
 const witnessActors=[actor(1,'WITNESS','witness-org-101'),
  actor(2,'WITNESS','witness-org-102')];
 azPacket.witnesses.forEach((w,i)=>{
  w.publicKeySpkiSha256=witnessActors[i].pin.publicKeySha256;
  w.administrativeAuthorityRef=witnessActors[i].pin.authorityRef;
 });
 const body={schemaVersion:1,purpose:ANCHOR_PURPOSE,logRef:a.logRef,
  checkpointReceiptSha256:a.checkpointReceiptSha256,
  archiveObjectSha256:a.archiveObjectSha256,
  treeSize:1,leafIndex:0,rootSha256:h(101),
  issuedAt:'2026-11-16T16:00:00.000Z',expiresAt:'2026-11-16T18:00:00.000Z',
  releaseDecision:'HOLD'};
 body.rootSha256=sha(Buffer.concat([Buffer.from([0]),phase1AyInclusionLeafHash(body)]));
 const anchors=witnessActors.map(w=>({body,signature:signature(phase1AyAnchorSigningBytes(body),w),
  inclusionProofSha256:[]}));
 const wormProbe={schemaVersion:1,purpose:BA_PROBE_PURPOSE,logRef:a.logRef,
  checkpointReceiptSha256:a.checkpointReceiptSha256,archiveObjectSha256:a.archiveObjectSha256,
  objectVersionIdSha256:a.objectVersionIdSha256,retentionPolicySha256:a.retentionPolicySha256,
  probeEvidenceSha256:h(123),retentionUntil:a.retentionUntil,
  startedAt:'2026-11-16T16:05:00.000Z',completedAt:'2026-11-16T16:06:00.000Z',
  deleteAttempt:'DENIED_CLAIMED',overwriteAttempt:'DENIED_CLAIMED',releaseDecision:'HOLD'};
 const auditorActors=[actor(3,'STORAGE_AUDITOR','storage-admin-103'),
  actor(4,'SECURITY_AUDITOR','security-admin-104')];
 const wormSignatures=auditorActors.map(w=>signature(phase1BaProbeSigningBytes(wormProbe),w));
 const drRehearsal={schemaVersion:1,purpose:RECOVERY_PURPOSE,
  incidentRef:r.incidentRef,checkpointReceiptSha256:r.sourceCheckpointReceiptSha256,
  restoredCheckpointReceiptSha256:r.restoredCheckpointReceiptSha256,
  backupManifestSha256:r.sourceManifestSha256,restoredManifestSha256:r.restoredManifestSha256,
  revocationSnapshotSha256:r.revocationSnapshotSha256,
  startedAt:r.startedAt,completedAt:r.completedAt,measuredRpoMs:r.measuredRpoMs,
  rtoTargetMs:r.rtoObjectiveMs,rpoTargetMs:r.rpoObjectiveMs,
  outboundHeld:true,releaseDecision:'HOLD'};
 const recoveryActors=[actor(5,'SECURITY','recovery-admin-105'),
  actor(6,'OPERATIONS','recovery-admin-106'),
  actor(7,'OWNER','recovery-admin-107')];
 const drSignatures=recoveryActors.map(x=>signature(phase1AyRecoverySigningBytes(drRehearsal),x));
 azPacket.approvers.forEach((w,i)=>{
  w.reviewerRef=recoveryActors[i].pin.reviewerRef;
  w.authorityRef=recoveryActors[i].pin.authorityRef;
 });
 const azExpectedDigest=phase1AzAssessReadiness(azPacket,{now}).packetSha256;
 return {azPacket,azExpectedDigest,anchors,witnessPins:witnessActors.map(x=>x.pin),
  wormProbe,wormPins:auditorActors.map(x=>x.pin),wormSignatures,
  drRehearsal,drPins:recoveryActors.map(x=>x.pin),drSignatures,now};
}
const assess=x=>assessPhase1BaIndependentAcceptance(x);
test('zero-input BA always hard blocks external authentication and release',()=>{
 const r=assess();
 assert.equal(r.internalClaimsConsistent,false);
 assert.equal(r.independentlyAuthenticatedWitnesses,false);
 assert.equal(r.immutableRetentionEnforced,false);
 assert.equal(r.encryptedDRWitnessed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.ok(r.blockerCodes.includes('INCOMPLETE_CROSS_BOUND_EVIDENCE'));
});
test('valid local cross-bound cryptographic fixtures can never self-authorize external trust',()=>{
 const x=fixture(),r=assess(x);
 assert.equal(r.internalClaimsConsistent,true,r.blockerCodes.join(','));
 assert.equal(r.azDigestMatch,true);
 assert.equal(r.witnessClaimsConsistent,true);
 assert.equal(r.archiveDenialClaimSignaturesConsistent,true);
 assert.equal(r.recoveryClaimSignaturesConsistent,true);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.immutableRetentionEnforced,false);
 assert.equal(r.encryptedDRWitnessed,false);
 assert.ok(r.blockerCodes.includes('EXTERNAL_WORM_OPERATION_NOT_VERIFIED'));
});
test('replayed or substituted AZ packet fingerprint is blocked even with valid signatures',()=>{
 const x=fixture();
 const r=assess({...x,azExpectedDigest:h(155)});
 assert.equal(r.internalClaimsConsistent,false);
 assert.ok(r.blockerCodes.includes('AZ_DIGEST_OR_CONTENT_MISMATCH'));
 const alt={...x.azPacket,archive:{...x.azPacket.archive,
  storageAccountSha256:h(999)}};
 const changed=assess({...x,azPacket:alt});
 assert.equal(changed.internalClaimsConsistent,false);
 assert.ok(changed.blockerCodes.includes('AZ_DIGEST_OR_CONTENT_MISMATCH'));
});
test('witness disappearance, tampered inclusion, and claimed organizational duplication fail closed',()=>{
 const x=fixture();
 const noQuorum=assess({...x,anchors:x.anchors.slice(0,1)});
 assert.ok(noQuorum.blockerCodes.includes('WITNESS_CRYPTO_OR_QUORUM_MISMATCH'));
 const badAnchor=structuredClone(x.anchors);
 badAnchor[0].inclusionProofSha256=[h(44)];
 const invalid=assess({...x,anchors:badAnchor});
 assert.ok(invalid.blockerCodes.includes('WITNESS_CRYPTO_OR_QUORUM_MISMATCH'));
 const collision=assess({...x,witnessPins:[x.witnessPins[0],
  {...x.witnessPins[1],authorityRef:x.witnessPins[0].authorityRef}]});
 assert.ok(collision.blockerCodes.includes('WITNESS_CRYPTO_OR_QUORUM_MISMATCH'));
});
test('archive probe signature, policy object version and WORM claim are immutable-bound',()=>{
 const x=fixture();
 const forged=structuredClone(x.wormSignatures);
 forged[0].signatureBase64=Buffer.alloc(64,9).toString('base64');
 assert.ok(assess({...x,wormSignatures:forged}).blockerCodes.includes('ARCHIVE_ATTESTATION_INVALID'));
 const mismatch=assess({...x,wormProbe:{...x.wormProbe,objectVersionIdSha256:h(98)}});
 assert.ok(mismatch.blockerCodes.includes('ARCHIVE_PROBE_NOT_BOUND_TO_AZ'));
 assert.throws(()=>assess({...x,wormProbe:{...x.wormProbe,deleteAttempt:'SUCCEEDED'}}));
 assert.throws(()=>assess({...x,wormProbe:{...x.wormProbe,releaseDecision:'GO'}}));
 assert.throws(()=>assess({...x,wormProbe:{...x.wormProbe,credentials:'DO_NOT_LOG'}}));
});
test('archive auditors cannot be self-approved or share witness administrative control',()=>{
 const x=fixture();
 const shared=assess({...x,wormPins:[x.wormPins[0],
  {...x.wormPins[1],authorityRef:x.wormPins[0].authorityRef}]});
 assert.ok(shared.blockerCodes.includes('ARCHIVE_AUDITOR_NOT_INDEPENDENT'));
 const cross=assess({...x,wormPins:[
  {...x.wormPins[0],authorityRef:x.witnessPins[0].authorityRef},x.wormPins[1]]});
 assert.ok(cross.blockerCodes.includes('WITNESS_AND_STORAGE_AUDITOR_COLLISION'));
});
test('DR restored receipt, manifests, measurements and claimed independence are bound to AZ',()=>{
 const x=fixture();
 const wrongRestore=assess({...x,drRehearsal:{
  ...x.drRehearsal,restoredManifestSha256:h(88)}});
 assert.ok(wrongRestore.blockerCodes.includes('DR_ATTESTATION_OR_OBJECTIVE_MISMATCH'));
 assert.ok(wrongRestore.blockerCodes.includes('DR_NOT_BOUND_TO_AZ_ARCHIVE_AND_PROBE'));
 const wrongAdmin=assess({...x,drPins:[{...x.drPins[0],
  authorityRef:x.wormPins[0].authorityRef},...x.drPins.slice(1)]});
 assert.ok(wrongAdmin.blockerCodes.includes('RECOVERY_AND_WITNESS_AUDITOR_COLLISION'));
 const missing=assess({...x,drSignatures:x.drSignatures.slice(0,2)});
 assert.ok(missing.blockerCodes.includes('DR_ATTESTATION_OR_OBJECTIVE_MISMATCH'));
 const expired=assess({...x,drRehearsal:{...x.drRehearsal,rtoTargetMs:100}});
 assert.ok(expired.blockerCodes.includes('DR_ATTESTATION_OR_OBJECTIVE_MISMATCH'));
});
test('future archive probe and expired retention are always denied',()=>{
 const x=fixture();
 const future=assess({...x,wormProbe:{
  ...x.wormProbe,startedAt:'2026-11-16T20:00:00.000Z',
  completedAt:'2026-11-16T20:01:00.000Z'}});
 assert.ok(future.blockerCodes.includes('FUTURE_ARCHIVE_PROBE'));
 assert.throws(()=>assess({...x,wormProbe:{
  ...x.wormProbe,retentionUntil:'2026-11-16T16:00:00.000Z'}}));
});
test('zero-input CLI rejects evidence paths and deploy switches without echoing secrets',()=>{
 const script=fileURLToPath(new URL('../scripts/phase1ba-independent-acceptance-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[script,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',GITHUB_ACTIONS:'true'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const ok=run(['--ci-hold']);
 assert.equal(ok.status,0,ok.stderr);
 const data=JSON.parse(ok.stdout);
 assert.equal(data.releaseDecision,'HOLD');
 assert.equal(data.productionReleaseBlocked,true);
 assert.equal(data.productionReleaseAuthorized,false);
 for(const args of [[],['--go'],['--ci-hold','--credential','HIGHLY_SENSITIVE'],
  ['--file','/tmp/private-info'],['--publish']]){
  const result=run(args);
  assert.equal(result.status,2);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/HOLD/);
  assert.equal(result.stderr.includes('HIGHLY_SENSITIVE'),false);
  assert.equal(result.stderr.includes('/tmp/private-info'),false);
 }
});

test('signed witness key and recovery reviewer must match AZ digest-bound dossier identities',()=>{
 const x=fixture(),wrongWitness=structuredClone(x.azPacket);
 wrongWitness.witnesses[0].publicKeySpkiSha256=h(999);
 let result=assess({...x,azPacket:wrongWitness,
  azExpectedDigest:phase1AzAssessReadiness(wrongWitness,{now}).packetSha256});
 assert.ok(result.blockerCodes.includes('WITNESS_KEY_NOT_BOUND_TO_AZ_ENROLLMENT'));
 assert.equal(result.internalClaimsConsistent,false);
 const wrongRecovery=structuredClone(x.azPacket);
 wrongRecovery.approvers[0].authorityRef='unapproved-operator-001';
 result=assess({...x,azPacket:wrongRecovery,
  azExpectedDigest:phase1AzAssessReadiness(wrongRecovery,{now}).packetSha256});
 assert.ok(result.blockerCodes.includes('RECOVERY_SIGNER_NOT_BOUND_TO_AZ_REVIEW'));
 assert.equal(result.productionReleaseAuthorized,false);
});
