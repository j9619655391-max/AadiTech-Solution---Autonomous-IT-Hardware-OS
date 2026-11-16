import test from 'node:test';
import assert from 'node:assert/strict';
import {beFixture} from './support/phase1beFixture.mjs';
import {assessPhase1BeRevocationFreeze,phase1BeFreezeSigningBytes}
 from '../scripts/lib/phase1BeRevocationFreeze.mjs';
const assess=x=>assessPhase1BeRevocationFreeze(x);
const h=n=>n.toString(16).padStart(64,'0');
test('zero-input freeze cannot authorize witness trust or production release',()=>{
 const r=assess();
 assert.equal(r.locallyCoSignedFreezeConsistent,false);
 assert.equal(r.incidentSha256,null);
 assert.equal(r.witnessKeyExternallyRevoked,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.ok(r.blockerCodes.includes('INCOMPLETE_EMERGENCY_FREEZE_EVIDENCE'));
});
test('genuine local Ed25519 co-signatures freeze a candidate without external trust promotion',()=>{
 const r=assess(beFixture());
 assert.equal(r.locallyCoSignedFreezeConsistent,true,r.blockerCodes.join(','));
 assert.match(r.incidentSha256,/^[0-9a-f]{64}$/);
 assert.match(r.bdReviewSha256,/^[0-9a-f]{64}$/);
 assert.match(r.azPacketSha256,/^[0-9a-f]{64}$/);
 for(const k of ['independentlyAuthenticatedRevocationSource',
   'independentlyAuthenticatedWitnessQuorum','witnessKeyExternallyRevoked',
   'actualObjectLockEnforcementVerified','actualEncryptedDRVerified',
   'productionReleaseAuthorized'])assert.equal(r[k],false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('reviewer signing order does not change canonical incident digest',()=>{
 const f=beFixture(),first=assess(f);
 f.governanceSignatures.reverse();
 const second=assess(f);
 assert.equal(second.locallyCoSignedFreezeConsistent,true,second.blockerCodes.join(','));
 assert.equal(first.incidentSha256,second.incidentSha256);
});
test('forged or missing survivor signature rejects even with three valid governance signatures',()=>{
 const f=beFixture();
 f.survivingWitnessSignature.signature.signatureBase64=Buffer.alloc(64,3).toString('base64');
 const r=assess(f);
 assert.equal(r.locallyCoSignedFreezeConsistent,false);
 assert.ok(r.blockerCodes.includes('SURVIVING_WITNESS_COSIGNATURE_INVALID'));
 const missing=beFixture();
 missing.survivingWitnessSignature=null;
 assert.ok(assess(missing).blockerCodes.includes('INCOMPLETE_EMERGENCY_FREEZE_EVIDENCE'));
});
test('compromised key cannot self-co-sign as the surviving independent authority',()=>{
 const f=beFixture();
 f.survivingWitnessSignature.pin={...f.bdEvidence.witnessEnrollments[0].pin};
 const r=assess(f);
 assert.equal(r.locallyCoSignedFreezeConsistent,false);
 assert.ok(r.blockerCodes.includes('SURVIVING_WITNESS_COSIGNATURE_INVALID'));
 const own=beFixture();
 own.body.survivingWitnessRef=own.body.revokedWitnessRef;
 assert.throws(()=>phase1BeFreezeSigningBytes(own.body));
});
test('forged tri-role signatures, duplicate or unregistered reviewer identity fail closed',()=>{
 const f=beFixture();
 f.governanceSignatures[0].signature.signatureBase64=Buffer.alloc(64,5).toString('base64');
 let r=assess(f);
 assert.equal(r.locallyCoSignedFreezeConsistent,false);
 assert.ok(r.blockerCodes.includes('INVALID_FREEZE_REVIEWER_SIGNATURE_OR_ENROLLMENT'));
 const duplicate=beFixture();
 duplicate.governanceSignatures[1].pin.authorityRef=
   duplicate.governanceSignatures[0].pin.authorityRef;
 r=assess(duplicate);
 assert.ok(r.blockerCodes.includes('COMMON_CONTROL_OF_FREEZE_REVIEWERS'));
 assert.ok(r.blockerCodes.includes('INVALID_FREEZE_REVIEWER_SIGNATURE_OR_ENROLLMENT'));
 const unknown=beFixture();
 unknown.governanceSignatures[2].pin.role='WITNESS';
 r=assess(unknown);
 assert.ok(r.blockerCodes.includes('MISSING_INDEPENDENT_FREEZE_REVIEWER'));
 assert.ok(r.blockerCodes.includes('INVALID_FREEZE_ROLE_QUORUM'));
});
test('BD signed provider receipt, prior revocation snapshot and DR telemetry are exactly bound',()=>{
 for(const field of ['claimedObjectLockDenialReceiptSha256',
  'claimedEncryptedRestoreTelemetrySha256','previousRevocationSnapshotSha256',
  'archiveObjectSha256','bdReviewSha256','storageObjectVersionSha256']){
  const f=beFixture();
  f.body[field]=h(900);
  f.resign();
  const r=assess(f);
  assert.equal(r.locallyCoSignedFreezeConsistent,false,field);
  assert.ok(r.blockerCodes.includes('INCIDENT_BINDING_TO_AZ_BD_EVIDENCE_INVALID'),field);
 }
});
test('changed revocation notice changes incident commitment but never external revocation status',()=>{
 const f=beFixture(),first=assess(f);
 f.body.revocationNoticeSha256=h(999);
 f.resign();
 const second=assess(f);
 assert.equal(second.locallyCoSignedFreezeConsistent,true,second.blockerCodes.join(','));
 assert.notEqual(second.incidentSha256,first.incidentSha256);
 assert.equal(second.witnessKeyExternallyRevoked,false);
});
test('replacing BD evidence content without revalidating signed history is rejected',()=>{
 const f=beFixture();
 f.bdEvidence.storageReceipt.body.providerCreateReceiptSha256=h(1234);
 const r=assess(f);
 assert.equal(r.locallyCoSignedFreezeConsistent,false);
 assert.ok(r.blockerCodes.includes('UNVERIFIED_UPSTREAM_1BD_CANDIDATE_EVIDENCE'));
});
test('future/expired quarantine, delayed activation and forbidden GO are denied',()=>{
 const f=beFixture();
 assert.throws(()=>phase1BeFreezeSigningBytes({...f.body,releaseDecision:'GO'}));
 assert.throws(()=>phase1BeFreezeSigningBytes({...f.body,quarantineRequired:false}));
 assert.throws(()=>phase1BeFreezeSigningBytes({...f.body,outboundHeld:false}));
 assert.throws(()=>phase1BeFreezeSigningBytes({...f.body,providerToken:'DO_NOT_STORE'}));
 assert.throws(()=>phase1BeFreezeSigningBytes({...f.body,
  freezeEffectiveAt:'2026-11-16T18:15:00.000Z'}));
 const stale=beFixture();
 assert.ok(assess({...stale,now:new Date('2026-11-17T18:00:00.000Z')})
  .blockerCodes.includes('STALE_FUTURE_OR_UNEFFECTIVE_FREEZE'));
 const future=beFixture();
 future.body.detectedAt='2027-11-16T17:54:00.000Z';
 future.body.freezeEffectiveAt='2027-11-16T17:55:00.000Z';
 future.body.expiresAt='2027-11-16T18:30:00.000Z';
 future.resign();
 assert.ok(assess(future).blockerCodes.includes('STALE_FUTURE_OR_UNEFFECTIVE_FREEZE'));
});
test('preflight CLI denies secrets, evidence files, external activation and unauthorized GO',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const path=fileURLToPath(new URL('../scripts/phase1be-revocation-freeze-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[path,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const good=run(['--ci-hold']);
 assert.equal(good.status,0,good.stderr);
 const r=JSON.parse(good.stdout);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.witnessKeyExternallyRevoked,false);
 for(const args of [[],['--approve'],['--go-live'],
  ['--ci-hold','--provider-secret','DONT_PRINT_KEY'],
  ['--evidence-file','/tmp/private-cert-chain']]){
  const denied=run(args);
  assert.equal(denied.status,2);
  assert.equal(denied.stdout,'');
  assert.match(denied.stderr,/HOLD/);
  assert.ok(!denied.stderr.includes('DONT_PRINT_KEY'));
  assert.ok(!denied.stderr.includes('/tmp/private-cert-chain'));
 }
});
