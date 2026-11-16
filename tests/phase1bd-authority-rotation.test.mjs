import test from 'node:test';
import assert from 'node:assert/strict';
import {bdRotationFixture,now} from './support/phase1bdRotationFixture.mjs';
import {assessPhase1BdRotation,phase1BdRotationSigningBytes}
 from '../scripts/lib/phase1BdAuthorityRotation.mjs';

const evaluate=(f)=>assessPhase1BdRotation(f);
const digest=n=>n.toString(16).padStart(64,'0');
test('zero evidence cannot permit key rotation or external release',()=>{
 const r=assessPhase1BdRotation();
 assert.equal(r.locallySignedHandoverConsistent,false);
 assert.equal(r.handoverSha256,null);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
 assert.ok(r.blockerCodes.includes('INCOMPLETE_ROTATION_EVIDENCE'));
});
test('two organizations old/new key co-signature and triple review bind one append-only head',()=>{
 const f=bdRotationFixture(),r=evaluate(f);
 assert.equal(r.locallySignedHandoverConsistent,true,r.blockerCodes.join(','));
 assert.match(r.handoverSha256,/^[0-9a-f]{64}$/);
 assert.notEqual(r.previousWitnessPinSetSha256,r.replacementWitnessPinSetSha256);
 assert.equal(r.independentKeyCustodyVerified,false);
 assert.equal(r.independentSourceOfTruthAuthenticated,false);
 assert.equal(r.realObjectLockAuditVerified,false);
 assert.equal(r.realEncryptedDrVerified,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('cross-bound handover fingerprint changes when only claimed WORM or DR audit metadata changes',()=>{
 const f=bdRotationFixture(),original=evaluate(f);
 f.envelope.claimedObjectLockAuditSha256=digest(122);
 f.resign();
 const changed=evaluate(f);
 assert.equal(changed.locallySignedHandoverConsistent,true,changed.blockerCodes.join(','));
 assert.notEqual(changed.handoverSha256,original.handoverSha256);
 f.envelope.claimedEncryptedDrAuditSha256=digest(123);
 f.resign();
 assert.notEqual(evaluate(f).handoverSha256,changed.handoverSha256);
 assert.equal(evaluate(f).realObjectLockAuditVerified,false);
});
test('a forged or omitted retiring witness signature denies rotation without trust promotion',()=>{
 const f=bdRotationFixture();
 f.previousWitnessSignatures[0].signature.signatureBase64=
  Buffer.alloc(64,17).toString('base64');
 let r=evaluate(f);
 assert.equal(r.locallySignedHandoverConsistent,false);
 assert.ok(r.blockerCodes.includes('INVALID_WITNESS_COSIGNATURE'));
 const g=bdRotationFixture();
 g.replacementWitnessSignatures.pop();
 r=evaluate(g);
 assert.equal(r.locallySignedHandoverConsistent,false);
 assert.ok(r.blockerCodes.includes('MISSING_DUAL_WITNESS_COSIGNATURES'));
});
test('key must genuinely change and cannot be reused by another witness',()=>{
 const f=bdRotationFixture();
 f.replacement.azPacket.witnesses[0].publicKeySpkiSha256=
  f.previous.azPacket.witnesses[0].publicKeySpkiSha256;
 const r=evaluate(f);
 assert.ok(r.blockerCodes.includes('WITNESS_KEY_WAS_NOT_ROTATED'));
 assert.equal(r.locallySignedHandoverConsistent,false);
});
test('forged, swapped or non-independent governance signature is rejected',()=>{
 const f=bdRotationFixture();
 f.reviews[0].signature.signatureBase64=Buffer.alloc(64,5).toString('base64');
 let r=evaluate(f);
 assert.ok(r.blockerCodes.includes('INVALID_GOVERNANCE_REVIEW_SIGNATURE'));
 const g=bdRotationFixture();
 g.reviews[1].pin.authorityRef=g.reviews[0].pin.authorityRef;
 r=evaluate(g);
 assert.ok(r.blockerCodes.includes('UNENROLLED_GOVERNANCE_REVIEWER'));
 assert.ok(r.blockerCodes.includes('NONINDEPENDENT_GOVERNANCE_REVIEWER'));
 assert.equal(r.productionReleaseAuthorized,false);
});
test('historical tree split view and mismatched AZ predecessor fail even with locally signed co-signers',()=>{
 const f=bdRotationFixture();
 const forked=[...f.replacementFixture.leaves];
 forked[2]=Buffer.from('synthetic-forked-predecessor-leaf');
 f.replacement=f.replacementFixture.make(3,5,forked);
 let r=evaluate(f);
 assert.equal(r.locallySignedHandoverConsistent,false);
 assert.ok(r.blockerCodes.includes('ROTATION_FORKED_HISTORICAL_TREE_HEAD'));
 const g=bdRotationFixture();
 g.replacement.azPacket.previousPacketSha256=digest(123);
 r=evaluate(g);
 assert.ok(r.blockerCodes.includes('INVALID_AZ_ROTATION_PREDECESSOR'));
});
test('same org must keep claimed administrative authority until separately authenticated enrollment',()=>{
 const f=bdRotationFixture();
 f.replacement.azPacket.witnesses[0].administrativeAuthorityRef='different-admin-002';
 const r=evaluate(f);
 assert.ok(r.blockerCodes.includes('ROTATION_REPLACED_AUTHORITY_WITHOUT_ENROLLMENT'));
 assert.equal(r.productionReleaseBlocked,true);
});
test('old and new signatures bound to exact packet digest and audit fingerprints',()=>{
 const f=bdRotationFixture();
 f.envelope.claimedEncryptedDrAuditSha256=digest(77);
 const r=evaluate(f);
 assert.ok(r.blockerCodes.includes('INVALID_WITNESS_COSIGNATURE'));
 assert.ok(r.blockerCodes.includes('INVALID_GOVERNANCE_REVIEW_SIGNATURE'));
 const g=bdRotationFixture();
 g.envelope.previousEvidenceSha256=digest(78);
 g.resign();
 assert.ok(evaluate(g).blockerCodes.includes('ROTATION_ENVELOPE_PROOF_BINDING_MISMATCH'));
});
test('reject GO, injected secrets, invalid SPKI hashes, expired or future rotation claims',()=>{
 const f=bdRotationFixture();
 for(const changed of [
  {...f.envelope,releaseDecision:'GO'},
  {...f.envelope,secretToken:'SUPER_SECRET'},
  {...f.envelope,handoverRootSha256:'A'.repeat(64)},
  {...f.envelope,effectiveAt:'2026-11-16T18:30:00.000Z'},
  {...f.envelope,reason:'EMERGENCY_ACTIVATION'}
 ])assert.throws(()=>phase1BdRotationSigningBytes(changed));
 const stale=bdRotationFixture();
 assert.equal(assessPhase1BdRotation({...stale,
  now:new Date('2026-11-16T20:00:00.000Z')}).locallySignedHandoverConsistent,false);
 const future=bdRotationFixture();
 future.envelope.issuedAt='2027-11-16T18:00:00.000Z';
 future.envelope.effectiveAt='2027-11-16T18:01:00.000Z';
 future.envelope.expiresAt='2027-11-16T18:15:00.000Z';
 future.resign();
 const r=evaluate(future);
 assert.ok(r.blockerCodes.includes('STALE_OR_FUTURE_ROTATION_CLAIM'));
 assert.equal(r.productionReleaseAuthorized,false);
});

test('Phase 1BD CLI rejects activation, credentials and private evidence without echoing them',async()=>{
 const {spawnSync}=await import('node:child_process');
 const {fileURLToPath}=await import('node:url');
 const file=fileURLToPath(new URL('../scripts/phase1bd-authority-rotation-preflight.mjs',import.meta.url));
 const run=args=>spawnSync(process.execPath,[file,...args],{
  cwd:fileURLToPath(new URL('../',import.meta.url)),
  env:{NODE_ENV:'production',GITHUB_ACTIONS:'true',DB_NAME:'aaditech_production'},
  encoding:'utf8',timeout:8000,maxBuffer:32000
 });
 const valid=run(['--ci-hold']);
 assert.equal(valid.status,0,valid.stderr);
 const result=JSON.parse(valid.stdout);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.productionReleaseBlocked,true);
 assert.equal(result.releaseDecision,'HOLD');
 assert.equal(result.externalWitnessAuthorityAuthenticated,false);
 for(const args of [[],['--approve'],['--publish'],
  ['--ci-hold','--private-key','NEVER_LOG_THIS_SECRET'],
  ['--external-chain','/tmp/secret-pki']]){
  const rejected=run(args);
  assert.equal(rejected.status,2);
  assert.equal(rejected.stdout,'');
  assert.match(rejected.stderr,/HOLD/);
  assert.ok(!rejected.stderr.includes('NEVER_LOG_THIS_SECRET'));
  assert.ok(!rejected.stderr.includes('/tmp/secret-pki'));
 }
});
