import test from 'node:test';
import assert from 'node:assert/strict';
import {assessCandidateExternalIntake,candidateIntakePacketDigest,
 candidateIntakePinsetDigest} from '../server/commercialIntegrity/quoteEvidenceIntake';
import {bpNow,bpSha,bpPins,bpPinsetSha,bpExpectedFixture,
 bpPacketFixture,bpResign,bpClone} from './bp-intake-fixtures';

const expected=bpExpectedFixture();
const check=(packet=bpPacketFixture(expected),config=expected,
 pins=bpPins,expectedPins=bpPinsetSha)=>
 assessCandidateExternalIntake({packet,expected:config,pinnedKeys:pins,
  expectedPinsetSha256:expectedPins,now:bpNow});
test('BP: four valid synthetic independently supplied signer pins are never production authority',()=>{
 const packet=bpPacketFixture(),r=check(packet);
 assert.equal(r.candidateIntakeConsistent,true,r.candidateIntakeAnomalyCodes.join(','));
 assert.match(r.candidateIntakePacketSha256!,/^[a-f0-9]{64}$/);
 assert.equal(r.candidateIntakePinsetSha256,bpPinsetSha);
 assert.equal(candidateIntakePinsetDigest([...bpPins].reverse()),bpPinsetSha);
 assert.equal(candidateIntakePacketDigest(packet),r.candidateIntakePacketSha256);
 for(const flag of [
  'authenticatedExternalKeyEnrollment','trustedIndependentHeadRetrieved',
  'actualCrlOcspChainAuthenticated','independentWormObjectLockVerified',
  'realWitnessedDrRecoveryVerified','issuerLegalAuthorityVerified',
  'productionReleaseAuthorized'] as const)assert.equal(r[flag],false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BP: applicant-supplied public key or modified signed claim is rejected',()=>{
 const packet=bpPacketFixture();
 const altered=bpClone(packet) as any;
 altered.claims[0].body.trustedPublicKeyPem='attacker-key';
 assert.ok(check(altered).candidateIntakeAnomalyCodes.includes('BP_CLAIM_SHAPE_INVALID'));
 const tampered=bpClone(packet);
 tampered.claims[0].body.publicationHeadSha256=bpSha('f');
 assert.ok(check(tampered).candidateIntakeAnomalyCodes.includes(
  'BP_SIGNED_CANDIDATE_EVIDENCE_INVALID'));
 const forged=bpClone(packet);
 forged.claims[0].signatureBase64=Buffer.alloc(64,3).toString('base64');
 assert.ok(check(forged).candidateIntakeAnomalyCodes.includes(
  'BP_SIGNED_CANDIDATE_EVIDENCE_INVALID'));
});
test('BP: wrong external pin digest, signer role reuse or unpinned key cannot attest',()=>{
 assert.ok(check(bpPacketFixture(),expected,bpPins,bpSha('e')).
  candidateIntakeAnomalyCodes.includes('BP_CONFIGURED_PINSET_MISMATCH'));
 const duplicates=[...bpPins];duplicates[1]=duplicates[0];
 assert.ok(check(bpPacketFixture(),expected,duplicates).
  candidateIntakeAnomalyCodes.includes('BP_PINSET_INVALID'));
 const revoked=[...bpPins];revoked[1]={...revoked[1],status:'REVOKED'};
 assert.equal(check(bpPacketFixture(),expected,revoked,
  candidateIntakePinsetDigest(revoked)).candidateIntakeConsistent,false);
 const sameRole=bpClone(bpPacketFixture());sameRole.claims[3]=sameRole.claims[0];
 assert.ok(check(sameRole).candidateIntakeAnomalyCodes.includes(
  'BP_SIGNER_ROLE_SOURCE_COLLISION'));
});
test('BP: signed but split publication head, issuer revocation or out-of-band WORM claims freeze',()=>{
 const changes=[
  {publicationHeadSha256:bpSha('f')},
  {crlSha256:bpSha('f')},{ocspSha256:bpSha('f')},
  {revocationEpoch:5},{revocationEpoch:2},
  {revocationNextUpdate:'2026-11-17T14:40:00.000Z'},
  {retentionUntil:'2026-11-17T15:01:00.000Z'},
  {overwriteDenied:false},{deleteDenied:false},
  {observedAt:'2026-11-17T12:00:00.000Z'},
  {observedAt:'2026-11-17T15:08:00.000Z'}
 ];
 for(const change of changes){
  const packet=bpResign(bpPacketFixture(),'ISSUER',change);
  const r=check(packet);
  assert.equal(r.candidateIntakeConsistent,false,JSON.stringify(change));
  assert.equal(r.trustedIndependentHeadRetrieved,false);
  assert.equal(r.actualCrlOcspChainAuthenticated,false);
  assert.equal(r.independentWormObjectLockVerified,false);
 }
});
test('BP: even signed WORM denial and DR statements are unverified and rollback fails',()=>{
 for(const change of [
  {restoredSequence:1},{restoredSequence:3},
  {restoredReceiptSha256:bpSha('f')},
  {restoredSourceSha256:bpSha('f')},
  {rtoSeconds:999999},
  {rpoSeconds:-1},
  {evidenceState:'VERIFIED' as any}
 ]){
  const packet=bpResign(bpPacketFixture(),'RECOVERY',change);
  assert.equal(check(packet).candidateIntakeConsistent,false,JSON.stringify(change));
 }
 const ok=check(bpPacketFixture());
 assert.equal(ok.realWitnessedDrRecoveryVerified,false);
});
test('BP: incorrect quote, dossier, challenge or BM/BN chain is always held',()=>{
 for(const change of [
  {quoteId:'33333333-3333-4333-8333-333333333333'},
  {boDossierSha256:bpSha('f')},
  {challengeSha256:bpSha('f')},
  {bnPacketSha256:bpSha('f')},
  {bmReceiptSha256:bpSha('f')}
 ]){
  const packet=bpResign(bpPacketFixture(),'PUBLISHER',change);
  assert.equal(check(packet).candidateIntakeConsistent,false,JSON.stringify(change));
 }
 const offline=bpClone(bpPacketFixture()) as any;
 offline.isIndependentTrusted=true;
 assert.ok(check(offline).candidateIntakeAnomalyCodes.includes('BP_PACKET_SHAPE_INVALID'));
 const missing=bpClone(bpPacketFixture());missing.claims.pop();
 assert.equal(check(missing).candidateIntakeConsistent,false);
 const baddossier={...expected,boLocallyConsistent:false};
 assert.ok(check(bpPacketFixture(),baddossier).
  candidateIntakeAnomalyCodes.includes('BP_UPSTREAM_BO_NOT_READY'));
});
