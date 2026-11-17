import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {assessCandidateRemoteEvidence,candidateRemotePacketDigest,
 candidateEndpointConfigDigest,candidateCollectorPinsetDigest,
 type CandidateRemotePacket,type CandidateRemoteExpected}
 from '../server/commercialIntegrity/quoteRemoteEvidence';
import {bqNow,bqSha,bqClone,bqRoot,bqRootSha,bqCollectors,bqCollectorsSha,
 bqEndpoints,bqEndpointsSha,bqExpectedFixture,bqPacketFixture,
 bqResignCapture,bqResignManifest}
 from './bq-remote-fixtures';

function assess(p:CandidateRemotePacket=bqPacketFixture(),
 e:CandidateRemoteExpected=bqExpectedFixture(),
 overrides:Record<string,unknown>={}){
 return assessCandidateRemoteEvidence({
  packet:p,expected:e,registrarPin:bqRoot,collectorPins:bqCollectors,
  endpoints:bqEndpoints,expectedRegistrarPinSha256:bqRootSha,
  expectedCollectorPinsetSha256:bqCollectorsSha,
  expectedEndpointConfigSha256:bqEndpointsSha,
  now:bqNow,...overrides
 });
}
test('BQ consistent offline registrar/collector signatures remain candidate-only HOLD',()=>{
 const p=bqPacketFixture(),result=assess(p);
 assert.equal(result.candidateRemoteEvidenceConsistent,true,
  result.candidateRemoteEvidenceAnomalyCodes.join(','));
 assert.equal(result.candidateRemotePacketSha256,candidateRemotePacketDigest(p));
 assert.match(result.candidateRegistrarPinSha256,/^[a-f0-9]{64}$/);
 assert.equal(result.candidateCollectorPinsetSha256,bqCollectorsSha);
 assert.equal(result.candidateEndpointConfigSha256,bqEndpointsSha);
 assert.equal(candidateCollectorPinsetDigest([...bqCollectors].reverse()),bqCollectorsSha);
 assert.equal(candidateEndpointConfigDigest([...bqEndpoints].reverse()),bqEndpointsSha);
 for(const flag of ['authenticatedRegistrarEnrollment','authenticatedIssuerChain',
  'liveRemoteCheckpointRetrieved','actualTlsSessionVerified',
  'liveSignedCrlOcspValidated','independentWormVerified',
  'realDrRecoveryWitnessed','productionReleaseAuthorized'] as const)
  assert.equal(result[flag],false,flag);
 assert.equal(result.releaseDecision,'HOLD');
});
test('BQ candidate registrar pin substitution and fake independent enrollment fail closed',()=>{
 const invalid=assess(bqPacketFixture(),bqExpectedFixture(),
  {expectedRegistrarPinSha256:bqSha('f')});
 assert.ok(invalid.candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_OPERATOR_CONFIG_PIN_MISMATCH'));
 const forged=bqClone(bqPacketFixture());
 forged.manifestSignatureBase64=Buffer.alloc(64,3).toString('base64');
 assert.ok(assess(forged).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_MANIFEST_SIGNATURE_INVALID'));
 const fake=bqResignManifest(bqPacketFixture(),
  {state:'PRODUCTION_AUTHORIZED' as any});
 assert.ok(assess(fake).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_MANIFEST_SHAPE_OR_AUTHORITY_CLAIM_INVALID'));
 const future=bqResignManifest(bqPacketFixture(),
  {issuedAt:'2026-11-17T16:00:00.000Z'});
 assert.ok(assess(future).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_MANIFEST_STALE_OR_FUTURE'));
 const publicSmuggle=bqClone(bqPacketFixture()) as any;
 publicSmuggle.manifest.registrarPublicKeySpkiPem='attacker';
 assert.ok(assess(publicSmuggle).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_MANIFEST_SHAPE_OR_AUTHORITY_CLAIM_INVALID'));
});
test('BQ transport contract enforces independent configured HTTPS origins/TLS pins, no redirects',()=>{
 assert.throws(()=>candidateEndpointConfigDigest([
  {...bqEndpoints[0],origin:'http://publisher-candidate.invalid/'},
  bqEndpoints[1]]));
 assert.throws(()=>candidateEndpointConfigDigest([
  {...bqEndpoints[0],origin:'https://localhost/'},
  bqEndpoints[1]]));
 assert.throws(()=>candidateEndpointConfigDigest([
  {...bqEndpoints[0],origin:'https://admin:secret@publisher-candidate.invalid/'},
  bqEndpoints[1]]));
 const mutations=[
  {origin:'https://attacker-candidate.invalid/'},
  {tlsSpkiSha256:bqSha('f')},
  {redirectCount:1 as any},
  {httpStatus:302 as any},
  {transportMode:'LIVE_EXTERNAL_ATTESTED' as any},
  {retrievedAt:'2026-11-17T12:59:00.000Z'}
 ];
 for(const changed of mutations){
  const r=assess(bqResignCapture(bqPacketFixture(),'SECONDARY',changed));
  assert.equal(r.candidateRemoteEvidenceConsistent,false,JSON.stringify(changed));
  assert.equal(r.actualTlsSessionVerified,false);
 }
 const tampered=bqClone(bqPacketFixture());
 tampered.captures[0].body.remoteReceiptSha256=bqSha('f');
 assert.ok(assess(tampered).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_CAPTURE_SIGNATURE_INVALID'));
});
test('BQ different source keys, signature and canonical receipt fields are mandatory',()=>{
 const packet=bqClone(bqPacketFixture());
 packet.captures[1]=packet.captures[0];
 assert.ok(assess(packet).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_DUPLICATE_COLLECTOR_ROLE_OR_KEY'));
 const stolen=bqClone(bqPacketFixture());
 stolen.captures[0].signatureBase64=stolen.captures[1].signatureBase64;
 assert.ok(assess(stolen).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_CAPTURE_SIGNATURE_INVALID'));
 const swapped=[...bqCollectors];
 const foreign=generateKeyPairSync('ed25519');
 swapped[0]={...swapped[0],
  publicKeySpkiPem:foreign.publicKey.export({format:'pem',type:'spki'}).toString()};
 const r=assess(bqPacketFixture(),bqExpectedFixture(),{
  collectorPins:swapped,expectedCollectorPinsetSha256:candidateCollectorPinsetDigest(swapped)});
 assert.ok(r.candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_CAPTURE_SIGNATURE_INVALID'));
 const shadow=bqClone(bqPacketFixture()) as any;
 shadow.captures[0].body.externalTrustPassed=true;
 assert.ok(assess(shadow).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_CAPTURE_SHAPE_OR_NETWORK_PROOF_INVALID'));
});
test('BQ claimed remote head split, revocation mismatch and stale CRL/OCSP cannot become authority',()=>{
 const changes=[
  {remoteSequence:0},{remoteSequence:5},
  {remoteReceiptSha256:bqSha('f')},{remoteSourceSha256:bqSha('f')},
  {revocationEpoch:2},{revocationEpoch:6},
  {crlSha256:bqSha('e')},{ocspSha256:bqSha('e')},
  {issuerChainSha256:bqSha('e')},
  {revocationThisUpdate:'2026-11-17T12:00:00.000Z'},
  {revocationNextUpdate:'2026-11-17T14:00:00.000Z'}
 ];
 for(const changed of changes){
  const result=assess(bqResignCapture(bqPacketFixture(),'PRIMARY',changed));
  assert.equal(result.candidateRemoteEvidenceConsistent,false,JSON.stringify(changed));
  assert.equal(result.liveSignedCrlOcspValidated,false);
  assert.equal(result.productionReleaseAuthorized,false);
 }
});
test('BQ WORM claimed retention and DR restore rollback/fork remain unverified',()=>{
 for(const changed of [
  {wormDeleteDenied:false},{wormOverwriteDenied:false},
  {wormRetentionUntil:'2026-11-18T15:00:00.000Z'},
  {drRestoredSequence:0},{drRestoredSequence:2},
  {drRestoredReceiptSha256:bqSha('f')},
  {drRestoredSourceSha256:bqSha('e')},
  {drTranscriptSha256:bqSha('f')}
 ]){
  const r=assess(bqResignCapture(bqPacketFixture(),'SECONDARY',changed));
  assert.equal(r.candidateRemoteEvidenceConsistent,false,JSON.stringify(changed));
  assert.equal(r.realDrRecoveryWitnessed,false);
  assert.equal(r.independentWormVerified,false);
 }
});
test('BQ upstream BP quarantined, challenge replay or quote mismatch never passes',()=>{
 const p=bqPacketFixture();
 for(const override of [{bpExists:false},{bpLocallyConsistent:false},
  {bpGovernanceState:'QUARANTINED' as const},{bpPacketSha256:bqSha('e')}]){
  assert.equal(assess(p,bqExpectedFixture(override)).candidateRemoteEvidenceConsistent,false);
 }
 const challenge=bqClone(p);challenge.challengeSha256=bqSha('f');
 assert.ok(assess(challenge).candidateRemoteEvidenceAnomalyCodes.includes(
  'BQ_CHALLENGE_OR_MANIFEST_BINDING_MISMATCH'));
 const quote=bqClone(p);quote.quoteId='33333333-3333-4333-8333-333333333333';
 assert.equal(assess(quote).candidateRemoteEvidenceConsistent,false);
});
