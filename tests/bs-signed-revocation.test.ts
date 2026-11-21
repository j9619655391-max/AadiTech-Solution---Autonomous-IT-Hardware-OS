import test from 'node:test';
import assert from 'node:assert/strict';
import {assessCandidateSignedRevocation,type CandidateRevocationExpected}
 from '../server/commercialIntegrity/quoteSignedRevocation';
import {candidateBytePacketDigest}
 from '../server/commercialIntegrity/quoteProviderBytes';
import {bsSignedFixture,bsNow}
 from './bs-revocation-fixtures';
import {brHex,brRootSha}
 from './br-provider-byte-fixtures';

function evaluate(options:Parameters<typeof bsSignedFixture>[3]={},
 expectedChanges:Partial<CandidateRevocationExpected>={}){
 const f=bsSignedFixture(undefined,undefined,bsNow,options);
 const expected:CandidateRevocationExpected={
  quoteId:f.material.expected.quoteId,
  brPacketSha256:candidateBytePacketDigest(f.material.packet),
  rootCertSha256:brRootSha,
  minimumRevocationEpoch:4,brExists:true,brLocallyConsistent:true,
  brGovernanceState:'HELD_UNVERIFIED',...expectedChanges
 };
 return assessCandidateSignedRevocation({
  brPacket:f.material.packet,expected,
  issuerCertificatePem:f.issuerCertificatePem,
  expectedIssuerRootSha256:brRootSha,now:bsNow
 });
}
test('BS: genuine RSA-signed synthetic v2 CRL and OCSP BasicResponse validate offline, permanent HOLD',()=>{
 const r=evaluate();
 assert.equal(r.candidateSignedRevocationConsistent,true,
  r.candidateSignedRevocationAnomalyCodes.join(','));
 assert.equal(r.crlNumber,4);
 assert.equal(r.syntheticIssuerCrlSignatureChecked,true);
 assert.equal(r.syntheticIssuerOcspSignatureChecked,true);
 assert.equal(r.syntheticOcspSerialAndNonceChecked,true);
 assert.ok(r.crlUntil!>bsNow.getTime());
 assert.ok(r.ocspUntil!>bsNow.getTime());
 for(const name of [
  'independentlyEnrolledCAKey','genuineRCAIorCCAIssuerPolicyVerified',
  'realProviderCrlDistributionAuthenticated',
  'liveOcspRequestResponseAuthenticated',
  'externalMonotonicHeadIndependentlyRetained',
  'productionReleaseAuthorized'
 ] as const)assert.equal(r[name],false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BS: cryptographically rehashed candidate bytes never save invalid CRL/OCSP signatures',()=>{
 for(const c of [{crlUnsigned:true},{ocspUnsigned:true}]){
  const r=evaluate(c);
  assert.ok(r.candidateSignedRevocationAnomalyCodes.includes(
   'BS_ISSUER_SIGNATURE_INVALID'),JSON.stringify(r));
 }
});
test('BS: CRL lists target serial as revoked, OCSP revoked or unknown status blocked',()=>{
 for(const c of [{crlRevoked:true},{ocspStatus:'REVOKED' as const},
  {ocspStatus:'UNKNOWN' as const}]){
  const r=evaluate(c);
  assert.equal(r.candidateSignedRevocationConsistent,false,JSON.stringify(c));
  assert.ok(r.candidateSignedRevocationAnomalyCodes.some(s=>
   s.includes('REVOKED')||s.includes('TARGET_NOT_GOOD')),JSON.stringify(r));
 }
});
test('BS: OCSP CertID exact certificate serial, issuerNameHash and nonce required',()=>{
 for(const c of [{ocspSerial:999999n},
  {ocspIssuerHashWrong:true},
  {ocspNonceHex:brHex('f')}]){
  const r=evaluate(c);
  assert.equal(r.candidateSignedRevocationConsistent,false);
  assert.ok(r.candidateSignedRevocationAnomalyCodes.some(s=>
    s.includes('CERT_ID')||s.includes('NONCE')),JSON.stringify(r));
 }
});
test('BS: CRL issuer and signer root must match independently configured candidate trust pin',()=>{
 const wrong=evaluate({crlIssuerMismatched:true});
 assert.ok(wrong.candidateSignedRevocationAnomalyCodes.includes(
  'BS_CRL_ISSUER_MISMATCH'));
 const f=bsSignedFixture();
 const r=assessCandidateSignedRevocation({
  brPacket:f.material.packet,expected:{
   quoteId:f.material.expected.quoteId,
   brPacketSha256:candidateBytePacketDigest(f.material.packet),
   rootCertSha256:brRootSha,minimumRevocationEpoch:4,
   brLocallyConsistent:true,brGovernanceState:'HELD_UNVERIFIED',brExists:true
  },issuerCertificatePem:f.issuerCertificatePem,
  expectedIssuerRootSha256:brHex('d'),now:bsNow
 });
 assert.ok(r.candidateSignedRevocationAnomalyCodes.includes(
  'BS_ISSUER_ROOT_PIN_OR_LEAF_CHAIN_INVALID'));
});
test('BS: monotonic CRL number and issuer response freshness fail closed',()=>{
 for(const c of [{crlNumber:3},{crlUpdatedMinutesAgo:65},
  {ocspUpdatedMinutesAgo:65},{crlNextMinutes:-1},
  {ocspNextMinutes:-1}]){
  const r=evaluate(c);
  assert.equal(r.candidateSignedRevocationConsistent,false,JSON.stringify(c));
  assert.ok(r.candidateSignedRevocationAnomalyCodes.some(s=>
   s.includes('ROLLBACK')||s.includes('STALE')),JSON.stringify(r));
 }
});
test('BS: responder ID spoof and BR upstream head mismatches never establish status',()=>{
 const wrong=evaluate({ocspResponderWrong:true});
 assert.ok(wrong.candidateSignedRevocationAnomalyCodes.includes(
  'BS_OCSP_RESPONDER_NOT_ISSUER'));
 const stale=evaluate({},{brLocallyConsistent:false});
 assert.ok(stale.candidateSignedRevocationAnomalyCodes.includes(
  'BS_UPSTREAM_BR_NOT_HELD'));
 const fork=evaluate({},{brPacketSha256:brHex('a')});
 assert.ok(fork.candidateSignedRevocationAnomalyCodes.includes(
  'BS_BR_HASH_OR_CHALLENGE_MISMATCH'));
});
