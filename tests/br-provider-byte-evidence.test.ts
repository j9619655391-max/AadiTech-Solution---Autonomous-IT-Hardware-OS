import test from 'node:test';
import assert from 'node:assert/strict';
import {assessCandidateProviderBytes,candidateBytePacketDigest} from '../server/commercialIntegrity/quoteProviderBytes';
import {brFixture,brNow,brRootPem,brRootSha,brOrigin,brHex,brClone}
 from './br-provider-byte-fixtures';
const check=(fixture=brFixture(),overrides:Record<string,unknown>={})=>
 assessCandidateProviderBytes({packet:fixture.packet,expected:fixture.expected,
  bqPacket:fixture.bq,rootCertificatePem:brRootPem,
  expectedRootCertSha256:brRootSha,expectedProviderOrigin:brOrigin,
  now:brNow,...overrides});
test('BR ephemeral private test root validates local checkpoint bytes but grants no issuer, WORM or DR authority',()=>{
 const f=brFixture(),report=check(f);
 assert.equal(report.candidateBytePreflightConsistent,true,
  report.candidateBytePreflightAnomalyCodes.join(','));
 assert.equal(report.candidateBytePacketSha256,candidateBytePacketDigest(f.packet));
 assert.equal(report.candidateRootCertificateSha256,brRootSha);
 assert.equal(report.byteHashAndOfflineCertificateSignatureChecked,true);
 for(const prop of ['enrolledExternalRootAuthenticated','liveTlsProviderSessionVerified',
  'authorizedIssuerPolicyAndCertificatePathVerified',
  'signedCrlOcspAndResponderAuthorized','independentWormObjectLockVerified',
  'realEncryptedDrRestorationWitnessed','productionReleaseAuthorized'] as const)
  assert.equal(report[prop],false,prop);
 assert.equal(report.releaseDecision,'HOLD');
});
test('BR uploaded fake trust root and wrong certificate hostname cannot become genuine CA trust',()=>{
 const f=brFixture();
 assert.ok(check(f,{expectedRootCertSha256:brHex('e')}).
  candidateBytePreflightAnomalyCodes.includes('BR_ROOT_OR_LEAF_CERT_CHAIN_INVALID'));
 assert.ok(check(f,{expectedProviderOrigin:'https://attacker-fixture.invalid/'}).
  candidateBytePreflightAnomalyCodes.includes('BR_ROOT_OR_LEAF_CERT_CHAIN_INVALID'));
 const s=brClone(f);(s.packet as any).rootCertificatePem=brRootPem;
 assert.ok(check(s).candidateBytePreflightAnomalyCodes.includes('BR_PACKET_SHAPE_INVALID'));
 assert.equal(check(f,{rootCertificatePem:'attacker-root'}).
  candidateBytePreflightConsistent,false);
});
test('BR signed exact checkpoint bytes cannot be tampered or rebound to other quote/BQ challenge',()=>{
 const f=brFixture(),invalid=brClone(f);
 const raw=Buffer.from(invalid.packet.checkpointUtf8Base64,'base64');
 raw[raw.length-1]=raw[raw.length-1]^1;
 invalid.packet.checkpointUtf8Base64=raw.toString('base64');
 assert.ok(check(invalid).candidateBytePreflightAnomalyCodes.includes(
  'BR_SIGNED_CHECKPOINT_BYTES_INVALID'));
 const wrong=brClone(f);
 wrong.packet.bqPacketSha256=brHex('f');
 assert.ok(check(wrong).candidateBytePreflightAnomalyCodes.includes(
  'BR_BQ_PACKET_DIGEST_OR_CHALLENGE_MISMATCH'));
 const changed=brClone(f);
 changed.packet.challengeSha256=brHex('f');
 assert.ok(check(changed).candidateBytePreflightAnomalyCodes.includes(
  'BR_BQ_PACKET_DIGEST_OR_CHALLENGE_MISMATCH'));
});
test('BR caller supplied DER CRL/OCSP raw bytes are hash-bound, but signed issuer revocation is NOT validated',()=>{
 const f=brFixture();
 for(const key of ['crlDerBase64','ocspDerBase64'] as const){
  const clone=brClone(f);
  clone.packet[key]=Buffer.from([0x30,0x06,0x02,0x01,0x05,0x02,0x01,0x06]).toString('base64');
  assert.ok(check(clone).candidateBytePreflightAnomalyCodes.includes(
   'BR_RAW_BYTES_VERSUS_BQ_CAPTURE_HASH_MISMATCH'));
 }
 const indefinite=brClone(f);
 indefinite.packet.crlDerBase64=Buffer.from([0x30,0x80,0x02,0x01,0x01,0,0,0]).toString('base64');
 assert.ok(check(indefinite).candidateBytePreflightAnomalyCodes.includes(
  'BR_BYTES_INVALID_NONCANONICAL_OR_DER_BOUND'));
 assert.equal(check(f).signedCrlOcspAndResponderAuthorized,false);
});
test('BR WORM and DR byte payload contradictions to BQ head are rejected',()=>{
 const f=brFixture();
 const worm=brClone(f);
 const parsed=JSON.parse(Buffer.from(worm.packet.wormReceiptUtf8Base64,'base64').toString());
 parsed.deniedDelete=false;
 worm.packet.wormReceiptUtf8Base64=Buffer.from(JSON.stringify(parsed)).toString('base64');
 assert.ok(check(worm).candidateBytePreflightAnomalyCodes.includes(
  'BR_WORM_CAPTURE_CONFLICT_OR_UNPROVEN'));
 const dr=brClone(f);
 const d=JSON.parse(Buffer.from(dr.packet.drTranscriptUtf8Base64,'base64').toString());
 d.sequence=0;
 dr.packet.drTranscriptUtf8Base64=Buffer.from(JSON.stringify(d)).toString('base64');
 assert.ok(check(dr).candidateBytePreflightAnomalyCodes.includes(
  'BR_DR_RESTORED_HEAD_OR_WITNESS_CLAIM_CONFLICT'));
});
test('BR expired checkpoint and altered claimed predecessor state fail closed',()=>{
 const f=brFixture();
 assert.ok(check(f,{now:new Date(brNow.getTime()+25*60000)}).
  candidateBytePreflightAnomalyCodes.includes('BR_SIGNED_CHECKPOINT_STALE_OR_FUTURE'));
 assert.ok(check(f,{expected:{...f.expected,bqLocallyConsistent:false}}).
  candidateBytePreflightAnomalyCodes.includes('BR_BQ_UPSTREAM_NOT_READY'));
 assert.ok(check(f,{expected:{...f.expected,bqPacketSha256:brHex('f')}}).
  candidateBytePreflightAnomalyCodes.includes('BR_BQ_PACKET_DIGEST_OR_CHALLENGE_MISMATCH'));
 const tampered=brClone(f);
 tampered.bq.captures[0].body.crlSha256=brHex('f');
 assert.ok(check(tampered).candidateBytePreflightAnomalyCodes.includes(
  'BR_BQ_PACKET_DIGEST_OR_CHALLENGE_MISMATCH'));
});
