import test from 'node:test';
import assert from 'node:assert/strict';
import { rootCertificates } from 'node:tls';
import { spawnSync } from 'node:child_process';
import {
  DISALLOWED_WEBPKI_SHA256,
  classifyPhase1AqPublicFingerprint,
  auditPhase1AqPublicCertificateChain
} from '../scripts/lib/phase1AqTrustIncident.mjs';

test('Mozilla incident inventory has exactly eight original G3, eight cross-signed and eight G2 RSA certificates', () => {
  const groups = Object.values(DISALLOWED_WEBPKI_SHA256);
  assert.deepEqual(groups.map(group => group.length), [8, 8, 8]);
  const hashes = groups.flat();
  assert.equal(new Set(hashes).size, 24);
  for (const fingerprint of hashes) {
    assert.match(fingerprint, /^[A-F0-9]{64}$/);
    assert.deepEqual(classifyPhase1AqPublicFingerprint(fingerprint), {
      knownIncidentCertificate: true,
      certificateTrustEstablished: false,
      disposition: 'DENY'
    });
  }
});

test('known incidents deny lowercase and colon-formatted fingerprints', () => {
  const fingerprint = DISALLOWED_WEBPKI_SHA256.G3_ORIGINAL[0];
  const colon = fingerprint.match(/.{2}/g).join(':').toLowerCase();
  assert.equal(classifyPhase1AqPublicFingerprint(colon).disposition, 'DENY');
  assert.equal(classifyPhase1AqPublicFingerprint(fingerprint.toLowerCase()).disposition, 'DENY');
});

test('unknown fingerprint remains unverified; malformed inputs fail closed', () => {
  const unknown = classifyPhase1AqPublicFingerprint('f'.repeat(64));
  assert.equal(unknown.certificateTrustEstablished, false);
  assert.equal(unknown.disposition, 'UNVERIFIED_HOLD');
  for (const value of [null, {}, 42, '', 'notsha', 'g'.repeat(64), '0'.repeat(65), 'abc:'.repeat(16)]) {
    assert.throws(() => classifyPhase1AqPublicFingerprint(value));
  }
});

test('zero or publicly trusted root certificates cannot satisfy external authorization', () => {
  const empty = auditPhase1AqPublicCertificateChain();
  assert.equal(empty.releaseDecision, 'HOLD');
  assert.equal(empty.incidentInventoryEntryCount, 24);
  assert.equal(empty.certificatePathAuthenticated, false);
  assert.equal(empty.indianCcaDscAuthorityAuthenticated, false);
  assert.equal(empty.productionReleaseAuthorized, false);
  assert.equal(empty.stockPostingEnabled, false);
  assert.ok(rootCertificates.length > 0);
  const checked = auditPhase1AqPublicCertificateChain([rootCertificates[0]]);
  assert.equal(checked.checkedPublicCertificateCount, 1);
  assert.equal(checked.releaseDecision, 'HOLD');
  assert.equal(checked.sandboxServiceAuthorized, false);
  assert.equal(checked.authenticatedLiveRevocation, false);
  assert.equal(checked.mcaAndSignatoryVerified, false);
  const report = JSON.stringify(checked);
  assert.ok(!report.includes('BEGIN CERTIFICATE'));
  assert.ok(!report.includes(rootCertificates[0]));
});

test('no private keys, mixed PEM, duplicate certificates or unbounded input accepted', () => {
  const pem = rootCertificates[0];
  for (const input of [
    [pem, pem],
    [pem + pem],
    ['-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----'],
    [pem + '\nAPI_TOKEN=SECRET'],
    ['junk'],
    [null],
    new Array(13).fill(pem),
    'not-an-array'
  ]) assert.throws(() => auditPhase1AqPublicCertificateChain(input));
});

test('CI trust-incident preflight emits HOLD and refuses unsupported or unsafe arguments', () => {
  const cmd = 'scripts/phase1aq-trust-incident-preflight.mjs';
  const accepted = spawnSync(process.execPath, [cmd, '--ci-hold'], {encoding:'utf8'});
  assert.equal(accepted.status, 0, accepted.stderr);
  const report = JSON.parse(accepted.stdout);
  assert.equal(report.releaseDecision, 'HOLD');
  assert.equal(report.incidentInventoryEntryCount, 24);
  const denied = spawnSync(process.execPath, [cmd, '--approve'], {encoding:'utf8'});
  assert.equal(denied.status, 2);
  assert.match(denied.stderr, /HOLD/);
  assert.ok(!denied.stderr.includes('--approve'));
});
