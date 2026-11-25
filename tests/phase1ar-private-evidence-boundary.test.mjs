import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, mkdtempSync, rmSync, writeFileSync, symlinkSync, realpathSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AUTHORITY_DIGEST_FIELDS, INDEPENDENT_REVIEW_DIGEST_FIELDS,
  PROVIDER_CODE, REQUESTED_SCOPE
} from '../scripts/lib/providerAuthorityPreflight.mjs';

const repoRoot = realpathSync(fileURLToPath(new URL('../', import.meta.url)));
const cli = fileURLToPath(new URL('../scripts/provider-authority-preflight.mjs', import.meta.url));
const env = {
  ...process.env, CI: 'false', GITHUB_ACTIONS: 'false',
  NODE_ENV: 'test', PHASE_1AP_OFFLINE_INSPECTION_APPROVED: 'YES'
};

function sample() {
  let index = 1;
  const hash = () => (index++).toString(16).padStart(64, '0');
  return {
    schemaVersion: 1, providerCode: PROVIDER_CODE, requestedScope: REQUESTED_SCOPE,
    artifactDigests: Object.fromEntries(AUTHORITY_DIGEST_FIELDS.map(k => [k, hash()])),
    reviewDigests: Object.fromEntries(INDEPENDENT_REVIEW_DIGEST_FIELDS.map(k => [k, hash()]))
  };
}

function invoke(args, overrides = {}, cwd = repoRoot) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd, encoding: 'utf8', timeout: 8000, maxBuffer: 32_768,
    env: { ...env, ...overrides }
  });
}

test('Phase 1AR offline authority intake is strict, bounded, and checkout-root anchored', () => {
  const external = mkdtempSync(join(tmpdir(), 'phase1ar-evidence-'));
  const internal = mkdtempSync(join(repoRoot, '.phase1ar-synthetic-'));
  try {
    const packet = sample();
    const outside = join(external, 'public-hashes-only.json');
    writeFileSync(outside, JSON.stringify(packet), { mode: 0o600 });
    chmodSync(outside, 0o600);
    const ok = invoke(['--offline-packet', outside], {}, external);
    assert.equal(ok.status, 0, ok.stderr);
    const report = JSON.parse(ok.stdout);
    assert.equal(report.packetInspected, true);
    assert.equal(report.declaredDigestCount, 16);
    assert.equal(report.releaseDecision, 'HOLD');
    assert.equal(report.sandboxServiceAuthorized, false);
    assert.equal(report.productionReleaseAuthorized, false);
    assert.equal(report.stockPostingEnabled, false);
    assert.equal(report.independentlyAuthenticatedRcaiCaChain, false);
    assert.ok(!ok.stdout.includes(outside));
    assert.ok(!ok.stdout.includes(packet.artifactDigests.signedAgreementSha256));

    // Previously cwd-relative checking could accept an in-checkout packet
    // when invoked with cwd outside the checkout.
    const inside = join(internal, 'synthetic-only.json');
    writeFileSync(inside, JSON.stringify(packet), { mode: 0o600 });
    const deniedInside = invoke(['--offline-packet', inside], {}, external);
    assert.equal(deniedInside.status, 2);
    assert.equal(deniedInside.stdout, '');
    assert.ok(!deniedInside.stderr.includes(inside));

    const alias = join(external, 'symlink.json');
    symlinkSync(outside, alias);
    assert.equal(invoke(['--offline-packet', alias]).status, 2);

    // Non-private packet permission is rejected even when fingerprints look valid.
    chmodSync(outside, 0o640);
    assert.equal(invoke(['--offline-packet', outside]).status, 2);
    chmodSync(outside, 0o600);

    const huge = join(external, 'oversized.json');
    writeFileSync(huge, 'X'.repeat(16_385), { mode: 0o600 });
    assert.equal(invoke(['--offline-packet', huge]).status, 2);

    // CI / production / missing operator approval remain strictly forbidden.
    assert.equal(invoke(['--offline-packet', outside], { CI: 'true' }).status, 2);
    assert.equal(invoke(['--offline-packet', outside], { GITHUB_ACTIONS: 'true' }).status, 2);
    assert.equal(invoke(['--offline-packet', outside], { NODE_ENV: 'production' }).status, 2);
    assert.equal(invoke(['--offline-packet', outside], { PHASE_1AP_OFFLINE_INSPECTION_APPROVED: 'NO' }).status, 2);

    for (const invalid of [
      ['--offline-packet', 'relative.json'],
      ['--offline-packet'],
      ['--authorize'],
      ['--ci-hold', '--offline-packet', outside]
    ]) assert.equal(invoke(invalid).status, 2);

    // A default CI HOLD is safe and makes no attempt to open private evidence.
    const hold = invoke(['--ci-hold'], { CI: 'true', GITHUB_ACTIONS: 'true' });
    assert.equal(hold.status, 0, hold.stderr);
    assert.equal(JSON.parse(hold.stdout).packetInspected, false);
  } finally {
    rmSync(external, { recursive: true, force: true });
    rmSync(internal, { recursive: true, force: true });
  }
});
