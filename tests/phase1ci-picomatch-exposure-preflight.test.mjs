import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock} from '../scripts/phase1bt-production-scope.mjs';
import {assessLockedPicomatchExposure,EXPECTED_INBOUND,EXPECTED_LOCK}
 from '../scripts/phase1ci-picomatch-exposure-preflight.mjs';

const pkg=JSON.parse(readFileSync('package.json','utf8'));
const lock=readBunLock(readFileSync('bun.lock','utf8'));
const serverSource=readFileSync('server.ts','utf8');
const viteConfigSource=readFileSync('vite.config.ts','utf8');
const base={pkg,lock,serverSource,viteConfigSource};
const evaluate=change=>assessLockedPicomatchExposure({...base,...change});
const clone=x=>structuredClone(x);
const has=(r,code)=>assert.ok(r.anomalyCodes.includes(code),r.anomalyCodes.join(','));
test('CI: REAL 336-package frozen Bun lock detects exactly three Picomatch introduction edges',()=>{
 const r=evaluate();
 assert.equal(r.localRealLockSelectedEntrypointsConsistent,true,r.anomalyCodes.join(';'));
 assert.equal(r.inspectedPackageCount,336);
 assert.deepEqual(r.directLockedIntroducers,EXPECTED_INBOUND);
 assert.equal(r.picomatchLockedVersion,EXPECTED_LOCK.picomatch);
 assert.equal(r.declaredBuildOnlyIsolationLocallyConsistent,true);
 assert.equal(r.representativeProductionRootRoute,null);
 assert.ok(r.representativeDevelopmentRootRoute.includes('picomatch'));
 assert.ok(r.reviewedIntroducerRoutes.tinyglobby.includes('tinyglobby'));
 assert.deepEqual(r.reviewedIntroducerRoutes.vite,['vite','picomatch']);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.productionReleaseBlocked,true);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CI: scoped local containment can NEVER certify whole repo source, zero-High audit or vendor remediation',()=>{
 const r=evaluate();
 for(const flag of ['wholeRepositoryRuntimeSourceGraphExhaustivelyScanned',
  'actualUntrustedPatternReachabilityProvenAbsent',
  'actualUpstreamPatchedReleaseVerified','globalZeroCriticalHighAuditPassed',
  'independentlyAuthenticatedSecurityAndBusinessApprovals',
  'genuineEmudhraAndCcaRcaIdentityVerified',
  'remoteWormRetentionDrAndForkPersistenceVerified','productionReleaseAuthorized']){
  assert.equal(r[flag],false,flag);
 }
 assert.equal(r.newUnreviewedIntroductionRejected,false);
});
test('CI: unexpected fourth direct Picomatch importer is blocked including dev-only packages',()=>{
 const l=clone(lock);
 l.packages['@vitejs/plugin-react'][2].dependencies.picomatch='^4.0.7';
 has(evaluate({lock:l}),'CI_UNREVIEWED_PICOMATCH_INTRODUCER_OR_EDGE_DRIFT');
});
test('CI: original vite, tinyglobby and fdir peer dependency specifications cannot silently drift',()=>{
 for(const [name,kind,value] of [
  ['vite','dependencies','^5.0.0'],
  ['tinyglobby','dependencies','^3'],
  ['fdir','peerDependencies','^3 only']]){
  const l=clone(lock);l.packages[name][2][kind].picomatch=value;
  has(evaluate({lock:l}),'CI_UNREVIEWED_PICOMATCH_INTRODUCER_OR_EDGE_DRIFT');
 }
});
test('CI: removing an introduction route or optional peer metadata is detected',()=>{
 for(const name of ['vite','tinyglobby','fdir']){
  const l=clone(lock),kind=name==='fdir'?'peerDependencies':'dependencies';
  delete l.packages[name][2][kind].picomatch;
  has(evaluate({lock:l}),'CI_UNREVIEWED_PICOMATCH_INTRODUCER_OR_EDGE_DRIFT');
 }
 const l=clone(lock);
 l.packages.fdir[2].optionalPeers=[];
 has(evaluate({lock:l}),'CI_FDIR_OPTIONAL_PEER_POLICY_DRIFT');
});
test('CI: direct new workspace production AND development Picomatch dependencies denied',()=>{
 for(const group of ['dependencies','devDependencies']){
  const p=clone(pkg),l=clone(lock);
  p[group].picomatch='4.0.7';
  l.workspaces[''][group].picomatch='4.0.7';
  has(evaluate({pkg:p,lock:l}),'CI_PICOMATCH_DIRECT_WORKSPACE_INTRODUCER');
 }
});
test('CI: indirect production attack path via Express or another actual root cannot be ignored',()=>{
 const l=clone(lock);
 l.packages.express[2].dependencies.picomatch='^4.0.7';
 const r=evaluate({lock:l});
 has(r,'CI_PRODUCTION_DEPENDENCY_SCOPE_BREACHED');
 has(r,'CI_VULNERABLE_PICOMATCH_REACHABLE_FROM_PRODUCTION_ROOT');
 assert.ok(r.representativeProductionRootRoute.includes('express'));
});
test('CI: changed vulnerable version and same-version tarball integrity are blocked',()=>{
 for(const [field,val,code] of [
  [0,'picomatch@4.0.8','CI_UNREVIEWED_LOCKED_BUILD_PACKAGE_PICOMATCH'],
  [3,'sha512-'+'A'.repeat(86)+'==','CI_PICOMATCH_LOCKED_TARBALL_INTEGRITY_DRIFT']
 ]){
  const l=clone(lock);l.packages.picomatch[field]=val;
  has(evaluate({lock:l}),code);
 }
});
test('CI: changed Vite, tinyglobby or fdir versions require real package/lock review',()=>{
 for(const [name,val] of [
  ['vite','vite@6.4.6'],
  ['tinyglobby','tinyglobby@0.2.18'],
  ['fdir','fdir@6.6.0']]){
  const l=clone(lock);l.packages[name][0]=val;
  has(evaluate({lock:l}),'CI_UNREVIEWED_LOCKED_BUILD_PACKAGE_'+name.toUpperCase());
 }
});
test('CI: malicious entrypoint import of Picomatch or tinyglobby is caught as direct runtime matcher ingress',()=>{
 for(const injected of [
  "\nimport picomatch from 'picomatch';\n",
  "\nconst tiny = require('tinyglobby');\n",
  "\nconst fdir = await import('fdir');\n"
 ]){
  has(evaluate({serverSource:serverSource+injected}),
   'CI_SERVER_ENTRYPOINT_IMPORTS_VULNERABLE_BUILD_MATCHER');
 }
});
test('CI: Vite config matcher import outside normal plugin chain is blocked',()=>{
 const altered=viteConfigSource+"\nimport picomatch from 'picomatch';\n";
 has(evaluate({viteConfigSource:altered}),'CI_UNREVIEWED_VITE_CONFIG_MATCHER_IMPORT');
});
test('CI: remote Vite exposure or permissive HMR/watch configuration fails closed',()=>{
 for(const replacement of [
  viteConfigSource.replace("host: '127.0.0.1'","host: '0.0.0.0'"),
  viteConfigSource.replace("preview: {\n      host: '127.0.0.1'","preview: {\n      host: '0.0.0.0'"),
  viteConfigSource.replace("allowedHosts: ['localhost','127.0.0.1']","allowedHosts: true"),
  viteConfigSource.replace("hmr: false","hmr: true"),
  viteConfigSource.replace("fs: {strict: true}","fs: {strict: false}")
 ]){
  has(evaluate({viteConfigSource:replacement}),
   'CI_DEV_SERVER_LOOPBACK_AND_RESTRICTED_MATCHER_BOUNDARY_DRIFT');
 }
 const config=viteConfigSource.replace("process.env.DISABLE_HMR === 'true' ? null : {}",
  "process.env.DISABLE_HMR === 'false' ? null : {}");
 has(evaluate({viteConfigSource:config}),'CI_DEV_WATCHER_ISOLATION_OPTION_MISSING');
});
test('CI: malformed lock nodes and unusual dependency graph metadata cannot bypass inbound enumeration',()=>{
 const l=clone(lock);l.packages.rogue=['rogue@1.0.0'];
 has(evaluate({lock:l}),'CI_UNBOUNDED_OR_MALFORMED_LOCK_NODE');
 const m=clone(lock);m.packages.vite[2].dependencies=['picomatch'];
 has(evaluate({lock:m}),'CI_UNBOUNDED_OR_MALFORMED_DEPENDENCY_EDGES');
});
test('CI: external CI ref and repository spoofing denied; commit identity must be exact SHA',()=>{
 const env={CI:'true',GITHUB_ACTIONS:'true',
  GITHUB_REPOSITORY:'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS',
  GITHUB_REF:'refs/pull/1/merge',GITHUB_SHA:'a'.repeat(40)};
 assert.equal(evaluate({environment:env}).localRealLockSelectedEntrypointsConsistent,true);
 const nodeLikeEnv=Object.assign(Object.create(null),env);
 assert.equal(evaluate({environment:nodeLikeEnv}).localRealLockSelectedEntrypointsConsistent,true);
 for(const variation of [
  {...env,GITHUB_REPOSITORY:'attacker/fork'},
  {...env,GITHUB_REF:'refs/heads/main'},
  {...env,GITHUB_SHA:'not-a-sha'},
  {...env,GITHUB_ACTIONS:'false'}
 ]){
  has(evaluate({environment:variation}),'CI_UNTRUSTED_RUN_CONTEXT');
 }
});
test('CI: cannot mark high vulnerability fixed with fake release flags or forged metadata',()=>{
 const l=clone(lock);l.packages.picomatch[2].productionReleaseAuthorized=true;
 has(evaluate({lock:l}),'CI_PICOMATCH_PACKAGE_METADATA_DRIFT');
 const report=evaluate({pkg:{...pkg,productionReleaseAuthorized:true}});
 assert.equal(report.productionReleaseAuthorized,false);
 assert.equal(report.globalZeroCriticalHighAuditPassed,false);
});
