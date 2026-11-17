import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readBunLock,assessProductionDependencyClosure,BUILD_ONLY}
 from '../scripts/phase1bt-production-scope.mjs';
import {checkLockedPatches,checkCurrentAudit}
 from '../scripts/verify-patched-dependencies.mjs';
import {triageDependencyAudit}
 from '../scripts/triage-dependencies.mjs';
const pkg=JSON.parse(readFileSync('package.json','utf8'));
const lock=readBunLock(readFileSync('bun.lock','utf8'));
const server=readFileSync('server.ts','utf8');
const assess=(p=pkg,l=lock,s=server)=>assessProductionDependencyClosure(p,l,s);
const clone=x=>structuredClone(x);

test('BT exact production dependency graph excludes Vite, picomatch and both build-only Vite plugins',()=>{
 const result=assess();
 assert.equal(result.productionDependencyClosureLocallyConsistent,true,
  result.anomalyCodes.join(','));
 assert.equal(result.productionContainsPicomatch,false);
 assert.equal(result.productionContainsVite,false);
 assert.equal(result.unpatchedDevelopmentDependencyRemains,true);
 assert.equal(result.picomatchLockedVersion,'picomatch@4.0.7');
 assert.ok(result.productionDependencyCount>=30);
 assert.equal(Object.isFrozen(BUILD_ONLY),true);
 assert.equal(result.criticalHighDependencyAuditStillRequired,true);
 assert.equal(result.upstreamVendorFixVerified,false);
 assert.equal(result.independentSecurityApprovalVerified,false);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.releaseDecision,'HOLD');
 const reviewed=checkLockedPatches(pkg,lock);
 assert.equal(reviewed.lockedPatchVersionsVerified,true,reviewed.problems.join(','));
});
test('BT attacker introduces direct Vite or picomatch into production manifest and graph check fails',()=>{
 for(const dep of ['vite','@tailwindcss/vite','@vitejs/plugin-react']){
  const p=clone(pkg);p.dependencies[dep]=p.devDependencies[dep];
  assert.equal(assess(p).productionDependencyClosureLocallyConsistent,false);
 }
 const p=clone(pkg),l=clone(lock);
 p.dependencies.picomatch='4.0.7';
 l.workspaces[''].dependencies.picomatch='4.0.7';
 const report=assess(p,l);
 assert.equal(report.productionContainsPicomatch,true);
 assert.ok(report.anomalyCodes.some(x=>x.includes('Unpatched picomatch production-reachable')));
 assert.equal(report.productionReleaseAuthorized,false);
});
test('BT transitive picomatch reintroduction through a formerly safe production package fails',()=>{
 const l=clone(lock);
 l.packages.express[2].dependencies.picomatch='^4.0.7';
 const result=assess(pkg,l);
 assert.equal(result.productionDependencyClosureLocallyConsistent,false);
 assert.equal(result.productionContainsPicomatch,true);
 assert.match(result.anomalyCodes.join(','),/express -> picomatch/);
});
test('BT tampered Bun workspace, missing locked metadata or removed dev plugin pin are blocked',()=>{
 const l=clone(lock);
 delete l.workspaces[''].devDependencies.vite;
 assert.equal(assess(pkg,l).productionDependencyClosureLocallyConsistent,false);
 const other=clone(lock);
 delete other.packages.express;
 assert.ok(assess(pkg,other).anomalyCodes.some(x=>
  x.includes('Missing or unpinned production package in lock: express')));
 const p=clone(pkg);
 p.devDependencies['@vitejs/plugin-react']='9.9.9';
 assert.equal(assess(p).productionDependencyClosureLocallyConsistent,false);
});
test('BT accidental unguarded Vite import is caught before packaging',()=>{
 const unsafe=server.replace('await import("vite")','await import("vite-unused")');
 assert.ok(assess(pkg,lock,unsafe).anomalyCodes.some(x=>
  x.includes('Development-only guarded dynamic Vite import missing')));
 const staticImport='import {createServer} from "vite";\n'+server;
 assert.ok(assess(pkg,lock,staticImport).anomalyCodes.some(x=>
  x.includes('Vite imported at module evaluation outside production path gate')));
});
test('BT Bun v2 lock must stay bounded, parseable and structurally trusted',()=>{
 assert.throws(()=>readBunLock('{"lockfileVersion":9,"workspaces":{},"packages":{}}'),
  /Unsupported/);
 assert.throws(()=>readBunLock('{__proto__: 1}'));
 assert.throws(()=>readBunLock('x'.repeat(1024*1024+1)),/oversize/);
});
test('BT known unpatched high advisory remains non-waivable even if production closure is isolated',()=>{
 const raw={picomatch:[{
  url:'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
  severity:'high',title:'ReDoS from repeated single-branch extglob'
 }]};
 const audit=checkCurrentAudit(raw,triageDependencyAudit(raw));
 assert.equal(audit.currentHigh,1);
 assert.equal(audit.criticalHighAuditPassed,false);
 assert.equal(audit.productionReleaseAuthorized,false);
 assert.equal(assess().productionDependencyClosureLocallyConsistent,true);
});
