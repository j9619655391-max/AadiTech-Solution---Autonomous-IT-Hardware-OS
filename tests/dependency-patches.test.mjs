import test from 'node:test';
import assert from 'node:assert/strict';
import {checkLockedPatches,checkCurrentAudit,REVIEWED_PATCHES}
 from '../scripts/verify-patched-dependencies.mjs';
import {triageDependencyAudit} from '../scripts/triage-dependencies.mjs';
const make=()=>{
 const packages=Object.fromEntries(Object.entries(REVIEWED_PATCHES)
  .map(([name,version])=>[name,[name+'@'+version]]));
 return {
  packageJson:{dependencies:{vite:'6.4.5'},devDependencies:{vite:'6.4.5'},
   overrides:{'proxy-addr':'2.0.8','body-parser':'1.20.9',
    'source-map-js':'1.2.2','qs':'6.16.1'}},
  lock:{packages,workspaces:{'':{dependencies:{vite:'6.4.5'},
   devDependencies:{vite:'6.4.5'}}}}
 };
};
test('reviewed patched dependencies must match exact lockfile and manifest versions',()=>{
 const {packageJson,lock}=make();
 assert.equal(checkLockedPatches(packageJson,lock).lockedPatchVersionsVerified,true);
 assert.equal(checkLockedPatches({...packageJson,overrides:{}},lock).lockedPatchVersionsVerified,false);
 assert.equal(checkLockedPatches(packageJson,
  {...lock,packages:{...lock.packages,'proxy-addr':['proxy-addr@2.0.7']}}).lockedPatchVersionsVerified,false);
 assert.equal(checkLockedPatches(packageJson,{
  ...lock,workspaces:{'':{dependencies:{vite:'^6.2.3'},devDependencies:{vite:'6.4.5'}}}
 }).lockedPatchVersionsVerified,false);
});
test('critical/high advisory matches fail, no findings does not certify production',()=>{
 const empty={};
 const outcome=checkCurrentAudit(empty,triageDependencyAudit(empty));
 assert.equal(outcome.criticalHighAuditPassed,true);
 assert.equal(outcome.productionReleaseAuthorized,false);
 const critical={'proxy-addr':[{url:'https://github.com/advisories/GHSA-jqcg-44mw-7w3h',
  severity:'critical'}]};
 const bad=checkCurrentAudit(critical,triageDependencyAudit(critical));
 assert.equal(bad.criticalHighAuditPassed,false);
 assert.equal(bad.currentCritical,1);
 const other={example:[{url:'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',severity:'high'}]};
 assert.equal(checkCurrentAudit(other,triageDependencyAudit(other)).criticalHighAuditPassed,false);
 assert.throws(()=>checkCurrentAudit(critical,triageDependencyAudit({})),/mismatch/);
});
test('moderate/low advisories are reported without a release authorization',()=>{
 const raw={example:[{url:'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',severity:'moderate'}]};
 const result=checkCurrentAudit(raw,triageDependencyAudit(raw));
 assert.equal(result.criticalHighAuditPassed,true);
 assert.equal(result.moderate,1);
 assert.equal(result.productionReleaseAuthorized,false);
});
