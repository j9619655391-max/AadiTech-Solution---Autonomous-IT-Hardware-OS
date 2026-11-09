import test from 'node:test';
import assert from 'node:assert/strict';
import {triageDependencyAudit} from '../scripts/triage-dependencies.mjs';

test('sorts actionable Bun advisories and keeps release blocked for known findings',()=>{
 const data={
  vite:[{url:'https://github.com/advisories/GHSA-9jrq-w75r-8gcw',title:'Dev issue',severity:'low',vulnerable_versions:'<=6.4.3'}],
  'proxy-addr':[{url:'https://github.com/advisories/GHSA-jqcg-44mw-7w3h',title:'Spoofing',severity:'critical',vulnerable_versions:'<2.0.8'}],
  'body-parser':[{url:'https://github.com/advisories/GHSA-27r3-jxmh-p828',title:'DoS',severity:'high',vulnerable_versions:'<1.20.9'}]
 };
 const report=triageDependencyAudit(data);
 assert.equal(report.advisoryCount,3);
 assert.equal(report.affectedPackageCount,3);
 assert.deepEqual(report.packages.map(p=>p.name),['proxy-addr','body-parser','vite']);
 assert.equal(report.bySeverity.critical,1);
 assert.equal(report.bySeverity.high,1);
 assert.equal(report.bySeverity.low,1);
 assert.equal(report.requiresManualSecurityApproval,true);
 assert.equal(report.productionReady,false);
 assert.ok(report.packages[0].reviewAction.includes('Express'));
});
test('empty advisories still never certify production approval',()=>{
 const report=triageDependencyAudit({});
 assert.equal(report.advisoryCount,0);
 assert.equal(report.productionReady,false);
 assert.equal(report.requiresManualSecurityApproval,false);
});
test('malformed advisory entries and unsafe links fail closed',()=>{
 assert.throws(()=>triageDependencyAudit([]));
 assert.throws(()=>triageDependencyAudit({foo:'invalid'}));
 assert.throws(()=>triageDependencyAudit({foo:[{url:'https://evil.example/GHSA-test',severity:'high'}]}));
});
