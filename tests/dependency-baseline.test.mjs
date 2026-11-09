import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateDependencyBaseline} from '../scripts/check-dependency-baseline.mjs';
import {triageDependencyAudit} from '../scripts/triage-dependencies.mjs';
const baseline={schemaVersion:1,kind:'known-unresolved-development-only',advisories:[
 {id:'GHSA-jqcg-44mw-7w3h',packageName:'proxy-addr',severity:'critical'},
 {id:'GHSA-27r3-jxmh-p828',packageName:'body-parser',severity:'moderate'}
]};
const raw={'proxy-addr':[{url:'https://github.com/advisories/GHSA-jqcg-44mw-7w3h',
 severity:'critical'}]};
test('documented critical advisory stays production-blocking without failing known development baseline',()=>{
 const result=evaluateDependencyBaseline(raw,triageDependencyAudit(raw),baseline);
 assert.equal(result.developmentBaselinePassed,true);
 assert.equal(result.productionReleaseBlocked,true);
 assert.equal(result.productionReleaseAuthorized,false);
 assert.equal(result.currentCriticalHigh,1);
 assert.deepEqual(result.noLongerReported,['GHSA-27r3-jxmh-p828']);
});
test('new advisories, escalations and moved packages require fresh human triage',()=>{
 const next={vite:[{url:'https://github.com/advisories/GHSA-9jrq-w75r-8gcw',severity:'high'}]};
 assert.equal(evaluateDependencyBaseline(next,triageDependencyAudit(next),baseline).developmentBaselinePassed,false);
 const increased={'body-parser':[{url:'https://github.com/advisories/GHSA-27r3-jxmh-p828',severity:'high'}]};
 assert.match(evaluateDependencyBaseline(increased,triageDependencyAudit(increased),baseline).newOrEscalated.join(),/severity increased/);
 const moved={express:[{url:'https://github.com/advisories/GHSA-jqcg-44mw-7w3h',severity:'critical'}]};
 assert.match(evaluateDependencyBaseline(moved,triageDependencyAudit(moved),baseline).newOrEscalated.join(),/Changed package/);
});
test('tampered or malformed reports and duplicate baselines fail closed',()=>{
 assert.throws(()=>evaluateDependencyBaseline(raw,triageDependencyAudit({}),baseline),/does not match/);
 assert.throws(()=>evaluateDependencyBaseline(raw,triageDependencyAudit(raw),
  {...baseline,advisories:[baseline.advisories[0],baseline.advisories[0]]}),/duplicated/);
 assert.throws(()=>evaluateDependencyBaseline([],{},baseline));
});
test('even advisory-free raw audit never authorizes production release',()=>{
 const report=evaluateDependencyBaseline({},triageDependencyAudit({}),baseline);
 assert.equal(report.developmentBaselinePassed,true);
 assert.equal(report.productionReleaseAuthorized,false);
});
