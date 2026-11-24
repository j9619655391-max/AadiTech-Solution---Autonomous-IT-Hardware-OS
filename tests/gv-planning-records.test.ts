import test from 'node:test';
import assert from 'node:assert/strict';
import {gvCanonical,gvPrepare,gvVerifyStored,gvPersistenceEnabled,gvSessionCookie} from '../server/internalPlanning/records';
const input={"lines":[{"sku":"S1","quantity":2,"unitPrice":"100.00","gstRate":"18.00"}],"discount":"10.00"};
test('1GV canonical request hashing and stored result integrity',()=>{
 const a=gvPrepare('M05',input),b=gvPrepare('M05',Object.fromEntries(Object.entries(input).reverse()));
 assert.equal(a.requestSha256,b.requestSha256);assert.notEqual(a.requestSha256,gvPrepare('M05',{...input,discount:'0'}).requestSha256);
 assert.equal(gvVerifyStored({module:a.module,result_json:a.resultJson,result_sha256:a.resultSha256}).releaseDecision,'HOLD');
 assert.throws(()=>gvVerifyStored({module:a.module,result_json:a.resultJson+' ',result_sha256:a.resultSha256}),/RECORD_INTEGRITY_HOLD/);
});
test('1GV canonical validator rejects sparse/accessor/non-finite/inherited values',()=>{
 let invoked=false;const access=Object.defineProperty({},'x',{enumerable:true,get(){invoked=true;return 1;}});
 for(const v of [Array(1),access,NaN,Infinity,-0,Object.create({a:1}),{x:undefined}])assert.throws(()=>gvCanonical(v),/INVALID_CANONICAL_VALUE/);assert.equal(invoked,false);
});
test('1GV persistence target and duplicate cookies fail closed',()=>{
 const env={GV_PLANNING_FIXTURE:'YES',CRM_TEST_DB:'1',NODE_ENV:'test',DB_NAME:'aaditech_ci',DB_SSL:'false'};
 assert.equal(gvPersistenceEnabled(env),true);
 for(const patch of [{NODE_ENV:'production'},{NODE_ENV:'staging'},{DB_NAME:'other'},{DB_SSL:'true'},{GV_PLANNING_FIXTURE:'NO'},{CRM_TEST_DB:'0'}])assert.equal(gvPersistenceEnabled({...env,...patch}),false);
 const v='a'.repeat(43);assert.equal(gvSessionCookie('aaditech_session='+v),v);assert.throws(()=>gvSessionCookie('aaditech_session='+v+'; aaditech_session='+v),/SESSION_AUTHORITY_REQUIRED/);
});
